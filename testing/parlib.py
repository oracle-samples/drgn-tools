# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Pre-authenticated request library: parlib

A simple library and tool for using OCI Object Storage Pre-authenticated
Requests (PARs).

PARs allow you to share a URL which allows another user to access (and possibly
modify) resources in an Object Storage Bucket without the need for OCI
credentials. The permissions are relatively flexible, and the PAR can't provide
any access outside the scope of those permissions.

While the main use for PARs is to allow a user to upload or download a single
object, they also can be used to provide RO or RW access to an entire bucket or
a prefix. The PARs expire and may be revoked at any time. This makes them ideal
for shared environments too.

To provide this functionality, a full ListObjects API as well as GET, HEAD, and
PUT object requests are available for the PARs. Unfortunately, you can't use the
OCI SDK to perform these ListObjects requests. The recommended method is to
manually construct requests and execute them with a tool like cURL.

This library provides a Python API to provide ListObjects as well as object
fetch and upload. It it Python 3.6 compatible, without any third-party
dependencies.
"""
import argparse
import json
import logging
import os
import posixpath
import shutil
import sys
import warnings
from http.client import HTTPResponse
from http.client import HTTPSConnection
from typing import Any
from typing import BinaryIO
from typing import Dict
from typing import Iterator
from typing import List
from typing import NamedTuple
from typing import Optional
from typing import Union
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.parse import urlparse
from urllib.request import Request
from urllib.request import urlopen


class ListResult(NamedTuple):
    nextStartWith: Optional[str]
    objects: List[Dict[str, Any]]
    prefixes: List[str]


MAX_LIST = 1000
MULTIPART_CHUNK = 100 * 1024 * 1024
log = logging.getLogger(__name__)


class ParClient:
    url: str
    host: str
    path: str
    conn: HTTPSConnection
    _last: Optional[HTTPResponse]

    def __init__(self, url: str):
        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise ValueError("PAR URLs must be https")
        self.url = url
        self.host = parsed.netloc
        self.path = parsed.path
        if "https_proxy" in os.environ:
            pstr = os.environ["https_proxy"]
            if "://" not in pstr:
                pstr = "http://" + pstr
            proxy = urlparse(pstr)
            log.debug("using proxy: %s", pstr)
            self.conn = HTTPSConnection(proxy.netloc)
            self.conn.set_tunnel(self.host)
        else:
            self.conn = HTTPSConnection(self.host)
        self._last = None

    def request(
        self,
        path: str,
        query: Optional[Dict[str, str]] = None,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Union[None, bytes, BinaryIO] = None,
    ) -> HTTPResponse:
        # We use a single HTTPSConnection for the lifetime of the client. This
        # is a bit lower-level than what people normally would use (urllib).
        # However, the reason makes sense: we're only making requests serially
        # in one thread, to one server. In the case of multipart uploads, it's
        # nice to avoid the extra overhead of establishing a new connection.
        #
        # For exceptionally long-lived clients, it's possible that the
        # connection gets closed unexpectedly. We may may need to implement a
        # way to reopen the connection. We'll wait and see whether it's
        # necessary before implementing that.
        #
        # Due to the use of the HTTPSConnection, we need to ensure that the
        # previous request has been fully completed before we issue a new one.
        # If the request had a body which was not read, it's a potential error.
        # However, don't raise an exception for it, because this can happen
        # during some error handling paths.
        if self._last:
            unconsumed = len(self._last.read())
            if unconsumed:
                warnings.warn(
                    f"Left {unconsumed} bytes unconsumed from previous request",
                    RuntimeWarning,
                )
        if query:
            path += "?" + urlencode(query)
        headers = headers or {}
        headers["Host"] = self.host
        headers["Connection"] = "keep-alive"
        self.conn.request(method, path, body=data, headers=headers)
        resp = self.conn.getresponse()
        self._last = resp
        logging.debug("%d: %s %s", resp.status, method, path)
        if not (200 <= resp.status < 300):
            raise HTTPError(
                f"https://{self.host}/{path}",
                resp.status,
                resp.reason,
                hdrs=resp.headers,
                fp=resp.fp,
            )
        return resp

    def _request(
        self,
        path: str,
        query: Optional[Dict[str, str]] = None,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Union[None, bytes, BinaryIO] = None,
    ) -> HTTPResponse:
        # This is an alternative implementation of request() that uses urllib.
        # It's much simpler, but of course it has extra overhead for the
        # multipart uploads. It is effectively dead code but retained here for
        # reference in case we need to revert to it later.
        if query:
            path += "?" + urlencode(query)
        req = Request(
            f"https://{self.host}{path}",
            method=method,
            headers=(headers or {}),
            data=data,
        )
        resp = urlopen(req)
        logging.debug("%d: %s %s", resp.status, method, path)
        return resp

    def __enter__(self) -> "ParClient":
        return self

    def __exit__(self, *args, **kwargs):
        self.conn.close()

    def list_objects_raw(
        self,
        prefix: Optional[str] = None,
        fields: Union[None, str, List[str]] = None,
        delimiter: Optional[str] = None,
        limit: Optional[int] = None,
        start: Optional[str] = None,
        end: Optional[str] = None,
        startAfter: Optional[str] = None,
    ) -> ListResult:
        """
        List objects in the bucket that are accessible to this PAR.

        This exposes the raw ListObjects API for the PAR, which is pretty much
        the same as the standard ListObjects API. Pagination is not directly
        handled here, instead it must be done manually or via
        ``list_objects_paginated()``. Errors are simply raised as HTTPError from
        urllib. The official OCI documentation for ListObjects should be
        considered canonical, along with any adujstments described for PARs:

        https://docs.oracle.com/en-us/iaas/api/#/en/objectstorage/20160918/Object/ListObjects
        https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/usingpreauthenticatedrequests_topic-Working_with_PreAuthenticated_Requests.htm

        :param prefix: Object prefix to filter by. Note that the PAR may have
          limitations that already filters by a prefix.
        :param fields: What fields should be returned for each object. Choices
          are documented in the OCI docs but include name, size, etag, md5,
          timeCreated, timeModified, storageTier, archivalState.
        :param delimiter: When supplied, only return objects without the
          delimiter in their name. Prefixes of object names up to the delimiter
          are also returned. This mimics a filesystem abstraction. Only "/" is a
          supported delimiter.
        :param limit: Return this many objects at a maximum. Note that OCI
          places a hard limit of 1000 on the response size.
        :param start: Return objects lexicographically greater or equal to key.
        :param end: Return objects lexicographically less or qual to key.
        :param startAfter: Return objects lexicographically greater than key.
        :returns: A list result, which contains a list of objects, as well as
          possibly a list of prefixes (when ``delimiter`` is used), and a
          ``nextStartWith`` key in case another page of results is available.
        """
        query = {}
        if isinstance(fields, list):
            query["fields"] = ",".join(fields)
        elif isinstance(fields, str):
            query["fields"] = fields

        if prefix is not None:
            query["prefix"] = prefix
        if delimiter is not None:
            query["delimiter"] = delimiter
        if limit is not None:
            query["limit"] = str(limit)
        if start is not None:
            query["limit"] = start
        if end is not None:
            query["end"] = end
        if startAfter is not None:
            query["startAfter"] = startAfter

        # There's not much point in catching and handling HTTP errors here. The
        # client will probably know better what to do with them than we will.
        data = json.load(self.request(self.path, query=query))

        objects = data["objects"]
        nextStartWith = data.get("nextStartWith")
        prefixes = data.get("prefixes", [])
        return ListResult(nextStartWith, objects, prefixes)

    def list_objects_paginated(
        self,
        prefix: Optional[str] = None,
        fields: Union[None, str, List[str]] = None,
        delimiter: Optional[str] = None,
        limit: Optional[int] = MAX_LIST,
        start: Optional[str] = None,
        end: Optional[str] = None,
        startAfter: Optional[str] = None,
    ) -> Iterator[ListResult]:
        """
        An automatically paginated version of ``list_objects_raw``

        This API returns an iterator of each result from ``list_objects_raw()``,
        handling the pagination for you. The parameters are the same as the
        above. The ``limit`` parameter will be used as a chunk size for
        pagination.
        """
        while True:
            res = self.list_objects_raw(
                prefix=prefix,
                fields=fields,
                delimiter=delimiter,
                limit=limit,
                start=start,
                end=end,
                startAfter=startAfter,
            )
            yield res
            if res.nextStartWith is not None:
                start = res.nextStartWith
            else:
                break

    def list_objects_simple(
        self,
        prefix: Optional[str] = None,
        fields: Union[None, str, List[str]] = None,
        limit: Optional[int] = MAX_LIST,
        start: Optional[str] = None,
        end: Optional[str] = None,
        startAfter: Optional[str] = None,
    ) -> Iterator[Dict[str, Any]]:
        """
        Return a transparently paginated iterator of objects

        This is the simplest version of the ListObjects API. It does not support
        the ``delimiter`` argument. It simply yields back objects, handling
        pagination using the ``limit`` provided in the parameters. See the
        documentation of ``list_objects_raw()`` for more details.
        """
        iterator = self.list_objects_paginated(
            prefix=prefix,
            fields=fields,
            limit=limit,
            start=start,
            end=end,
            startAfter=startAfter,
        )
        for result in iterator:
            yield from result.objects

    def get_object(self, key: str) -> BinaryIO:
        """
        Read an object, returning a file-like object.
        """
        path = posixpath.join(self.path, key)
        return self.request(path)

    def put_object_raw(self, key: str, data: bytes) -> None:
        """
        Upload an object directly using a single PUT request.

        Uploads can be complex for large objects. This API does the simplest
        option: it directly uploads an object using the PUT method, with all the
        data at once.
        """
        path = posixpath.join(self.path, key)
        self.request(path, method="PUT", data=data)

    def put_object_multipart(
        self,
        key: str,
        data: BinaryIO,
        chunk_size: int = MULTIPART_CHUNK,
        first_block: Optional[bytes] = None,
    ) -> None:
        """
        Upload an object using a multipart upload.
        """
        path = posixpath.join(self.path, key)
        headers = {"opc-multipart": "true"}
        with self.request(path, method="PUT", headers=headers) as f:
            multipart = json.load(f)

        try:
            part = 1
            while True:
                block = first_block or data.read(chunk_size)
                first_block = None
                if not block:
                    break
                path = posixpath.join(multipart["accessUri"], str(part))
                self.request(path, method="PUT", data=block)
                part += 1

            self.request(multipart["accessUri"], method="POST")
        except BaseException:
            # If we're interrupted for any reason, including keyboard interrupt
            # or exceptions, we need to delete the multipart upload.
            self.request(multipart["accessUri"], method="DELETE")
            raise

    def put_object(
        self,
        key: str,
        data: BinaryIO,
        chunk_size: int = MULTIPART_CHUNK,
    ) -> None:
        """
        Upload an object, selecting multipart when it is large or unknown size
        """
        first_block = data.read(chunk_size)
        if len(first_block) < chunk_size:
            self.put_object_raw(key, data.read())
        else:
            self.put_object_multipart(
                key, data, chunk_size, first_block=first_block
            )


def main():
    parser = argparse.ArgumentParser(
        description="Pre-authenticated request tools"
    )
    parser.add_argument(
        "--url",
        "-u",
        type=str,
        default=os.environ.get("OCI_PAR_URL"),
        help="Pre-authenticated request URL. This can be provided "
        "via the environment variable OCI_PAR_URL as well.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="enable debug logging",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="output file for get operation",
    )
    parser.add_argument(
        "--chunk-size",
        "-c",
        type=int,
        default=MULTIPART_CHUNK,
        help="Chunk size (in bytes) for multipart upload",
    )
    parser.add_argument(
        "operation",
        choices=["list", "ls", "get", "put"],
        help="Choose an operation",
    )
    parser.add_argument(
        "arg",
        type=str,
        default=None,
        nargs="?",
        help="Argument to operation",
    )
    parser.add_argument(
        "arg2",
        type=str,
        default=None,
        nargs="?",
        help="Argument 2 to operation",
    )

    args = parser.parse_args()
    loglevel = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(level=loglevel)
    client = ParClient(args.url)
    if args.operation == "list":
        for object in client.list_objects_simple(args.arg, fields="size"):
            print(f"{object['size']:10d}  {object['name']}")
    elif args.operation == "ls":
        for resp in client.list_objects_paginated(
            args.arg, fields="size", delimiter="/"
        ):
            for pfx in resp.prefixes:
                print(f"       DIR  {pfx}")
            for object in resp.objects:
                print(f"{object['size']:10d}  {object['name']}")
    elif args.operation == "get":
        if not args.arg:
            sys.exit("usage: get OBJECT")
        if args.output:
            out = open(args.output, "wb")
        else:
            out = os.fdopen(sys.stdout.fileno(), "wb", closefd=False)
        shutil.copyfileobj(client.get_object(args.arg), out)
    elif args.operation == "put":
        if not args.arg and not args.arg2:
            sys.exit("usage: put KEY FILENAME")
        with open(args.arg2, "rb") as f:
            client.put_object(args.arg, f, args.chunk_size)
    else:
        sys.exit(f"unknown operation: {args.operation}")


if __name__ == "__main__":
    main()
