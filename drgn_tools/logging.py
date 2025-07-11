# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helpers for logging with some added context info.
"""
import contextlib
import logging
import typing as t


class PrependedLoggerAdapter(logging.LoggerAdapter):
    __context: t.List[t.Tuple[str, t.Any]]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, *kwargs)
        self.__context = []

    @contextlib.contextmanager
    def add_context(self, **kwargs: t.Any) -> t.Iterator[None]:
        self.__context.extend(kwargs.items())
        try:
            yield
        finally:
            del self.__context[-len(kwargs) :]

    def process(
        self, message: str, kwargs: t.MutableMapping[str, t.Any]
    ) -> t.Tuple[str, t.MutableMapping[str, str]]:
        if not self.__context:
            return message, kwargs
        pfx = " ".join(f"[{k}={str(v)}]" for k, v in self.__context)
        return (
            f"{pfx} {message}",
            kwargs,
        )


def get_logger(name: str) -> PrependedLoggerAdapter:
    return PrependedLoggerAdapter(logging.getLogger(name), {})


class FilterMissingDebugSymbolsMessages(logging.Filter):
    def filter(self, rec: logging.LogRecord):
        # Drgn C log messages are logged with "%s" and the entirety of the
        # message as a C string by C code. We'd like to check the contents of
        # the message string, but we don't want to cause _every_ log message to
        # get formatted, even if we aren't enabled for them. Use short-circuit
        # evaluation to ensure that the log message looks like a drgn C log
        # message prior to calling getMessage(), which should then be quite
        # cheap.
        #
        # Return True if the message is to be emitted. Thus, return False when
        # we want to filter the message, i.e. if the message matches the
        # "missing debugging symbols for" text.
        if rec.msg != "%s":
            return True
        msg = rec.getMessage()
        return not (
            msg.startswith("missing debugging symbols for")
            or msg.startswith("... missing ")
        )
