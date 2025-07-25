# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import subprocess
from datetime import datetime
from datetime import timedelta
from pathlib import Path

from sos.report.plugins import Plugin
from sos.report.plugins import PluginOpt
from sos.report.plugins import RedHatPlugin


class LibCorelens(Plugin, RedHatPlugin):
    """
    Corelens Data Collection
    """

    plugin_name = "corelens"
    profiles = ("system", "corelens")
    short_desc = "Corelens data collection"
    option_list = [
        PluginOpt("task-days", default=3, desc="days of task history")
    ]

    def get_vmcore_dir_path(self):
        try:
            storage = None
            vmcore_path = None
            with open("/etc/kdump.conf", "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue

                    parts = line.split(None, 1)
                    if len(parts) < 2:
                        continue

                    key, value = parts

                    if key.lower() in {"raw", "ext4", "xfs", "nfs", "ssh"}:
                        storage = value
                    elif key.lower() == "path":
                        vmcore_path = value

            if vmcore_path:
                if storage and (
                    storage.startswith("LABEL=") or storage.startswith("UUID=")
                ):
                    resolved_storage = subprocess.getoutput(
                        f"findmnt -rn -o TARGET -S {storage}"
                    )
                    if resolved_storage:
                        storage = resolved_storage
                        return (
                            f"{storage}/{vmcore_path}"
                            if not vmcore_path.startswith("/")
                            else f"{storage}{vmcore_path}"
                        )
                return vmcore_path
            else:
                return None
        except Exception:
            return None

    def process_recent_vmcores(self, days):
        # This section is is to check the directory list under the path specified in kdump.conf
        # looks only for latest 5 directories
        error_logs = []
        try:
            vmcore_dir_path = self.get_vmcore_dir_path()
            if not vmcore_dir_path:
                error_logs.append(
                    "Error: Could not determine vmcore path from /etc/kdump.conf"
                )
                self.add_string_as_file(
                    "\n".join(error_logs), filename="corelens"
                )
                return

            vmcore_dir_path = Path(vmcore_dir_path)
            if not vmcore_dir_path.is_dir():
                error_logs.append(
                    f"Error: {vmcore_dir_path} is not a valid directory."
                )
                self.add_string_as_file(
                    "\n".join(error_logs), filename="corelens"
                )
                return

            now = datetime.now()
            oldest_allowed_date = now - timedelta(days)
            recent_vmcore_dirs = []

            for directory in vmcore_dir_path.iterdir():
                if directory.is_dir():
                    try:
                        timestamp_str = directory.name[-19:]
                        dir_timestamp = datetime.strptime(
                            timestamp_str, "%Y-%m-%d-%H:%M:%S"
                        )
                        if dir_timestamp >= oldest_allowed_date:
                            recent_vmcore_dirs.append(
                                (dir_timestamp, directory)
                            )
                    except ValueError:
                        error_logs.append(
                            f"Warning: Skipping invalid directory format: {directory.name}"
                        )

            recent_vmcore_dirs.sort(reverse=True, key=lambda x: x[0])
            recent_vmcore_dirs = [
                directory[1] for directory in recent_vmcore_dirs[:3]
            ]
            if not recent_vmcore_dirs:
                error_logs.append("No recent vmcore directories found.")
                self.add_string_as_file(
                    "\n".join(error_logs), filename="corelens"
                )
                return

            archive_tmp_dir = self.archive.get_tmp_dir()
            corelens_output_path = (
                Path(archive_tmp_dir) / "sos_commands/corelens"
            )
            corelens_output_path.mkdir(parents=True, exist_ok=True)

            for vmcore_subdir in recent_vmcore_dirs:
                try:
                    vmcore_file = next(vmcore_subdir.glob("*vmcore"))
                except StopIteration:
                    error_logs.append(
                        f"Error: missing vmcore in {vmcore_subdir}"
                    )
                    continue
                corelens_output_file = (
                    corelens_output_path / vmcore_subdir.name
                )
                corelens_cmd = (
                    f"corelens {vmcore_file} -A -o {corelens_output_file}"
                )
                try:
                    self.add_cmd_output(
                        corelens_cmd,
                        suggest_filename=f"corelens-{vmcore_subdir.name}",
                    )
                except subprocess.CalledProcessError:
                    error_logs.append(
                        f"Error: Failed to process vmcore at {vmcore_file}"
                    )
        except Exception as e:
            error_logs.append(f"Unexpected error: {e}")

        if error_logs:
            self.add_string_as_file("\n".join(error_logs), filename="corelens")

    def setup(self):
        days = self.get_option("task-days")
        self.process_recent_vmcores(days)
