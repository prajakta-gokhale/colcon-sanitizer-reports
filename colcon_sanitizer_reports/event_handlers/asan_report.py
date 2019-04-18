# Copyright 2019 Open Source Robotics Foundation
# Licensed under the Apache License, version 2.0

from colcon_core.event.job import JobEnded
from colcon_core.event_handler import EventHandlerExtensionPoint
from colcon_core.location import get_log_path
from colcon_core.plugin_system import satisfies_version
from colcon_output.event_handler.log import STDOUT_STDERR_LOG_FILENAME
from colcon_sanitizer_reports.report import Report


class ASanReportEventHandler(EventHandlerExtensionPoint):
    """Generate a report of all Address Sanitizer output in packages."""

    ENABLED_BY_DEFAULT = False

    def __init__(self):
        """Initialize."""
        super().__init__()
        satisfies_version(EventHandlerExtensionPoint.EXTENSION_POINT_VERSION, '^1.0')
        self.enabled = False
        self._report = Report()

    def __call__(self, event):
        """Start parsing."""
        data = event[0]

        if isinstance(data, JobEnded):
            self._handle(event)

    def _handle(self, event):
        """Convert test log file to xml, if present."""
        job = event[1]
        asan_log_f = get_log_path() / job.identifier / STDOUT_STDERR_LOG_FILENAME
        if not asan_log_f.exists():
            return

        with open(asan_log_f, 'r') as in_file:
            for line in in_file:
                self._report.add_line(line)

        with open('asan_report.xml', 'w') as asan_report_xml_f_out:
            asan_report_xml_f_out.write(self._report.xml)
