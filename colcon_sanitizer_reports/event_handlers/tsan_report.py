# Copyright 2019 Open Source Robotics Foundation
# Licensed under the Apache License, version 2.0

from collections import defaultdict
from datetime import date
import re
import xml.etree.cElementTree as ET

from colcon_core.event.test import TestFailure
from colcon_core.event_handler import EventHandlerExtensionPoint
from colcon_core.location import get_log_path
from colcon_core.plugin_system import satisfies_version
import colcon_output.event_handler.log as log
from colcon_sanitizer_reports.event_handlers.xml_helpers import XmlHelpers
from colcon_sanitizer_reports.report import Report


class TSanReportEventHandler(EventHandlerExtensionPoint):
    """Generate a report of all Thread Sanitizer output in packages."""

    ENABLED_BY_DEFAULT = True

    def __init__(self):
        """Initialize error counters and summary."""
        super().__init__()
        satisfies_version(
            EventHandlerExtensionPoint.EXTENSION_POINT_VERSION, '^1.0')

        self.count_by_line_by_error = \
            defaultdict(lambda: defaultdict(lambda: 0))

    def __call__(self, event):
        """Start parsing."""
        data = event[0]

        if isinstance(data, TestFailure):
            jobs = event[1]
            self._start_tsan_output_parsing(jobs)

    def _start_tsan_output_parsing(self, jobs):
        input_file = get_log_path() / jobs[0].identifier / \
            log.STDOUT_STDERR_LOG_FILENAME
        output_file = 'tsan_report_' + str(date.today()) + '.xml'
        with open(input_file, 'r') as f_in:
            report = Report(f_in.readlines())
        self._convert_log_to_xml(report, output_file, True, 'UTF-8')

    def _build_xml_doc(self, report):
        for section in report.sections:
            for sub_section in section.sub_sections:
                for masked_line in sub_section.masked_lines:
                    # Find the first line that comes from our build.
                    if re.match(
                            r'^.*#X.*/home/jenkins.*$',
                            masked_line
                    ) is not None:
                        self.count_by_line_by_error[section.name][masked_line]\
                            += 1
                        break

    def _to_xml_string(self, report, prettyprint=True, encoding=None):
        """
        Return the string representation of the JUnit XML document.

        @param encoding: encoding of the input
        @return: unicode string
        """
        test_element = ET.Element('testsuites')

        self._build_xml_doc(report)

        element_by_error = {
            error: ET.SubElement(test_element, error.replace(' ', '_'))
            for error in self.count_by_line_by_error.keys()
        }

        for error, count_by_line in self.count_by_line_by_error.items():
            for line, count in count_by_line.items():
                XmlHelpers().insert_into_xml_tree(
                    element_by_error[error], line, count)

        try:
            xml_string = ET.tostring(
                test_element, encoding=encoding, method='xml')
        except TypeError:
            print('Could not serialize parsed content into xml')
            raise

        xml_string = XmlHelpers().clean_illegal_xml_chars(
            xml_string.decode(encoding or 'utf-8'))

        if prettyprint:
            xml_string = XmlHelpers().pretty_print_xml_string(
                xml_string, encoding)
            if encoding:
                xml_string = xml_string.decode(encoding)

        return xml_string

    def _convert_log_to_xml(
            self, report, output_file, prettyprint=True, encoding=None):
        """Write the JUnit XML document to a file."""
        xml_string = self._to_xml_string(
            report, prettyprint=prettyprint, encoding=encoding)
        with open(output_file, 'w') as file:
            file.write(xml_string)


def main():
    output_file = 'tsan_report_' + str(date.today()) + '.xml'
    with open(
            '/Users/prajaktg/workspaces/colcon-sanitizer-reports/'
            'colcon_sanitizer_reports/tsan.log', 'r') as tsan_f_in:
        report = Report(tsan_f_in.readlines())
    TSanReportEventHandler()._convert_log_to_xml(
        report, output_file, True, 'UTF-8')


if __name__ == '__main__':
    main()
