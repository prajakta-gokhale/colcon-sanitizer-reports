# Copyright 2019 Open Source Robotics Foundation
# Licensed under the Apache License, version 2.0

from datetime import date
import traceback
import xml.etree.cElementTree as ET

from colcon_core.event.test import TestFailure
from colcon_core.event_handler import EventHandlerExtensionPoint
from colcon_core.location import get_log_path
from colcon_core.plugin_system import satisfies_version
import colcon_output.event_handler.log as log
from colcon_sanitizer_reports.event_handlers.xml_helpers import XmlHelpers
from colcon_sanitizer_reports.report import Report


class ErrorSignatures():
    """Define sanitizer error signatures."""

    DATA_RACE = 'data race'
    DEADLOCK = 'lock order inversion'
    HEAP_USE_AFTER_FREE = 'heap-use-after-free'
    SIGNAL_UNSAFE_CALL = 'signal-unsafe call inside of a signal'
    SIGNAL_HANDLER_SPOILS_ERRNO = 'signal handler spoils errno'


class ReportNames():
    """Define report representation of sanitizer errors."""

    DATA_RACE = 'data-race'
    DEADLOCK = 'lock-order-inversion'
    HEAP_USE_AFTER_FREE = 'heap-use-after-free'
    SIGNAL_UNSAFE_CALL = 'signal-unsafe-call inside-signal'
    SIGNAL_HANDLER_SPOILS_ERRNO = 'signal-handler-spoils-errno'


class TSanReportEventHandler(EventHandlerExtensionPoint):
    """Generate a report of all Thread Sanitizer output in packages."""

    ENABLED_BY_DEFAULT = True

    def __init__(self):
        """Initialize error counters and summary."""
        super().__init__()
        satisfies_version(
            EventHandlerExtensionPoint.EXTENSION_POINT_VERSION, '^1.0')

        self.data_race_count = 0
        self.lock_order_inversion_count = 0
        self.heap_after_free_count = 0
        self.signal_in_signal_count = 0
        self.signal_handler_err_count = 0
        self.final_summary_for_tsan_errors = {}

    def __call__(self, event):
        """Kick off parsing."""
        data = event[0]

        if (isinstance(data, TestFailure)):
            jobs = event[1]
            self._start_tsan_output_parsing(jobs)

    def _start_tsan_output_parsing(self, jobs):
        input_file = get_log_path() / jobs[0].identifier / \
            log.STDOUT_STDERR_LOG_FILENAME
        output_file = 'tsan_report_' + str(date.today()) + '.xml'
        report = Report(input_file)
        self._convert_log_to_xml(report, output_file, True, 'UTF-8')

    def _add_to_summary(self, errors_map, type_of_error, total_count):
        # Add individual test analysis to overall summary map
        if type_of_error not in self.final_summary_for_tsan_errors:
            self.final_summary_for_tsan_errors[type_of_error] = {}
        for key in errors_map:
            if key not in self.final_summary_for_tsan_errors[type_of_error]:
                self.final_summary_for_tsan_errors[type_of_error][key] = 0
            self.final_summary_for_tsan_errors[
                type_of_error][key] += errors_map[key]

    def _add_summary_to_report(self, map_key, base_element, total_count):
        if map_key in self.final_summary_for_tsan_errors:
            for location in self.final_summary_for_tsan_errors.get(map_key):
                XmlHelpers.insert_into_xml_tree(
                    base_element, map_key, location,
                    self.final_summary_for_tsan_errors[map_key][location])

        base_element.set('actual-reported', str(total_count))
        base_element.set(
            'potential-unique',
            str(len(self.final_summary_for_tsan_errors.get(map_key, []))))

    def _build_xml_doc(self, report):

        for section in report.sections:
            name = section.name

            line_after_data_race_msg = 0
            data_race_places_with_count = {}
            line_after_lock_order_inversion_msg = 0
            lock_order_inversion_places_with_count = {}
            line_after_heap_after_free_msg = 0
            heap_after_free_places_with_count = {}
            line_after_signal_in_signal_msg = 0
            signal_in_signal_places_with_count = {}
            line_after_signal_handler_err_msg = 0
            signal_handler_err_places_with_count = {}

            for line in section.lines:
                # Logic to determine place of issue
                if name == ErrorSignatures.DATA_RACE:
                    if line_after_data_race_msg == 1:
                        if 'libtsan' in line:
                            continue
                        if len(line.split()) < 2:
                            continue
                        data_race_place = line.split(' ')[-2].rstrip('\n\r')
                        if data_race_place == '':
                            continue
                        if 'null' in data_race_place:
                            continue
                        if data_race_place in data_race_places_with_count:
                            data_race_places_with_count[data_race_place] += 1
                        else:
                            data_race_places_with_count[data_race_place] = 1
                        self._add_to_summary(
                            data_race_places_with_count, 'data-race')
                        data_race_count += 1
                        break
                    else:
                        if '#0' in line:
                            line_after_data_race_msg += 1

                elif name == ErrorSignatures.DEADLOCK:
                    if line_after_lock_order_inversion_msg == 8:
                        lock_order_place = line.split(' ')[-2].rstrip('\n\r')
                        if 'null' in lock_order_place or \
                                'node_with_name' in lock_order_place:
                            continue
                        if lock_order_place == 'in'or \
                                lock_order_place == 'thread' or \
                                lock_order_place == 'warning':
                            continue
                        if lock_order_place in \
                                lock_order_inversion_places_with_count:
                            lock_order_inversion_places_with_count[
                                lock_order_place] += 1
                        else:
                            lock_order_inversion_places_with_count[
                                lock_order_place] = 1
                        self._add_to_summary(
                            lock_order_inversion_places_with_count, 'deadlock')
                        lock_order_inversion_count += 1
                        break
                    else:
                        line_after_lock_order_inversion_msg += 1

                elif name == ErrorSignatures.HEAP_USE_AFTER_FREE:
                    if line_after_heap_after_free_msg == 2:
                        heap_after_free_place = \
                            line.split(' ')[-2].rstrip('\n\r')
                        if heap_after_free_place in \
                                heap_after_free_places_with_count:
                            heap_after_free_places_with_count[
                                heap_after_free_place] += 1
                        else:
                            heap_after_free_places_with_count[
                                heap_after_free_place] = 1
                        self._add_to_summary(
                            heap_after_free_places_with_count,
                            'heap-use-after-free')
                        heap_after_free_count += 1
                        break
                    else:
                        line_after_heap_after_free_msg += 1

                elif name == ErrorSignatures.SIGNAL_UNSAFE_CALL:
                    if line_after_signal_in_signal_msg == 2:
                        signal_in_signal_place = \
                            line.split(' ')[-2].rstrip('\n\r')
                        if signal_in_signal_place in \
                                signal_in_signal_places_with_count:
                            signal_in_signal_places_with_count[
                                signal_in_signal_place] += 1
                        else:
                            signal_in_signal_places_with_count[
                                signal_in_signal_place] = 1
                        self._add_to_summary(
                            signal_in_signal_places_with_count,
                            'signal-unsafe-call-in-signal')
                        signal_in_signal_count += 1
                        break
                    else:
                        line_after_signal_in_signal_msg += 1

                elif name == ErrorSignatures.SIGNAL_HANDLER_SPOILS_ERRNO:
                    if line_after_signal_handler_err_msg == 2:
                        signal_errno_place = line.split(' ')[-2].rstrip('\n\r')
                        if signal_errno_place in \
                                signal_handler_err_places_with_count:
                            signal_handler_err_places_with_count[
                                signal_errno_place] += 1
                        else:
                            signal_handler_err_places_with_count[
                                signal_errno_place] = 1
                        self._add_to_summary(
                            signal_handler_err_places_with_count,
                            'signal-handler-spoils-errno')
                        signal_handler_err_count += 1
                        break
                    else:
                        line_after_signal_handler_err_msg += 1

    def _to_xml_string(self, report, prettyprint=True, encoding=None):
        """
        Return the string representation of the JUnit XML document.

        @param encoding: encoding of the input
        @return: unicode string
        """
        test_element = ET.Element('testsuites')

        data_race_base = ET.SubElement(
            test_element, ReportNames.DATA_RACE)
        lock_order_inversion_base = ET.SubElement(
            test_element, ReportNames.DEADLOCK)
        heap_use_after_free_base = ET.SubElement(
            test_element, ReportNames.HEAP_USE_AFTER_FREE)
        signal_unsafe_call_base = ET.SubElement(
            test_element, ReportNames.SIGNAL_UNSAFE_CALL)
        signal_handler_base = ET.SubElement(
            test_element, ReportNames.SIGNAL_HANDLER_SPOILS_ERRNO)

        self._build_xml_doc(report)

        self._add_summary_to_report(
            ReportNames.DATA_RACE,
            data_race_base, self.data_race_count)
        self._add_summary_to_report(
            ReportNames.DEADLOCK,
            lock_order_inversion_base, self.lock_order_inversion_count)
        self._add_summary_to_report(
            ReportNames.HEAP_USE_AFTER_FREE,
            heap_use_after_free_base, self.heap_after_free_count)
        self._add_summary_to_report(
            ReportNames.SIGNAL_UNSAFE_CALL,
            signal_unsafe_call_base, self.signal_in_signal_count)
        self._add_summary_to_report(
            ReportNames.SIGNAL_HANDLER_SPOILS_ERRNO,
            signal_handler_base, self.signal_handler_err_count)

        xml_string: str
        try:
            xml_string = ET.tostring(
                test_element, encoding=encoding, method='xml')
        except TypeError:
            print('Could not serialize parsed content into xml')
            traceback.print_exc()

        xml_string = XmlHelpers.clean_illegal_xml_chars(
            xml_string.decode(encoding or 'utf-8'))

        if prettyprint:
            xml_string = XmlHelpers.pretty_print_xml_string(
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
