# Copyright 2019 Open Source Robotics Foundation
# Licensed under the Apache License, version 2.0

import traceback
import xml.etree.cElementTree as ET

from colcon_core.event.test import TestFailure
from colcon_core.event_handler import EventHandlerExtensionPoint
from colcon_core.location import get_log_path
from colcon_core.plugin_system import satisfies_version
import colcon_output.event_handler.log as log
from colcon_sanitizer_reports.event_handlers.xml_helpers import XmlHelpers


class TSanReportEventHandler(EventHandlerExtensionPoint):
    """Generate a report of all Thread Sanitizer output in packages."""

    ENABLED_BY_DEFAULT = True

    # Define TSan error signatures to look for
    DATA_RACE_ERROR_SIGNATURE = \
        'WARNING: ThreadSanitizer: data race'
    DEADLOCK_ERROR_SIGNATURE = \
        'WARNING: ThreadSanitizer: lock-order-inversion'
    HEAP_USE_AFTER_FREE_ERROR_SIGNATURE = \
        'WARNING: ThreadSanitizer: lock-order-inversion'
    SIGNAL_UNSAFE_ERROR_SIGNATURE = \
        'WARNING: ThreadSanitizer: signal-unsafe call inside of a signal'
    SIGNAL_HANDLER_ERROR_SIGNATURE = \
        'WARNING: ThreadSanitizer: signal handler spoils errno'

    # Define map key strings, used to maintain counts of error signatures
    DATA_RACE_MAP_KEY = 'data-race'
    DEADLOCK_MAP_KEY = 'deadlock'
    HEAP_USE_AFTER_FREE_MAP_KEY = 'heap-use-after-free'
    SIGNAL_UNSAFE_MAP_KEY = 'signal-unsafe-call-in-signal'
    SIGNAL_HANDLER_MAP_KEY = 'signal-handler-spoils-errno'

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
        input_file_name = \
            get_log_path() / jobs[0].identifier / \
            log.STDOUT_STDERR_LOG_FILENAME
        output_file_name = 'tsan_results_parsed.xml'
        test_names = ' '.join(sorted(j.task.context.pkg.name for j in jobs))
        self._convert_log_to_xml(
            input_file_name, output_file_name, test_names, True, 'UTF-8')

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

    def _reset_error_counters(self):
        # Reset all types of error counters
        self.data_race_count = 0
        self.lock_order_inversion_count = 0
        self.heap_after_free_count = 0
        self.signal_in_signal_count = 0
        self.signal_handler_err_count = 0

    def _build_xml_doc(self, input_file_name, suite_name):

        find_place_of_data_race = False
        line_after_data_race_msg = 0
        data_race_places_with_count = {}

        find_place_of_lock_order_inversion = False
        line_after_lock_order_inversion_msg = 0
        lock_order_inversion_places_with_count = {}

        find_place_of_heap_after_free = False
        line_after_heap_after_free_msg = 0
        heap_after_free_places_with_count = {}

        find_place_of_signal_in_signal = False
        line_after_signal_in_signal_msg = 0
        signal_in_signal_places_with_count = {}

        find_place_of_signal_handler_err = False
        line_after_signal_handler_err_msg = 0
        signal_handler_err_places_with_count = {}

        with open(input_file_name, 'r') as f:
            for line in f:
                if 'Test command:' in line:
                    line_elements = line.split(' ')
                    # If package name is different from current package name,
                    # return for now.
                    if '"--package-name"' in line:
                        package_name_index = line_elements.index(
                            '"--package-name"') + 1
                    data_race_places_with_count = {}
                    lock_order_inversion_places_with_count = {}
                    heap_after_free_places_with_count = {}
                    signal_in_signal_places_with_count = {}
                    signal_handler_err_places_with_count = {}
                    if package_name_index >= 0:
                        package_name = line_elements[package_name_index]
                        if not package_name == suite_name:
                            return

                if TSanReportEventHandler.DATA_RACE_ERROR_SIGNATURE in line:
                    self.data_race_count += 1
                    find_place_of_data_race = True
                    line_after_data_race_msg = 0
                if TSanReportEventHandler.DEADLOCK_ERROR_SIGNATURE in line:
                    self.lock_order_inversion_count += 1
                    find_place_of_lock_order_inversion = True
                    line_after_lock_order_inversion_msg = 0
                if TSanReportEventHandler.HEAP_USE_AFTER_FREE_ERROR_SIGNATURE \
                   in line:
                    self.heap_after_free_count += 1
                    find_place_of_heap_after_free = True
                    line_after_heap_after_free_msg = 0
                if TSanReportEventHandler.SIGNAL_UNSAFE_ERROR_SIGNATURE \
                   in line:
                    self.signal_in_signal_count += 1
                    find_place_of_signal_in_signal = True
                    line_after_signal_in_signal_msg = 0
                if TSanReportEventHandler.SIGNAL_HANDLER_ERROR_SIGNATURE \
                   in line:
                    self.signal_handler_err_count += 1
                    find_place_of_signal_handler_err = True
                    line_after_signal_handler_err_msg = 0

                # Logic to determine place of issue
                if find_place_of_data_race:
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
                            self._add_to_summary(
                                data_race_places_with_count,
                                TSanReportEventHandler.DATA_RACE_MAP_KEY)
                        else:
                            data_race_places_with_count[data_race_place] = 1
                            self._add_to_summary(
                                data_race_places_with_count,
                                TSanReportEventHandler.DATA_RACE_MAP_KEY)
                        find_place_of_data_race = False
                        line_after_data_race_msg = 0
                    else:
                        if '#0' in line:
                            line_after_data_race_msg += 1

                if find_place_of_lock_order_inversion:
                    if line_after_lock_order_inversion_msg == 9:
                        lock_order_place = line.split(' ')[-2].rstrip('\n\r')
                        if 'null' in lock_order_place:
                            continue
                        if 'node_with_name' in lock_order_place:
                            continue
                        if lock_order_place == 'in':
                            continue
                        if lock_order_place == 'thread':
                            continue
                        if lock_order_place == 'warning':
                            continue
                        if lock_order_place in \
                                lock_order_inversion_places_with_count:
                            lock_order_inversion_places_with_count[
                                lock_order_place] += 1
                            self._add_to_summary(
                                lock_order_inversion_places_with_count,
                                TSanReportEventHandler.DEADLOCK_MAP_KEY)
                        else:
                            lock_order_inversion_places_with_count[
                                lock_order_place] = 1
                            self._add_to_summary(
                                lock_order_inversion_places_with_count,
                                TSanReportEventHandler.DEADLOCK_MAP_KEY)
                        find_place_of_lock_order_inversion = False
                        line_after_lock_order_inversion_msg = 0
                    else:
                        line_after_lock_order_inversion_msg += 1

                if find_place_of_heap_after_free:
                    if line_after_heap_after_free_msg == 3:
                        heap_after_free_place = \
                            line.split(' ')[-2].rstrip('\n\r')
                        if heap_after_free_place in \
                                heap_after_free_places_with_count:
                            heap_after_free_places_with_count[
                                heap_after_free_place] += 1
                            self._add_to_summary(
                                heap_after_free_places_with_count,
                                TSanReportEventHandler.
                                HEAP_USE_AFTER_FREE_MAP_KEY)
                        else:
                            heap_after_free_places_with_count[
                                heap_after_free_place] = 1
                            self._add_to_summary(
                                heap_after_free_places_with_count,
                                TSanReportEventHandler.
                                HEAP_USE_AFTER_FREE_MAP_KEY)
                        find_place_of_heap_after_free = False
                        line_after_heap_after_free_msg = 0
                    else:
                        line_after_heap_after_free_msg += 1

                if find_place_of_signal_in_signal:
                    if line_after_signal_in_signal_msg == 3:
                        signal_in_signal_place = \
                            line.split(' ')[-2].rstrip('\n\r')
                        if signal_in_signal_place in \
                                signal_in_signal_places_with_count:
                            signal_in_signal_places_with_count[
                                signal_in_signal_place] += 1
                            self._add_to_summary(
                                signal_in_signal_places_with_count,
                                TSanReportEventHandler.SIGNAL_UNSAFE_MAP_KEY)
                        else:
                            signal_in_signal_places_with_count[
                                signal_in_signal_place] = 1
                            self._add_to_summary(
                                signal_in_signal_places_with_count,
                                TSanReportEventHandler.SIGNAL_UNSAFE_MAP_KEY)
                        find_place_of_signal_in_signal = False
                        line_after_signal_in_signal_msg = 0
                    else:
                        line_after_signal_in_signal_msg += 1

                if find_place_of_signal_handler_err:
                    if line_after_signal_handler_err_msg == 3:
                        signal_errno_place = line.split(' ')[-2].rstrip('\n\r')
                        if signal_errno_place in \
                                signal_handler_err_places_with_count:
                            signal_handler_err_places_with_count[
                                signal_errno_place] += 1
                            self._add_to_summary(
                                signal_handler_err_places_with_count,
                                TSanReportEventHandler.SIGNAL_HANDLER_MAP_KEY)
                        else:
                            signal_handler_err_places_with_count[
                                signal_errno_place] = 1
                            self._add_to_summary(
                                signal_handler_err_places_with_count,
                                TSanReportEventHandler.SIGNAL_HANDLER_MAP_KEY)
                        find_place_of_signal_handler_err = False
                        line_after_signal_handler_err_msg = 0
                    else:
                        line_after_signal_handler_err_msg += 1

    def _to_xml_string(
            self, input_file_name, test_suites, prettyprint=True, encoding=None
    ):
        """
        Return the string representation of the JUnit XML document.

        @param encoding: encoding of the input
        @return: unicode string
        """
        try:
            iter(test_suites)
        except TypeError:
            raise Exception('test_suites must be a list of test suites')

        base_element = ET.Element('testsuites')

        for ts in test_suites:
            test_element = ET.SubElement(base_element, 'testsuite')
            test_element.set('suite-name', str(ts))

            data_race_base = ET.SubElement(
                test_element, 'data-races')
            lock_order_inversion_base = ET.SubElement(
                test_element, 'lock-order-inversions')
            heap_use_after_free_base = ET.SubElement(
                test_element, 'heap-use-after-free')
            signal_unsafe_call_base = ET.SubElement(
                test_element, 'signal-unsafe-call-inside-signal')
            signal_handler_base = ET.SubElement(
                test_element, 'signal-handler-spoils-errno')

            self._build_xml_doc(input_file_name, ts)

            self._add_summary_to_report(
                TSanReportEventHandler.DATA_RACE_MAP_KEY,
                data_race_base, self.data_race_count)
            self._add_summary_to_report(
                TSanReportEventHandler.DEADLOCK_MAP_KEY,
                lock_order_inversion_base, self.lock_order_inversion_count)
            self._add_summary_to_report(
                TSanReportEventHandler.HEAP_USE_AFTER_FREE_MAP_KEY,
                heap_use_after_free_base, self.heap_after_free_count)
            self._add_summary_to_report(
                TSanReportEventHandler.SIGNAL_UNSAFE_MAP_KEY,
                signal_unsafe_call_base, self.signal_in_signal_count)
            self._add_summary_to_report(
                TSanReportEventHandler.SIGNAL_HANDLER_MAP_KEY,
                signal_handler_base, self.signal_handler_err_count)

            self._reset_error_counters()

        xml_string = ''
        try:
            xml_string = ET.tostring(base_element, encoding=encoding,
                                     method='xml')
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

    def _convert_log_to_xml(self, input_file_name, output_file_name,
                            test_suites, prettyprint=True, encoding=None):
        """Write the JUnit XML document to a file."""
        xml_string = self._to_xml_string(input_file_name, test_suites,
                                         prettyprint=prettyprint,
                                         encoding=encoding)
        with open(output_file_name, 'w') as file:
            file.write(xml_string)
