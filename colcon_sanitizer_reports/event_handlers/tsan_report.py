# Copyright 2019 Open Source Robotics Foundation
# Licensed under the Apache License, version 2.0

import json
import re
import sys
import traceback
import xml.dom.minidom
import xml.etree.cElementTree as ET
from collections import defaultdict

from six import u
from colcon_core.event_handler import EventHandlerExtensionPoint
from colcon_core.plugin_system import satisfies_version


class TSanReportEventHandler(EventHandlerExtensionPoint):
    """
    Generate a report of all Thread Sanitizer output in packages.
    """

    ENABLED_BY_DEFAULT = False

    def __init__(self):
        super().__init__()
        satisfies_version(
            EventHandlerExtensionPoint.EXTENSION_POINT_VERSION, '^1.0')
        # Initialize all error counters and summary
        self.data_race_count = 0
        self.lock_order_inversion_count = 0
        self.heap_after_free_count = 0
        self.signal_in_signal_count = 0
        self.signal_handler_err_count = 0
        self.final_summary_for_tsan_errors = {}
        # Define TSan error signatures to look for
        self.DATA_RACE_ERROR_SIGNATURE = \
            'WARNING: ThreadSanitizer: data race'
        self.DEADLOCK_ERROR_SIGNATURE = \
            'WARNING: ThreadSanitizer: lock-order-inversion'
        self.HEAP_USE_AFTER_FREE_ERROR_SIGNATURE = \
            'WARNING: ThreadSanitizer: lock-order-inversion'
        self.SIGNAL_UNSAFE_ERROR_SIGNATURE = \
            'WARNING: ThreadSanitizer: signal-unsafe call inside of a signal'
        self.SIGNAL_HANDLER_ERROR_SIGNATURE = \
            'WARNING: ThreadSanitizer: signal handler spoils errno'
        # Define map key strings, used to maintain counts of error signatures
        self.DATA_RACE_MAP_KEY = 'data-race'
        self.DEADLOCK_MAP_KEY = 'deadlock'
        self.HEAP_USE_AFTER_FREE_MAP_KEY = 'heap-use-after-free'
        self.SIGNAL_UNSAFE_MAP_KEY = 'signal-unsafe-call-in-signal'
        self.SIGNAL_HANDLER_MAP_KEY = 'signal-handler-spoils-errno'

    def __call__(self, event):
        input_file_name = "actual-log.txt"
        output_file_name = "tsan_results_parsed.xml"
        testcases_list = []
        self._convert_log_to_xml(
          input_file_name, output_file_name, testcases_list, True, "UTF-8")

    def _add_to_summary(self, errors_map, type_of_error):
        # Add individual test analysis to overall summary map
        if type_of_error not in self.final_summary_for_tsan_errors:
            self.final_summary_for_tsan_errors[type_of_error] = {}
        for key in errors_map:
            if key not in self.final_summary_for_tsan_errors[type_of_error]:
                self.final_summary_for_tsan_errors[type_of_error][key] = 0
            self.final_summary_for_tsan_errors[
                type_of_error][key] += errors_map[key]

    def _insert_into_xml_tree(
      self, base_element, type_of_error, location, count):
        attrs = defaultdict(int)
        attrs['location'] = json.dumps(location)
        attrs['count'] = str(count)
        ET.SubElement(base_element, type_of_error, attrs)

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

        with open(input_file_name, "r") as f:
            for line in f:
                if 'Test command:' in line:
                    line_elements = line.split(" ")
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

                if self.DATA_RACE_ERROR_SIGNATURE in line:
                    self.data_race_count += 1
                    find_place_of_data_race = True
                    line_after_data_race_msg = 0
                if self.DEADLOCK_ERROR_SIGNATURE in line:
                    self.lock_order_inversion_count += 1
                    find_place_of_lock_order_inversion = True
                    line_after_lock_order_inversion_msg = 0
                if self.HEAP_USE_AFTER_FREE_ERROR_SIGNATURE in line:
                    self.heap_after_free_count += 1
                    find_place_of_heap_after_free = True
                    line_after_heap_after_free_msg = 0
                if self.SIGNAL_UNSAFE_ERROR_SIGNATURE in line:
                    self.signal_in_signal_count += 1
                    find_place_of_signal_in_signal = True
                    line_after_signal_in_signal_msg = 0
                if self.SIGNAL_HANDLER_ERROR_SIGNATURE in line:
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
                        data_race_place = line.split(" ")[-2].rstrip("\n\r")
                        if data_race_place == '':
                            continue
                        if 'null' in data_race_place:
                            continue
                        if data_race_place in data_race_places_with_count:
                            data_race_places_with_count[data_race_place] += 1
                            self._add_to_summary(
                                data_race_places_with_count,
                                self.DATA_RACE_MAP_KEY)
                        else:
                            data_race_places_with_count[data_race_place] = 1
                            self._add_to_summary(
                                data_race_places_with_count,
                                self.DATA_RACE_MAP_KEY)
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
                                self.DEADLOCK_MAP_KEY)
                        else:
                            lock_order_inversion_places_with_count[
                                lock_order_place] = 1
                            self._add_to_summary(
                                lock_order_inversion_places_with_count,
                                self.DEADLOCK_MAP_KEY)
                        find_place_of_lock_order_inversion = False
                        line_after_lock_order_inversion_msg = 0
                    else:
                        line_after_lock_order_inversion_msg += 1

                if find_place_of_heap_after_free:
                    if line_after_heap_after_free_msg == 3:
                        heap_after_free_place = \
                            line.split(" ")[-2].rstrip("\n\r")
                        if heap_after_free_place in \
                                heap_after_free_places_with_count:
                            heap_after_free_places_with_count[
                                heap_after_free_place] += 1
                            self._add_to_summary(
                                heap_after_free_places_with_count,
                                self.HEAP_USE_AFTER_FREE_MAP_KEY)
                        else:
                            heap_after_free_places_with_count[
                                heap_after_free_place] = 1
                            self._add_to_summary(
                                heap_after_free_places_with_count,
                                self.HEAP_USE_AFTER_FREE_MAP_KEY)
                        find_place_of_heap_after_free = False
                        line_after_heap_after_free_msg = 0
                    else:
                        line_after_heap_after_free_msg += 1

                if find_place_of_signal_in_signal:
                    if line_after_signal_in_signal_msg == 3:
                        signal_in_signal_place = \
                            line.split(" ")[-2].rstrip("\n\r")
                        if signal_in_signal_place in \
                                signal_in_signal_places_with_count:
                            signal_in_signal_places_with_count[
                                signal_in_signal_place] += 1
                            self._add_to_summary(
                                signal_in_signal_places_with_count,
                                self.SIGNAL_UNSAFE_MAP_KEY)
                        else:
                            signal_in_signal_places_with_count[
                                signal_in_signal_place] = 1
                            self._add_to_summary(
                                signal_in_signal_places_with_count,
                                self.SIGNAL_UNSAFE_MAP_KEY)
                        find_place_of_signal_in_signal = False
                        line_after_signal_in_signal_msg = 0
                    else:
                        line_after_signal_in_signal_msg += 1

                if find_place_of_signal_handler_err:
                    if line_after_signal_handler_err_msg == 3:
                        signal_errno_place = line.split(" ")[-2].rstrip("\n\r")
                        if signal_errno_place in \
                                signal_handler_err_places_with_count:
                            signal_handler_err_places_with_count[
                                signal_errno_place] += 1
                            self._add_to_summary(
                                signal_handler_err_places_with_count,
                                self.SIGNAL_HANDLER_MAP_KEY)
                        else:
                            signal_handler_err_places_with_count[
                                signal_errno_place] = 1
                            self._add_to_summary(
                                signal_handler_err_places_with_count,
                                self.SIGNAL_HANDLER_MAP_KEY)
                        find_place_of_signal_handler_err = False
                        line_after_signal_handler_err_msg = 0
                    else:
                        line_after_signal_handler_err_msg += 1

    def _find_unique_packages(self, input_file_name, test_suites):
        """
        Find unique package names for separating reports.
        """
        with open(input_file_name, "r") as f:
            for line in f:
                if 'Test command:' in line:
                    line_elements = line.split(" ")
                    if '"--package-name"' in line:
                        package_name_index = \
                            line_elements.index('"--package-name"')
                        if line_elements[package_name_index + 1] not in \
                                test_suites:
                            test_suites.append(str(line_elements[
                                package_name_index + 1]))

    def _to_xml_string(
      self, input_file_name, test_suites, prettyprint=True, encoding=None):
        """
        Returns the string representation of the JUnit XML document.
        @param encoding: The encoding of the input.
        @return: unicode string
        """
        try:
            iter(test_suites)
        except TypeError:
            raise Exception('test_suites must be a list of test suites')

        base_element = ET.Element("testsuites")

        for ts in test_suites:
            test_element = ET.SubElement(base_element, "testsuite")
            data_race_base = ET.SubElement(
                test_element, "data-races")
            lock_order_inversion_base = ET.SubElement(
                test_element, "lock-order-inversions")
            heap_use_after_free_base = ET.SubElement(
                test_element, "heap-use-after-free")
            signal_unsafe_call_base = ET.SubElement(
                test_element, "signal-unsafe-call-inside-signal")
            signal_handler_base = ET.SubElement(
                test_element, "signal-handler-spoils-errno")

            self._build_xml_doc(input_file_name, ts)

            if self.DATA_RACE_MAP_KEY in self.final_summary_for_tsan_errors:
                for location in self.final_summary_for_tsan_errors.get(
                  self.DATA_RACE_MAP_KEY):
                    self._insert_into_xml_tree(
                        data_race_base,
                        self.DATA_RACE_MAP_KEY,
                        location,
                        self.final_summary_for_tsan_errors
                        [self.DATA_RACE_MAP_KEY][location])
            if self.DEADLOCK_MAP_KEY in self.final_summary_for_tsan_errors:
                for location in self.final_summary_for_tsan_errors.get(
                  self.DEADLOCK_MAP_KEY):
                    self._insert_into_xml_tree(
                        lock_order_inversion_base,
                        self.DEADLOCK_MAP_KEY,
                        location,
                        self.final_summary_for_tsan_errors
                        [self.DEADLOCK_MAP_KEY][location])
            if self.HEAP_USE_AFTER_FREE_MAP_KEY in \
                    self.final_summary_for_tsan_errors:
                for location in self.final_summary_for_tsan_errors.get(
                  self.HEAP_USE_AFTER_FREE_MAP_KEY):
                    self._insert_into_xml_tree(
                        heap_use_after_free_base,
                        self.HEAP_USE_AFTER_FREE_MAP_KEY,
                        location,
                        self.final_summary_for_tsan_errors
                        [self.HEAP_USE_AFTER_FREE_MAP_KEY][location])
            if self.SIGNAL_UNSAFE_MAP_KEY in \
                    self.final_summary_for_tsan_errors:
                for location in self.final_summary_for_tsan_errors.get(
                  self.SIGNAL_UNSAFE_MAP_KEY):
                    self._insert_into_xml_tree(
                        signal_unsafe_call_base,
                        self.SIGNAL_UNSAFE_MAP_KEY,
                        location,
                        self.final_summary_for_tsan_errors
                        [self.SIGNAL_UNSAFE_MAP_KEY][location])
            if self.SIGNAL_HANDLER_MAP_KEY in \
                    self.final_summary_for_tsan_errors:
                for location in self.final_summary_for_tsan_errors.get(
                  self.SIGNAL_HANDLER_MAP_KEY):
                    self._insert_into_xml_tree(
                        signal_handler_base,
                        self.SIGNAL_HANDLER_MAP_KEY,
                        location,
                        self.final_summary_for_tsan_errors
                        [self.SIGNAL_HANDLER_MAP_KEY][location])

            test_element.set('suite-name', str(ts))

            data_race_base.set(
                'actual-reported', str(self.data_race_count))
            data_race_base.set(
                'potential-unique',
                str(len(self.final_summary_for_tsan_errors.get(
                    self.DATA_RACE_MAP_KEY, []))))

            lock_order_inversion_base.set(
                'actual-reported', str(self.lock_order_inversion_count))
            lock_order_inversion_base.set(
                'potential-unique',
                str(len(self.final_summary_for_tsan_errors.get(
                    self.DEADLOCK_MAP_KEY, []))))

            heap_use_after_free_base.set(
                'actual-reported', str(self.heap_after_free_count))
            heap_use_after_free_base.set(
                'potential-unique',
                str(len(self.final_summary_for_tsan_errors.get(
                    self.HEAP_USE_AFTER_FREE_MAP_KEY, []))))

            signal_unsafe_call_base.set(
                'actual-reported', str(self.signal_in_signal_count))
            signal_unsafe_call_base.set(
                'potential-unique',
                str(len(self.final_summary_for_tsan_errors.get(
                    self.SIGNAL_UNSAFE_MAP_KEY, []))))

            signal_handler_base.set(
                'actual-reported', str(self.signal_handler_err_count))
            signal_handler_base.set(
                'potential-unique',
                str(len(self.final_summary_for_tsan_errors.get(
                    self.SIGNAL_HANDLER_MAP_KEY, []))))

            self._reset_error_counters()

        xml_string = ''
        try:
            xml_string = ET.tostring(base_element, encoding=encoding,
                                     method='xml')
        except TypeError:
            print('Could not serialize parsed content into xml')
            traceback.print_exc()
        # is encoded now
        xml_string = self._clean_illegal_xml_chars(
            xml_string.decode(encoding or 'utf-8'))
        # is unicode now

        if prettyprint:
            # minidom.parseString() works just on
            # correctly encoded binary strings
            xml_string = xml_string.encode(encoding or 'utf-8')
            xml_string = xml.dom.minidom.parseString(xml_string)
            # toprettyxml() produces unicode if no encoding is being passed
            # or binary string with an encoding
            xml_string = xml_string.toprettyxml(encoding=encoding)
            if encoding:
                xml_string = xml_string.decode(encoding)
        return xml_string

    def _convert_log_to_xml(self, input_file_name, output_file_name,
                            test_suites, prettyprint=True, encoding=None):
        """
        Writes the JUnit XML document to a file.
        """
        self._find_unique_packages(input_file_name, test_suites)
        xml_string = self._to_xml_string(
            input_file_name,
            test_suites,
            prettyprint=prettyprint,
            encoding=encoding)
        with open(output_file_name, 'w') as file:
            file.write(xml_string)

    def _clean_illegal_xml_chars(self, string_to_clean):
        """
        Removes any illegal unicode characters from the given XML string.
        See:
        http://stackoverflow.com/questions/1707890/fast-way-to-filter-illegal-xml-unicode-chars-in-python
        """
        illegal_chrs = [
            (0x00, 0x08), (0x0B, 0x1F), (0x7F, 0x84), (0x86, 0x9F),
            (0xD800, 0xDFFF), (0xFDD0, 0xFDDF), (0xFFFE, 0xFFFF),
            (0x1FFFE, 0x1FFFF), (0x2FFFE, 0x2FFFF), (0x3FFFE, 0x3FFFF),
            (0x4FFFE, 0x4FFFF), (0x5FFFE, 0x5FFFF), (0x6FFFE, 0x6FFFF),
            (0x7FFFE, 0x7FFFF), (0x8FFFE, 0x8FFFF), (0x9FFFE, 0x9FFFF),
            (0xAFFFE, 0xAFFFF), (0xBFFFE, 0xBFFFF), (0xCFFFE, 0xCFFFF),
            (0xDFFFE, 0xDFFFF), (0xEFFFE, 0xEFFFF), (0xFFFFE, 0xFFFFF),
            (0x10FFFE, 0x10FFFF)]

        illegal_ranges = ["%s-%s" % (chr(low), chr(high))
                          for (low, high) in illegal_chrs
                          if low < sys.maxunicode]

        illegal_xml_re = re.compile(u('[%s]') % u('').join(illegal_ranges))
        return illegal_xml_re.sub('', string_to_clean)
