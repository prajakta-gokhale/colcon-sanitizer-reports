# Copyright 2019 Open Source Robotics Foundation
# Licensed under the Apache License, version 2.0

from collections import defaultdict
import json
import re
import sys
import xml.dom.minidom
import xml.etree.cElementTree as ET

from six import u


class XmlHelpers:
    """XML helper methods for Sanitizer output parsing scripts."""

    def insert_into_xml_tree(self, base_element, location, count):
        """Insert error summary data into XML structure."""
        attrs = defaultdict(int)
        attrs['location'] = json.dumps(location)
        attrs['count'] = str(count)
        ET.SubElement(base_element, base_element.tag, attrs)

    @staticmethod
    def clean_illegal_xml_chars(string_to_clean):
        """Remove illegal unicode characters from the given XML string."""
        illegal_chrs = [
            (0x00, 0x08), (0x0B, 0x1F), (0x7F, 0x84), (0x86, 0x9F),
            (0xD800, 0xDFFF), (0xFDD0, 0xFDDF), (0xFFFE, 0xFFFF),
            (0x1FFFE, 0x1FFFF), (0x2FFFE, 0x2FFFF), (0x3FFFE, 0x3FFFF),
            (0x4FFFE, 0x4FFFF), (0x5FFFE, 0x5FFFF), (0x6FFFE, 0x6FFFF),
            (0x7FFFE, 0x7FFFF), (0x8FFFE, 0x8FFFF), (0x9FFFE, 0x9FFFF),
            (0xAFFFE, 0xAFFFF), (0xBFFFE, 0xBFFFF), (0xCFFFE, 0xCFFFF),
            (0xDFFFE, 0xDFFFF), (0xEFFFE, 0xEFFFF), (0xFFFFE, 0xFFFFF),
            (0x10FFFE, 0x10FFFF)]

        illegal_ranges = ['%s-%s' % (chr(low), chr(high))
                          for (low, high) in illegal_chrs
                          if low < sys.maxunicode]

        illegal_xml_re = re.compile(u('[%s]') % u('').join(illegal_ranges))
        return illegal_xml_re.sub('', string_to_clean)

    @staticmethod
    def pretty_print_xml_string(string_to_print, encoding):
        """Prett-print the given xml string."""
        # minidom.parseString() works just on
        # correctly encoded binary strings
        string_to_print = string_to_print.encode(encoding or 'utf-8')
        string_to_print = xml.dom.minidom.parseString(string_to_print)
        # toprettyxml() produces unicode if no encoding is being passed
        # or binary string with an encoding
        string_to_print = string_to_print.toprettyxml(encoding=encoding)

        return string_to_print
