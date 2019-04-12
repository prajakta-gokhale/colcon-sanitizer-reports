from collections import defaultdict
import re
import xml.dom.minidom
import xml.etree.cElementTree as ET
from typing import Dict, List, Optional, Tuple


class _SubSection:
    lines: Tuple[str]
    masked_lines: Tuple[str]

    def __init__(self, lines: List[str]) -> None:
        self.lines = tuple(lines)

        masked_lines = []
        for line in lines:
            masked_line = line
            masked_line = re.sub(r'0x[\dabcdef]+', '0xX', masked_line)
            masked_line = re.sub(r' \d+ ', ' X ', masked_line)
            masked_line = re.sub(r'==\d+==', '==X==', masked_line)
            masked_line = re.sub(r'#\d+', '#X', masked_line)
            masked_lines.append(masked_line)

        self.masked_lines = tuple(masked_lines)


class _Section:
    """
    Contents for a single Sanitizer output section including header, \
    stack traces, and footer.
    """
    name: str
    sub_sections: Tuple[_SubSection]

    def __init__(self, lines: List[str]) -> None:
        # Section name comes after 'Sanitizer: ',
        # and before any open paren or hex number.
        self.name = re.match(
            r'^.*Sanitizer: (?P<name>.+?)(?= \(| 0x[\dabcdef]+|\s*$)', lines[0]
        ).groupdict()['name']

        # Remove log lines that pollute sanitizer output.
        lines = [
            line for line in lines
            if re.match(
                '^.*(process has died|signal_handler).*$', line) is None
        ]

        # Strip common prefix.
        prefix = lines[0]
        for line in lines:
            for i, (c0, c1) in enumerate(zip(prefix, line)):
                if c0 != c1:
                    prefix = prefix[:i]
                    break

        lines = tuple(line[len(prefix):].rstrip() for line in lines)
        for line in lines:
            assert not line.startswith('15 INFO     [test_subscriber-2]')

        # Divide into _SubSections.
        # SubSections begin with a line that is not indented.
        sub_section_lines: List[str] = []
        sub_sections: List[_SubSection] = []
        for line in lines:
            if re.match(r'^\S.*$', line) is not None and sub_section_lines:
                sub_sections.append(_SubSection(sub_section_lines))
                sub_section_lines = []

            sub_section_lines.append(line)
        else:
            sub_sections.append(_SubSection(sub_section_lines))

        self.sub_sections = tuple(sub_sections)

    @property
    def lines(self) -> Tuple[str]:
        return tuple(
            line for sub_section in
            [sub_section for sub_section in self.sub_sections]
            for line in sub_section.lines
        )


class Report:
    """
    Generate a report of all Sanitizer output in packages.
    """

    def __init__(self) -> None:
        self._sections: List[_Section] = []
        self._section_lines: Optional[List[str]] = None

    @property
    def xml(self) -> str:
        count_by_line_by_error = defaultdict(lambda: defaultdict(lambda: 0))
        for section in self.sections:
            for sub_section in section.sub_sections:
                for masked_line in sub_section.masked_lines:
                    # Find the first line that comes from our build.
                    if re.match(r'^.*#X.*/home/jenkins.*$', masked_line) is not None:
                        count_by_line_by_error[section.name][masked_line] += 1
                        break

        test_element = ET.Element('testsuites')

        element_by_error = {
            error: ET.SubElement(test_element, error.replace(' ', '_'))
            for error in count_by_line_by_error.keys()
        }

        for error, count_by_line in count_by_line_by_error.items():
            element = element_by_error[error]
            for line, count in count_by_line.items():
                ET.SubElement(
                    element,
                    element.tag,
                    {
                        'location': line,
                        'count': str(count),
                    }
                )

        return xml.dom.minidom.parseString(
            ET.tostring(test_element, encoding='unicode', method='xml')
        ).toprettyxml()

    @property
    def sections(self) -> Tuple[_Section]:
        return tuple(self._sections)

    @property
    def sections_by_name(self) -> Dict[str, Tuple[_Section]]:
        sections_by_name = {}
        for section in self.sections:
            sections_by_name.setdefault(section.name, []).append(section)

        sections_by_name = {k: tuple(v) for k, v in sections_by_name.items()}

        return sections_by_name

    def add_line(self, line) -> None:
        # Append lines to the current section.
        if self._section_lines is None:
            if re.match(r'^.*(WARNING|ERROR):.*Sanitizer:.*', line) is not None:
                self._section_lines = [line]
        else:
            self._section_lines.append(line)
            # Stop if this is the summary line.
            if re.match(r'^.*SUMMARY: .*Sanitizer: .*', line) is not None:
                self._sections.append(_Section(self._section_lines))
                self._section_lines = None
