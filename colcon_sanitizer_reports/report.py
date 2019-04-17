from collections import defaultdict
import csv
import re
from io import StringIO
from pathlib import Path
import xml.dom.minidom
import xml.etree.cElementTree as ET
from typing import Dict, List, Optional, Tuple


class _SubSection:
    lines: Tuple[str]
    masked_lines: Tuple[str]
    key: Optional[str]

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

        self.key = None
        for masked_line in self.masked_lines:
            # Find the first line that comes from our build.
            if str(Path.home()) in masked_line:
                self.key = masked_line
                break


class _Section:
    """
    Contents for a single Sanitizer output section including header, \
    stack traces, and footer.
    """
    package: str
    name: str
    sub_sections: Tuple[_SubSection]

    def __init__(self, package: str, lines: List[str]) -> None:
        # Section name comes after 'Sanitizer: ',
        # and before any open paren or hex number.
        self.package = package
        self.name = re.match(
            r'^.*Sanitizer: (?P<name>.+?)( \(| 0x[\dabcdef]+|\s*$)', lines[0]
        ).groupdict()['name']

        # Divide into _SubSections. SubSections begin with a line that is not indented.
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
        self._package: Optional[str] = None

        self._section_lines_by_prefix: Dict[str: List[str]] = {}

    @property
    def xml(self) -> str:
        count_by_line_by_error = defaultdict(lambda: defaultdict(lambda: 0))
        for section in self.sections:
            for sub_section in section.sub_sections:
                if sub_section.key is not None:
                    count_by_line_by_error[section.name][sub_section.key] += 1

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
    def csv(self) -> str:
        count_by_line_by_error_by_package = \
            defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: 0)))

        for section in self.sections:
            for sub_section in section.sub_sections:
                if sub_section.key is not None:
                    count_by_line_by_error_by_package[section.package][section.name][
                        sub_section.key] += 1

        csv_f_out = StringIO()
        writer = csv.writer(csv_f_out)
        writer.writerow(['package', 'error', 'line', 'count'])

        for package, count_by_line_by_error in count_by_line_by_error_by_package.items():
            for error, count_by_line in count_by_line_by_error.items():
                for line, count in count_by_line.items():
                    writer.writerow([package, error, line.strip(), count])

        return csv_f_out.getvalue()

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

    def add_line(self, line: str) -> None:
        line = line.rstrip()

        # If we have a new sanitizer section, start gathering its lines in self._sections_by_line
        match = re.match(r'^(?P<prefix>.*?)(==\d+==|)(WARNING|ERROR):.*Sanitizer:.*', line)
        if match is not None:
            prefix = match.groupdict()['prefix']
            self._section_lines_by_prefix[prefix] = []

        # Check if this line should belong to any of the sections we're currently building.
        for prefix in self._section_lines_by_prefix.keys():
            match = re.match(r'^{prefix}(?P<line>.*)$'.format(prefix=re.escape(prefix)), line)
            if match is not None:
                self._section_lines_by_prefix[prefix].append(match.groupdict()['line'])
                break

        # If this is the final line of a section, create the section and stop gathering lines for it
        match = re.match(r'^(?P<prefix>.*)SUMMARY: .*Sanitizer: .*', line)
        if match is not None:
            prefix = match.groupdict()['prefix']
            self._sections.append(_Section(self._package, self._section_lines_by_prefix[prefix]))
            del self._section_lines_by_prefix[prefix]
            return

        # Keep track of the start of packages.
        match = re.match(r'^.*Starting >>> (?P<package>\S+).*$', line)
        if match is not None:
            self._package = match.groupdict()['package']
            return

        # Keep track of the end of packages.
        match = re.match(r'^.*Finished <<< .*$', line)
        if match is not None:
            self._package = None
            return
