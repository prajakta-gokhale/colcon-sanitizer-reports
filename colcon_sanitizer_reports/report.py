import re
from typing import Dict, Iterable, List, Optional, Tuple


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

    sections: Tuple[_Section]

    def __init__(self, lines: Iterable[str]) -> None:
        section_lines: Optional[List[str]] = None
        sections: List[_Section] = []
        for line in lines:
            # Append lines to the current section.
            if section_lines is None:
                if re.match(
                        r'^.*(WARNING|ERROR):.*Sanitizer:.*',
                        line
                ) is not None:
                    section_lines = [line]
            else:
                section_lines.append(line)
                # Stop if this is the summary line.
                if re.match(
                        r'^.*SUMMARY: .*Sanitizer: .*', line) is not None:
                    sections.append(_Section(section_lines))
                    section_lines = None

        self.sections = tuple(sections)

    @property
    def sections_by_name(self) -> Dict[str, Tuple[_Section]]:
        sections_by_name = {}
        for section in self.sections:
            sections_by_name.setdefault(section.name, []).append(section)

        sections_by_name = {k: tuple(v) for k, v in sections_by_name.items()}

        return sections_by_name
