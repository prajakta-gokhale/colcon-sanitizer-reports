import re
from typing import List, Optional, TextIO


class _Section:
    name: str
    lines: List[str]

    def __init__(self, name: str) -> None:
        """Initialize name and lines."""
        self.name = name
        self.lines = []


class Report:
    """Generate a report of all Address Sanitizer output in packages."""

    def __init__(self, report_path: str) -> None:
        """Open input log file and parse it."""
        self.sections: List[_Section] = []

        with open(report_path, 'r') as report_f_in:
            self._parse_report(report_f_in)

    def _parse_report(self, report_f_in: TextIO) -> None:
        section: Optional[_Section] = None
        for line in report_f_in.readlines():
            if section is not None:
                # Append lines to the current section.
                section.lines.append(line)

                # Stop if this is the summary line.
                m = re.match(r'^.*SUMMARY: .*Sanitizer.*$', line)
                if m is not None:
                    section = None
            else:
                # Try to match the first line of a Sanitizer output section.
                m = re.match(
                    r'^.*(WARNING|ERROR):.*Sanitizer: (?P<name>.+?)(?= \(|$)',
                    line
                )
                if m is not None:
                    section = _Section(**m.groupdict())
                    self.sections.append(section)
