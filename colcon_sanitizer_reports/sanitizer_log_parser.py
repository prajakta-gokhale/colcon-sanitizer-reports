from collections import defaultdict
import csv
from io import StringIO
import re
from typing import Dict, List, Optional, Tuple


class _KeysFactory:
    """Finds key stack trace lines in sanitizer error subsections."""

    @staticmethod
    def _make_masked_line(line: str) -> str:
        """Masks numbers in a sanitizer error line so that keys from similar errors will match."""
        masked_line = line
        masked_line = re.sub(r'0x[\dabcdef]+', '0xX', masked_line)
        masked_line = re.sub(r' \d+ ', ' X ', masked_line)
        masked_line = re.sub(r'#\d+', '#X', masked_line)

        return masked_line

    @staticmethod
    def _make_keys_base(*, lines: Tuple[str], stack_begin_regexes: Tuple[str, ...]) -> Tuple[str]:
        keys: List[str] = []

        lines = iter(lines)
        for stack_begin_regex in stack_begin_regexes:
            for line in lines:
                match = re.match(
                    stack_begin_regex,
                    _KeysFactory._make_masked_line(line)
                )
                if match is not None:
                    break

            for line in lines:
                match = re.match(
                    r'^\s*#X (0xX in|)\s*(?P<key>.*/ros2.*)\s*$',
                    _KeysFactory._make_masked_line(line)
                )
                if match is not None:
                    keys.append(match.groupdict()['key'])
                    break
            else:
                # We didn't find one of the keys we were required to find.
                keys = []
                break

        return tuple(keys)

    @staticmethod
    def _make_default_keys(*, lines: Tuple[str]) -> Tuple[str]:
        # Most sanitizer errors have the only/most significant stack trace first in a subsection, so
        # we assume we've already found the correct stack trace.
        return _KeysFactory._make_keys_base(
            lines=lines,
            stack_begin_regexes=(
                r'^.*$',
            ),
        )

    @staticmethod
    def _make_detected_memory_leaks_keys(*, lines: Tuple[str]) -> Tuple[str]:
        # There is one stack trace per subsection in a "detected memory leaks" error.
        return _KeysFactory._make_keys_base(
            lines=lines,
            stack_begin_regexes=(
                r'^Direct leak of X byte\(s\) in X object\(s\) allocated from:$',
            )
        )

    @staticmethod
    def _make_data_race_keys(*, lines: Tuple[str]) -> Tuple[str]:
        # There are two stack traces involved a "data race" error, both in the same subsection.
        return _KeysFactory._make_keys_base(
            lines=lines,
            stack_begin_regexes=(
                r'^\s+(Read|Write) of size X at 0xX .*$',
                r'^\s+Previous (read|write) of size X at 0xX .*$'
            )
        )

    @staticmethod
    def _make_lock_order_inversion_keys(*, lines: Tuple[str]) -> Tuple[str]:
        # There are two stack traces involved in a "lock-order-inversion" error, both in the same
        # subsection and with identical header lines.
        return _KeysFactory._make_keys_base(
            lines=lines,
            stack_begin_regexes=(
                r'^\s+Mutex M\d+ acquired here while holding mutex M\d+ in .*$',
                r'^\s+Mutex M\d+ acquired here while holding mutex M\d+ in .*$'
            )
        )

    @staticmethod
    def make_keys(*, lines: Tuple[str], error_name: str) -> Tuple[str]:
        if error_name == 'data race':
            return _KeysFactory._make_data_race_keys(lines=lines)
        elif error_name == 'detected memory leaks':
            return _KeysFactory._make_detected_memory_leaks_keys(lines=lines)
        elif error_name == 'lock-order-inversion':
            return _KeysFactory._make_lock_order_inversion_keys(lines=lines)
        else:
            return _KeysFactory._make_default_keys(lines=lines)


class _SubSection:
    keys: Tuple[str]

    def __init__(self, *, lines: Tuple[str], error_name: str) -> None:
        self.keys = _KeysFactory.make_keys(lines=lines, error_name=error_name)


class _Section:
    """Contents for a single Sanitizer output section."""

    error_name: str
    sub_sections: Tuple[_SubSection]

    def __init__(self, *, lines: Tuple[str]) -> None:
        # Section name comes after 'Sanitizer: ', and before any open paren or hex number.
        self.error_name = re.match(
            r'^.*Sanitizer: (?P<error_name>.+?)( \(| 0x[\dabcdef]+|\s*$)', lines[0]
        ).groupdict()['error_name']

        # Divide into _SubSections. SubSections begin with a line that is not indented.
        sub_section_lines: List[str] = []
        sub_sections: List[_SubSection] = []
        for line in lines:
            if re.match(r'^\S.*$', line) is not None and sub_section_lines:
                sub_sections.append(
                    _SubSection(lines=tuple(sub_section_lines), error_name=self.error_name)
                )
                sub_section_lines = []

            sub_section_lines.append(line)
        else:
            sub_sections.append(
                _SubSection(lines=tuple(sub_section_lines), error_name=self.error_name)
            )

        self.sub_sections = tuple(sub_sections)


class SanitizerLogParser:
    """Parses logged sanitizer errors and warnings and generates report."""

    def __init__(self) -> None:
        # Holds count of errors seen. This is what will be in the report.
        self._counts = defaultdict(int)

        # Current package and sections that are partially parsed
        self._package: Optional[str] = None
        self._section_lines_by_prefix: Dict[str: List[str]] = {}

    @property
    def csv(self) -> str:
        """Return a csv representation of reported error/warnings."""
        csv_f_out = StringIO()
        writer = csv.writer(csv_f_out)
        writer.writerow(['package', 'error_name', 'key', 'count'])
        for (package, error_name, key), count in self._counts.items():
            writer.writerow([package, error_name, key, count])

        return csv_f_out.getvalue()

    def set_package(self, package: Optional[str]) -> None:
        self._package = package

    def add_line(self, line: str) -> None:
        """Generate report from log file lines."""
        line = line.rstrip()

        # If we have a new sanitizer section, start gathering lines for it.
        match = re.match(r'^(?P<prefix>.*?)(==\d+==|)(WARNING|ERROR):.*Sanitizer:.*', line)
        if match is not None:
            prefix = match.groupdict()['prefix']
            self._section_lines_by_prefix[prefix] = []

        # Check if this line belongs to any of the sections we're currently building.
        for prefix in self._section_lines_by_prefix.keys():
            match = re.match(r'^{prefix}(?P<line>.*)$'.format(prefix=re.escape(prefix)), line)
            if match is not None:
                self._section_lines_by_prefix[prefix].append(match.groupdict()['line'])
                break

        # If this is the last line of a section, create the section and stop gathering lines for it.
        match = re.match(r'^(?P<prefix>.*)(SUMMARY: .*Sanitizer: .*)$', line)
        if match is not None:
            prefix = match.groupdict()['prefix']
            section = _Section(lines=tuple(self._section_lines_by_prefix[prefix]))
            for sub_section in section.sub_sections:
                for key in sub_section.keys:
                    self._counts[(self._package, section.error_name, key)] += 1
            del self._section_lines_by_prefix[prefix]
            return
