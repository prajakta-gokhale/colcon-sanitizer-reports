from collections import defaultdict
import csv
from io import StringIO
import re
from typing import Dict, List, Optional, Tuple


class _KeysFactory:

    @staticmethod
    def _make_keys_base(
            *,
            masked_lines: Tuple[str],
            stack_begin_regexes: Tuple[str, ...]
    ) -> Tuple[str]:

        keys: List[str] = []

        masked_lines = iter(masked_lines)
        for stack_begin_regex in stack_begin_regexes:
            for masked_line in masked_lines:
                if re.match(stack_begin_regex, masked_line) is not None:
                    break

            for masked_line in masked_lines:
                match = re.match(r'^\s*#X (0xX in|)\s*(?P<key>.*/ros2.*)\s*$', masked_line)
                if match is not None:
                    keys.append(match.groupdict()['key'])
                    break
            else:
                keys = []

        return tuple(keys)

    @staticmethod
    def _make_default_keys(*, masked_lines: Tuple[str]) -> Tuple[str]:
        return _KeysFactory._make_keys_base(
            masked_lines=masked_lines,
            stack_begin_regexes=(
                r'^.*$',
            ),
        )

    @staticmethod
    def _make_detected_memory_leaks_keys(*, masked_lines: Tuple[str]) -> Tuple[str]:
        return _KeysFactory._make_keys_base(
            masked_lines=masked_lines,
            stack_begin_regexes=(
                r'^Direct leak of X byte\(s\) in X object\(s\) allocated from:$',
            )
        )

    @staticmethod
    def _make_data_race_keys(*, masked_lines: Tuple[str]) -> Tuple[str]:
        return _KeysFactory._make_keys_base(
            masked_lines=masked_lines,
            stack_begin_regexes=(
                r'^\s+(Read|Write) of size X at 0xX .*$',
                r'^\s+Previous (read|write) of size X at 0xX .*$'
            )
        )

    @staticmethod
    def _make_lock_order_inversion_keys(*, masked_lines: Tuple[str]) -> Tuple[str]:
        return _KeysFactory._make_keys_base(
            masked_lines=masked_lines,
            stack_begin_regexes=(
                r'^\s+Mutex M\d+ acquired here while holding mutex M\d+ in .*$',
                r'^\s+Mutex M\d+ acquired here while holding mutex M\d+ in .*$'
            )
        )

    @staticmethod
    def make_keys(
            *,
            masked_lines: Tuple[str],
            error_name: str
    ) -> Tuple[str]:
        if error_name == 'data race':
            return _KeysFactory._make_data_race_keys(masked_lines=masked_lines)
        elif error_name == 'detected memory leaks':
            return _KeysFactory._make_detected_memory_leaks_keys(masked_lines=masked_lines)
        elif error_name == 'lock-order-inversion':
            return _KeysFactory._make_lock_order_inversion_keys(masked_lines=masked_lines)
        else:
            return _KeysFactory._make_default_keys(masked_lines=masked_lines)


class _SubSection:
    lines: Tuple[str]
    masked_lines: Tuple[str]
    keys: Tuple[str]

    def __init__(self, *, lines: Tuple[str], error_name: str) -> None:
        self.lines = lines

        masked_lines = []
        for line in lines:
            masked_line = line
            masked_line = re.sub(r'0x[\dabcdef]+', '0xX', masked_line)
            masked_line = re.sub(r' \d+ ', ' X ', masked_line)
            masked_line = re.sub(r'==\d+==', '==X==', masked_line)
            masked_line = re.sub(r'#\d+', '#X', masked_line)
            masked_lines.append(masked_line)

        self.masked_lines = tuple(masked_lines)

        self.keys = _KeysFactory.make_keys(
            masked_lines=self.masked_lines, error_name=error_name)


class _Section:
    """Contents for a single Sanitizer output section."""

    package_name: str
    error_name: str
    sub_sections: Tuple[_SubSection]

    def __init__(self, *, package_name: str, lines: Tuple[str]) -> None:
        # Section name comes after 'Sanitizer: ', and before any open paren or hex number.
        self.package_name = package_name
        self.error_name = re.match(
            r'^.*Sanitizer: (?P<error_name>.+?)( \(| 0x[\dabcdef]+|\s*$)', lines[0]
        ).groupdict()['error_name']

        # Divide into _SubSections. SubSections begin with a line that is not indented.
        sub_section_lines: List[str] = []
        sub_sections: List[_SubSection] = []
        for line in lines:
            if re.match(r'^\S.*$', line) is not None and sub_section_lines:
                sub_sections.append(
                    _SubSection(
                        lines=tuple(sub_section_lines),
                        error_name=self.error_name
                    )
                )
                sub_section_lines = []

            sub_section_lines.append(line)
        else:
            sub_sections.append(
                _SubSection(
                    lines=tuple(sub_section_lines),
                    error_name=self.error_name
                )
            )

        self.sub_sections = tuple(sub_sections)


class Report:
    """Generate a report from logged errors and warnings."""

    def __init__(self) -> None:
        """Initialize report fields."""
        self._sections: List[_Section] = []
        self._package: Optional[str] = None

        self._section_lines_by_prefix: Dict[str: List[str]] = {}

    @property
    def csv(self) -> str:
        """Return a csv represenr=tation of reported error/warnings."""
        count_by_key_by_error_name_by_package = \
            defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: 0)))

        for section in self.sections:
            for sub_section in section.sub_sections:
                for key in sub_section.keys:
                    count_by_key_by_error_name_by_package[
                        section.package_name][section.error_name][key] += 1

        csv_f_out = StringIO()
        writer = csv.writer(csv_f_out)
        writer.writerow(['package', 'error_name', 'key', 'count'])

        for package, count_by_key_by_error_name in count_by_key_by_error_name_by_package.items():
            for error_name, count_by_key in count_by_key_by_error_name.items():
                for key, count in count_by_key.items():
                    writer.writerow([package, error_name, key, count])

        return csv_f_out.getvalue()

    @property
    def sections(self) -> Tuple[_Section]:
        """Return all sections of this report."""
        return tuple(self._sections)

    def add_line(self, line: str) -> None:
        """Generate report from log file lines."""
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
        match = re.match(r'^(?P<prefix>.*)(SUMMARY: .*Sanitizer: .*)$', line)
        if match is not None:
            prefix = match.groupdict()['prefix']
            self._sections.append(
                _Section(
                    package_name=self._package,
                    lines=tuple(self._section_lines_by_prefix[prefix])
                )
            )
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
