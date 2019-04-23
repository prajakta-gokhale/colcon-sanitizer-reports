from csv import DictReader
import os
from typing import Dict, Optional, Tuple

from colcon_sanitizer_reports.report import Report
import pytest


class Fixture:

    def __init__(self, resource_name: str) -> None:
        self.resource_name = resource_name
        self._report: Optional[Report] = None

    @property
    def resource_path(self) -> str:
        return os.path.dirname(os.path.abspath(__file__)) + '/resources/' + self.resource_name

    @property
    def input_log_path(self) -> str:
        return self.resource_path + '/input.log'

    @property
    def expected_output_csv_path(self) -> str:
        return self.resource_path + '/expected_output.csv'

    @property
    def report(self) -> Report:
        if self._report is None:
            report = Report()
            with open(self.input_log_path, 'r') as input_log_f_in:
                for line in input_log_f_in.readlines():
                    report.add_line(line)

            self._report = report

        return self._report

    @property
    def report_csv(self) -> DictReader:
        return DictReader(self.report.csv.split('\n'))

    @property
    def expected_csv(self) -> DictReader:
        with open(self.expected_output_csv_path, 'r') as expected_output_csv_f_in:
            return DictReader(expected_output_csv_f_in.read().split('\n'))


@pytest.fixture(params=os.listdir(os.path.dirname(os.path.abspath(__file__)) + '/resources'))
def fixture(request) -> Fixture:
    return Fixture(request.param)


def test_csv_has_field_names(fixture) -> None:
    assert tuple(fixture.report_csv.fieldnames) == ('package', 'error_name', 'key', 'count')


def test_csv_has_output(fixture) -> None:
    if fixture.resource_name == 'no_errors':
        assert len(list(fixture.report_csv)) == 0
    else:
        assert len(list(fixture.report_csv)) > 0


def test_csv_has_expected_line_count(fixture) -> None:
    assert len(list(fixture.report_csv)) == len(list(fixture.expected_csv))


def test_csv_has_expected_lines(fixture) -> None:
    def make_key(line: Dict[str, str]) -> Tuple[str, ...]:
        return tuple(line.items())

    expected_line_by_key = {make_key(line): line for line in fixture.expected_csv}

    for line in fixture.report_csv:
        assert line == expected_line_by_key.pop(make_key(line))
