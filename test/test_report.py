from contextlib import ExitStack
from tempfile import NamedTemporaryFile
from typing import TextIO
import unittest

from colcon_sanitizer_reports.report import Report


class TestReport(unittest.TestCase):

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.exit_stack = ExitStack()

    def setUp(self) -> None:
        self.temp_f: TextIO = self.exit_stack.enter_context(
            NamedTemporaryFile('w'))

    def tearDown(self) -> None:
        self.exit_stack.close()

    def set_report_text(self, text: str) -> None:
        self.temp_f.truncate(0)
        self.temp_f.write(text)
        self.temp_f.flush()

    def test_report_creates_section_for_error(self) -> None:
        self.set_report_text(
            '2: ==17726==ERROR: LeakSanitizer: detected memory leaks')

        report = Report(self.temp_f.name)
        self.assertEqual(len(report.sections), 1)

    def test_report_creates_two_sections_for_two_errors(self) -> None:
        self.set_report_text('\n'.join([
            '2: ==17726==ERROR: LeakSanitizer: detected memory leaks',
            '2: SUMMARY: AddressSanitizer: '
            '96 byte(s) leaked in 3 allocation(s).',
            '27: [test_requester-2] WARNING: ThreadSanitizer: '
            'lock-order-inversion (potential deadlock) (pid=19699)',
            '27: [test_requester-2] SUMMARY: ThreadSanitizer: '
            'lock-order-inversion (potential deadlock) '
            '(/usr/lib/x86_64-linux-gnu/libtsan.so.0+0x3faeb) in '
            '__interceptor_pthread_mutex_lock'
        ]))

        report = Report(self.temp_f.name)
        self.assertEqual(len(report.sections), 2)

    def test_report_detects_error_name(self) -> None:
        self.set_report_text(
            '2: ==17726==ERROR: LeakSanitizer: detected memory leaks')
        report = Report(self.temp_f.name)
        self.assertEqual(report.sections[0].name, 'detected memory leaks')

    def test_report_detects_error_name_with_trailing_info(self) -> None:
        self.set_report_text(
            '27: [test_requester-2] WARNING: ThreadSanitizer: '
            'lock-order-inversion (potential deadlock) (pid=19699)'
        )
        report = Report(self.temp_f.name)
        self.assertEqual(report.sections[0].name, 'lock-order-inversion')


if __name__ == '__main__':
    unittest.main(verbosity=2)
