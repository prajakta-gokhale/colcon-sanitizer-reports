# Copyright 2019 Open Source Robotics Foundation
# Licensed under the Apache License, Version 2.0

import argparse

from colcon_core.event.test import TestFailure
from colcon_core.event_handler import add_event_handler_arguments
from colcon_core.event_handler import apply_event_handler_arguments
from colcon_core.event_handler import get_event_handler_extensions
from colcon_sanitizer_reports.event_handlers.tsan_report \
    import TSanReportEventHandler
from mock import Mock
from mock import patch

from .entry_point_context import EntryPointContext


def test_get_shell_extensions():
    with EntryPointContext(tsan_report=TSanReportEventHandler):
        extensions = get_event_handler_extensions(context=None)
    assert list(extensions.keys()) == ['tsan_report']


def test_add_event_handler_arguments():
    parser = argparse.ArgumentParser()
    with EntryPointContext(tsan_report=TSanReportEventHandler):
        add_event_handler_arguments(parser)
    text = parser.format_help()
    assert 'tsan_report+' in text
    assert '* tsan_report:' in text
    assert 'Generate a report of all' in text


def test_apply_event_handler_arguments():
    with EntryPointContext(tsan_report=TSanReportEventHandler):
        extensions = get_event_handler_extensions(context=None)
    assert extensions['tsan_report'].enabled is True

    extensions['tsan_report'].enabled = None
    assert extensions['tsan_report'].enabled is None

    args = Mock()
    args.event_handlers = ['tsan_report-']
    apply_event_handler_arguments(extensions, args)
    assert extensions['tsan_report'].enabled is False


def test_parsing_method_called():
    extension = TSanReportEventHandler()
    with patch(
        'colcon_sanitizer_reports.event_handlers.tsan_report.'
        'TSanReportEventHandler._start_tsan_output_parsing'
    ) as tsan_parser:
        event = TestFailure(['executable'])
        extension((event, None))
        assert tsan_parser.call_count == 1

        tsan_parser.reset_mock()
        event = TestFailure(['executable'])
        extension((event, None))
        assert tsan_parser.call_count == 1

        tsan_parser.reset_mock()
        extension(('unknown', None))
        assert tsan_parser.call_count == 0
