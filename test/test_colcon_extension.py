# Copyright 2019 Open Source Robotics Foundation
# Licensed under the Apache License, Version 2.0

import argparse

from colcon_core.event.job import JobEnded
from colcon_core.event_handler import add_event_handler_arguments
from colcon_core.event_handler import apply_event_handler_arguments
from colcon_core.event_handler import get_event_handler_extensions
from colcon_sanitizer_reports.event_handlers.asan_report \
    import ASanReportEventHandler
from colcon_sanitizer_reports.event_handlers.tsan_report \
    import TSanReportEventHandler
from mock import Mock
from mock import patch

from .entry_point_context import EntryPointContext


def test_get_shell_extensions():
    with EntryPointContext(tsan_report=TSanReportEventHandler, asan_report=ASanReportEventHandler):
        extensions = get_event_handler_extensions(context=None)
    assert list(extensions.keys()) == ['asan_report', 'tsan_report']


def test_add_event_handler_arguments():
    parser = argparse.ArgumentParser()
    with EntryPointContext(tsan_report=TSanReportEventHandler, asan_report=ASanReportEventHandler):
        add_event_handler_arguments(parser)
    text = parser.format_help()
    assert 'asan_report- tsan_report-' in text
    assert 'asan_report:' in text
    assert 'tsan_report:' in text


def test_apply_event_handler_arguments():
    with EntryPointContext(tsan_report=TSanReportEventHandler, asan_report=ASanReportEventHandler):
        extensions = get_event_handler_extensions(context=None)
    assert extensions['asan_report'].enabled is False
    assert extensions['tsan_report'].enabled is False

    extensions['tsan_report'].enabled = None
    assert extensions['asan_report'].enabled is False
    assert extensions['tsan_report'].enabled is None

    args = Mock()
    args.event_handlers = ['asan_report+', 'tsan_report-']
    apply_event_handler_arguments(extensions, args)
    assert extensions['asan_report'].enabled is True
    assert extensions['tsan_report'].enabled is False


def test_parsing_method_called():
    extension = TSanReportEventHandler()
    with patch(
        'colcon_sanitizer_reports.event_handlers.tsan_report.'
        'TSanReportEventHandler.__call__'
    ) as tsan_parser:
        event = JobEnded(['test_communication'], 0)
        extension((event, None))
        assert tsan_parser.call_count == 1

        tsan_parser.reset_mock()
        event = JobEnded(['test_rclcpp'], 0)
        extension((event, None))
        assert tsan_parser.call_count == 1

        # Extension methods will get called but not handled for unknown event types.
        tsan_parser.reset_mock()
        extension(('unknown', None))
        assert tsan_parser.call_count == 1
