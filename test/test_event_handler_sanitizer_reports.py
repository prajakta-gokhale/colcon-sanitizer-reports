# Copyright 2019 Open Source Robotics Foundation
# Licensed under the Apache License, Version 2.0


from colcon_core.event.job import JobEnded
from colcon_sanitizer_reports.event_handlers.asan_report \
    import ASanReportEventHandler
from colcon_sanitizer_reports.event_handlers.tsan_report \
    import TSanReportEventHandler
from mock import patch


def test_event_handler_asan_report():
    extension = ASanReportEventHandler()
    with patch(
        'colcon_sanitizer_reports.event_handlers.asan_report.'
        'ASanReportEventHandler._handle'
    ) as asan_handler:
        event = JobEnded(['test_communication'], 0)
        extension((event, None))
        assert asan_handler.call_count == 1

        asan_handler.reset_mock()
        event = JobEnded(['test_rclcpp'], 0)
        extension((event, None))
        assert asan_handler.call_count == 1

        # Unknown event types will not be handled.
        asan_handler.reset_mock()
        extension(('unknown', None))
        assert asan_handler.call_count == 0


def test_event_handler_tsan_report():
    extension = TSanReportEventHandler()
    with patch(
        'colcon_sanitizer_reports.event_handlers.tsan_report.'
        'TSanReportEventHandler._handle'
    ) as tsan_handler:
        event = JobEnded(['test_communication'], 0)
        extension((event, None))
        assert tsan_handler.call_count == 1

        tsan_handler.reset_mock()
        event = JobEnded(['test_rclcpp'], 0)
        extension((event, None))
        assert tsan_handler.call_count == 1

        # Unknown event types will not be handled.
        tsan_handler.reset_mock()
        extension(('unknown', None))
        assert tsan_handler.call_count == 0
