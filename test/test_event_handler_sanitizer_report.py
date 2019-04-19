# Copyright 2019 Open Source Robotics Foundation
# Licensed under the Apache License, Version 2.0


from colcon_core.event.job import JobEnded
from colcon_sanitizer_reports.event_handlers.sanitizer_report \
    import SanitizerReportEventHandler
from mock import patch


def test_event_handler_asan_report():
    extension = SanitizerReportEventHandler()
    with patch(
        'colcon_sanitizer_reports.event_handlers.sanitizer_report.'
        'SanitizerReportEventHandler._handle'
    ) as handler:
        event = JobEnded(['test_communication'], 0)
        extension((event, None))
        assert handler.call_count == 1

        handler.reset_mock()
        event = JobEnded(['test_rclcpp'], 0)
        extension((event, None))
        assert handler.call_count == 1

        # Unknown event types will not be handled.
        handler.reset_mock()
        extension(('unknown', None))
        assert handler.call_count == 0
