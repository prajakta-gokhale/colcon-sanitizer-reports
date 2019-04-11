import unittest

from colcon_sanitizer_reports.report import Report


class TestReport(unittest.TestCase):

    def test_report_creates_section_for_error(self) -> None:
        report = Report([
            '2: ==17726==ERROR: LeakSanitizer: detected memory leaks',
            '2: ',
            '2: SUMMARY: AddressSanitizer: 96 byte(s) leaked in 3 allocation(s).',
        ])
        self.assertEqual(len(report.sections), 1)

    def test_report_creates_two_sections_for_two_errors(self) -> None:
        report = Report([
            '2: ==17726==ERROR: LeakSanitizer: detected memory leaks',
            '2: ',
            '2: SUMMARY: AddressSanitizer: 96 byte(s) leaked in 3 allocation(s).',
            '27: [test_requester-2] WARNING: ThreadSanitizer: lock-order-inversion (potential '
            'deadlock) (pid=19699)',
            '27: [test_requester-2] ',
            '27: [test_requester-2] SUMMARY: ThreadSanitizer: lock-order-inversion (potential '
            'deadlock) (/usr/lib/x86_64-linux-gnu/libtsan.so.0+0x3faeb) in '
            '__interceptor_pthread_mutex_lock'
        ])
        self.assertEqual(len(report.sections), 2)

    def test_report_creates_two_different_sections_by_name_for_two_different_errors(self) -> None:
        report = Report([
            '2: ==17726==ERROR: LeakSanitizer: detected memory leaks',
            '2: ',
            '2: SUMMARY: AddressSanitizer: 96 byte(s) leaked in 3 allocation(s).',
            '27: [test_requester-2] WARNING: ThreadSanitizer: lock-order-inversion (potential '
            'deadlock) (pid=19699)',
            '27: [test_requester-2] ',
            '27: [test_requester-2] SUMMARY: ThreadSanitizer: lock-order-inversion (potential '
            'deadlock) (/usr/lib/x86_64-linux-gnu/libtsan.so.0+0x3faeb) in '
            '__interceptor_pthread_mutex_lock'
        ])
        self.assertEqual(len(report.sections_by_name), 2)

    def test_report_detects_error_name(self) -> None:
        report = Report([
            '2: ==17726==ERROR: LeakSanitizer: detected memory leaks',
            '2: ',
            '2: SUMMARY: AddressSanitizer: 96 byte(s) leaked in 3 allocation(s).',
        ])

        self.assertEqual(report.sections[0].name, 'detected memory leaks')

    def test_report_detects_error_name_with_trailing_info(self) -> None:
        report = Report([
            '27: [test_requester-2] WARNING: ThreadSanitizer: lock-order-inversion (potential '
            'deadlock) (pid=19699)',
            '27: [test_requester-2] ',
            '27: [test_requester-2] SUMMARY: ThreadSanitizer: lock-order-inversion (potential '
            'deadlock) (/usr/lib/x86_64-linux-gnu/libtsan.so.0+0x3faeb) in '
            '__interceptor_pthread_mutex_lock'
        ])
        self.assertEqual(report.sections[0].name, 'lock-order-inversion')

    def test_report_has_header_subsection(self) -> None:
        report = Report([
            '27: [test_requester-2] WARNING: ThreadSanitizer: lock-order-inversion (potential '
            'deadlock) (pid=19699)',
            '27: [test_requester-2] ',
            '27: [test_requester-2] SUMMARY: ThreadSanitizer: lock-order-inversion (potential '
            'deadlock) (/usr/lib/x86_64-linux-gnu/libtsan.so.0+0x3faeb) in '
            '__interceptor_pthread_mutex_lock'
        ])
        self.assertIsNotNone(report.sections[0].sub_sections)

    def test_report_has_footer_subsection(self) -> None:
        report = Report([
            '27: [test_requester-2] WARNING: ThreadSanitizer: lock-order-inversion (potential '
            'deadlock) (pid=19699)',
            '27: [test_requester-2] ',
            '27: [test_requester-2] SUMMARY: ThreadSanitizer: lock-order-inversion (potential '
            'deadlock) (/usr/lib/x86_64-linux-gnu/libtsan.so.0+0x3faeb) in '
            '__interceptor_pthread_mutex_lock'
        ])
        self.assertIsNotNone(report.sections[0].sub_sections)

    def test_report_prefix_is_stripped(self) -> None:
        report = Report([
            '27: [test_requester-2] WARNING: ThreadSanitizer: lock-order-inversion (potential '
            'deadlock) (pid=19699)',
            '27: [test_requester-2] ',
            '27: [test_requester-2] SUMMARY: ThreadSanitizer: lock-order-inversion (potential '
            'deadlock) (/usr/lib/x86_64-linux-gnu/libtsan.so.0+0x3faeb) in '
            '__interceptor_pthread_mutex_lock'
        ])
        self.assertEqual(
            report.sections[0].sub_sections[0].lines[0],
            'WARNING: ThreadSanitizer: lock-order-inversion (potential deadlock) (pid=19699)'
        )
        self.assertEqual(
            report.sections[0].sub_sections[0].lines[1],
            'SUMMARY: ThreadSanitizer: lock-order-inversion (potential deadlock) '
            '(/usr/lib/x86_64-linux-gnu/libtsan.so.0+0x3faeb) in __interceptor_pthread_mutex_lock'
        )

    def test_report_body_section_hex_and_standalone_decimal_are_masked(self) -> None:
        report = Report([
            '1: == 17623 == ERROR: LeakSanitizer: detected memory leaks',
            '1: ',
            '1: Direct leak of 48000 byte(s) in 1 object(s) allocated from:',
            '1:  #0 0x7eff1e673d38 in __interceptor_calloc (/usr/lib/x86_64-linux-gnu/libasan.so.'
            '4+0xded38)',
            '1:  #1 0x7eff1ded9ad7 in rosidl_generator_c__String__Sequence__init '
            '/home/jenkins-agent/workspace/nightly_linux_address_sanitizer/ws/src/ros2/rosidl/'
            'rosidl_generator_c/src/string_functions.c:114',
            '1:  #2 0x556cce247375 in void get_message<test_msgs__msg__DynamicArrayPrimitives>('
            'test_msgs__msg__DynamicArrayPrimitives*, unsigned long) /home/jenkins-agent/workspace/'
            'nightly_linux_address_sanitizer/ws/src/ros2/system_tests/test_communication/test/'
            'test_messages_c.cpp:724',
            '1:  #3 0x556cce24823b in void verify_message<test_msgs__msg__DynamicArrayPrimitives>('
            'test_msgs__msg__DynamicArrayPrimitives&, unsigned long) /home/jenkins-agent/workspace/'
            'nightly_linux_address_sanitizer/ws/src/ros2/system_tests/test_communication/test/'
            'test_messages_c.cpp:773',
            '1:  #4 0x556cce27a173 in void TestMessagesFixture::test_message_type<'
            'test_msgs__msg__DynamicArrayPrimitives>(char const*, rosidl_message_type_support_t '
            'const*, rcl_context_t*) (/home/jenkins-agent/workspace/'
            'nightly_linux_address_sanitizer/ws/build/test_communication/'
            'test_messages_c__rmw_connext_cpp+0x56173)',
            '1:  #5 0x556cce24ab26 in TestMessagesFixture_test_dynamicarrayprimitives_Test::'
            'TestBody() /home/jenkins-agent/workspace/nightly_linux_address_sanitizer/ws/src/ros2/'
            'system_tests/test_communication/test/test_messages_c.cpp:836',
            '1:  #6 0x556cce2ff1b9 in void testing::internal::'
            'HandleSehExceptionsInMethodIfSupported<testing::Test, void>(testing::Test*, void ('
            'testing::Test::*)(), char const*) /home/jenkins-agent/workspace/'
            'nightly_linux_address_sanitizer/ws/install/gtest_vendor/src/gtest_vendor/./src/'
            'gtest.cc:2395',
            '1:  #7 0x556cce2f22d7 in void testing::internal::HandleExceptionsInMethodIfSupported<'
            'testing::Test, void>(testing::Test*, void (testing::Test::*)(), char const*) /home/'
            'jenkins-agent/workspace/nightly_linux_address_sanitizer/ws/install/gtest_vendor/src/'
            'gtest_vendor/./src/gtest.cc:2431',
            '1:  #8 0x556cce2ac37f in testing::Test::Run() /home/jenkins-agent/workspace/'
            'nightly_linux_address_sanitizer/ws/install/gtest_vendor/src/gtest_vendor/./src/'
            'gtest.cc:2467',
            '1:  #9 0x556cce2ad789 in testing::TestInfo::Run() /home/jenkins-agent/workspace/'
            'nightly_linux_address_sanitizer/ws/install/gtest_vendor/src/gtest_vendor/./src/'
            'gtest.cc:2645',
            '1:  #10 0x556cce2ae306 in testing::TestCase::Run() /home/jenkins-agent/workspace/'
            'nightly_linux_address_sanitizer/ws/install/gtest_vendor/src/gtest_vendor/./src/'
            'gtest.cc:2763',
            '1:  #11 0x556cce2bf518 in testing::internal::UnitTestImpl::RunAllTests() /home/'
            'jenkins-agent/workspace/nightly_linux_address_sanitizer/ws/install/gtest_vendor/src/'
            'gtest_vendor/./src/gtest.cc:4658',
            '1:  #12 0x556cce301c72 in bool testing::internal::'
            'HandleSehExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool>('
            'testing::internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), char '
            'const*) /home/jenkins-agent/workspace/nightly_linux_address_sanitizer/ws/install/'
            'gtest_vendor/src/gtest_vendor/./src/gtest.cc:2395',
            '1:  #13 0x556cce2f44c6 in bool testing::internal::'
            'HandleExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool>(testing::'
            'internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), char const*) /'
            'home/jenkins-agent/workspace/nightly_linux_address_sanitizer/ws/install/gtest_vendor/'
            'src/gtest_vendor/./src/gtest.cc:2431',
            '1:  #14 0x556cce2bc4c2 in testing::UnitTest::Run() /home/jenkins-agent/workspace/'
            'nightly_linux_address_sanitizer/ws/install/gtest_vendor/src/gtest_vendor/./src/'
            'gtest.cc:4270',
            '1:  #15 0x556cce29a1a2 in RUN_ALL_TESTS() /home/jenkins-agent/workspace/'
            'nightly_linux_address_sanitizer/ws/install/gtest_vendor/src/gtest_vendor/include/'
            'gtest/gtest.h:2243',
            '1:  #16 0x556cce29a0e8 in main /home/jenkins-agent/workspace/'
            'nightly_linux_address_sanitizer/ws/install/gtest_vendor/src/gtest_vendor/src/'
            'gtest_main.cc:37',
            '1:  #17 0x7eff1cefab96 in __libc_start_main (/lib/x86_64-linux-gnu/'
            'libc.so.6+0x21b96)',
            '1: ',
            '1: SUMMARY: AddressSanitizer: 634603 byte(s) leaked in 6792 allocation(s).'
        ])

        self.assertEqual(
            report.sections[0].sub_sections[0].masked_lines[0],
            (
                '== X == ERROR: LeakSanitizer: detected memory leaks'
            )
        )
        self.assertEqual(
            report.sections[0].sub_sections[0].masked_lines,
            (
                '== X == ERROR: LeakSanitizer: detected memory leaks',
                'Direct leak of X byte(s) in X object(s) allocated from:',
                ' #X 0xX in __interceptor_calloc (/usr/lib/x86_64-linux-gnu/libasan.so.'
                '4+0xX)',
                ' #X 0xX in rosidl_generator_c__String__Sequence__init '
                '/home/jenkins-agent/workspace/nightly_linux_address_sanitizer/ws/src/ros2/rosidl/'
                'rosidl_generator_c/src/string_functions.c:114',
                ' #X 0xX in void get_message<test_msgs__msg__DynamicArrayPrimitives>('
                'test_msgs__msg__DynamicArrayPrimitives*, unsigned long) /home/jenkins-agent/'
                'workspace/nightly_linux_address_sanitizer/ws/src/ros2/system_tests/'
                'test_communication/test/test_messages_c.cpp:724',
                ' #X 0xX in void verify_message<'
                'test_msgs__msg__DynamicArrayPrimitives>(test_msgs__msg__DynamicArrayPrimitives&, '
                'unsigned long) /home/jenkins-agent/workspace/nightly_linux_address_sanitizer/ws/'
                'src/ros2/system_tests/test_communication/test/test_messages_c.cpp:773',
                ' #X 0xX in void TestMessagesFixture::test_message_type<'
                'test_msgs__msg__DynamicArrayPrimitives>(char const*, '
                'rosidl_message_type_support_t const*, rcl_context_t*) (/home/jenkins-agent/'
                'workspace/nightly_linux_address_sanitizer/ws/build/test_communication/'
                'test_messages_c__rmw_connext_cpp+0xX)',
                ' #X 0xX in TestMessagesFixture_test_dynamicarrayprimitives_Test::'
                'TestBody() /home/jenkins-agent/workspace/nightly_linux_address_sanitizer/ws/src/'
                'ros2/system_tests/test_communication/test/test_messages_c.cpp:836',
                ' #X 0xX in void testing::internal::'
                'HandleSehExceptionsInMethodIfSupported<testing::Test, void>(testing::Test*, void ('
                'testing::Test::*)(), char const*) /home/jenkins-agent/workspace/'
                'nightly_linux_address_sanitizer/ws/install/gtest_vendor/src/gtest_vendor/./src/'
                'gtest.cc:2395',
                ' #X 0xX in void testing::internal::HandleExceptionsInMethodIfSupported'
                '<testing::Test, void>(testing::Test*, void (testing::Test::*)(), char const*) '
                '/home/jenkins-agent/workspace/nightly_linux_address_sanitizer/ws/install/'
                'gtest_vendor/src/gtest_vendor/./src/gtest.cc:2431',
                ' #X 0xX in testing::Test::Run() /home/jenkins-agent/workspace/'
                'nightly_linux_address_sanitizer/ws/install/gtest_vendor/src/gtest_vendor/./src/'
                'gtest.cc:2467',
                ' #X 0xX in testing::TestInfo::Run() /home/jenkins-agent/workspace/'
                'nightly_linux_address_sanitizer/ws/install/gtest_vendor/src/gtest_vendor/./src/'
                'gtest.cc:2645',
                ' #X 0xX in testing::TestCase::Run() /home/jenkins-agent/workspace/'
                'nightly_linux_address_sanitizer/ws/install/gtest_vendor/src/gtest_vendor/./src/'
                'gtest.cc:2763',
                ' #X 0xX in testing::internal::UnitTestImpl::RunAllTests() /home/'
                'jenkins-agent/workspace/nightly_linux_address_sanitizer/ws/install/gtest_vendor/'
                'src/gtest_vendor/./src/gtest.cc:4658',
                ' #X 0xX in bool testing::internal::'
                'HandleSehExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool>('
                'testing::internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), '
                'char const*) /home/jenkins-agent/workspace/nightly_linux_address_sanitizer/ws/'
                'install/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2395',
                ' #X 0xX in bool testing::internal::'
                'HandleExceptionsInMethodIfSupported<testing::internal::UnitTestImpl, bool>('
                'testing::internal::UnitTestImpl*, bool (testing::internal::UnitTestImpl::*)(), '
                'char const*) /home/jenkins-agent/workspace/nightly_linux_address_sanitizer/ws/'
                'install/gtest_vendor/src/gtest_vendor/./src/gtest.cc:2431',
                ' #X 0xX in testing::UnitTest::Run() /home/jenkins-agent/workspace/'
                'nightly_linux_address_sanitizer/ws/install/gtest_vendor/src/gtest_vendor/./src/'
                'gtest.cc:4270',
                ' #X 0xX in RUN_ALL_TESTS() /home/jenkins-agent/workspace/'
                'nightly_linux_address_sanitizer/ws/install/gtest_vendor/src/gtest_vendor/include/'
                'gtest/gtest.h:2243',
                ' #X 0xX in main /home/jenkins-agent/workspace/'
                'nightly_linux_address_sanitizer/ws/install/gtest_vendor/src/gtest_vendor/src/'
                'gtest_main.cc:37',
                ' #X 0xX in __libc_start_main (/lib/x86_64-linux-gnu/'
                'libc.so.6+0xX)',
                'SUMMARY: AddressSanitizer: X byte(s) leaked in X allocation(s).',
            )
        )
        self.assertEqual(
            report.sections[0].sub_sections.masked_lines[-1],
            ('SUMMARY: AddressSanitizer: X byte(s) leaked in X allocation(s).',)
        )

    def test_section_lines_gives_correct_lines(self) -> None:
        report = Report([
            '1: == 17623 == ERROR: LeakSanitizer: detected memory leaks',
            '1: ',
            '1: Direct leak of 48000 byte(s) in 1 object(s) allocated from:',
            '1: ',
            '1: SUMMARY: AddressSanitizer: 634603 byte(s) leaked in 6792 allocation(s).'
        ])

        self.assertEqual(
            report.sections[0].lines,
            (
                '== 17623 == ERROR: LeakSanitizer: detected memory leaks',
                '',
                'Direct leak of 48000 byte(s) in 1 object(s) allocated from:',
                '',
                'SUMMARY: AddressSanitizer: 634603 byte(s) leaked in 6792 allocation(s).'
            )
        )


if __name__ == '__main__':
    unittest.main(verbosity=2)
