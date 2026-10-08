"""Test old/new private AT-SPI activation contracts without desktop access."""
from pathlib import Path
import runpy
import subprocess
import unittest
from unittest.mock import patch

PREFLIGHT = runpy.run_path(str(Path(__file__).with_name('prompt-accessibility.py')))


def interface(properties):
    return '<node><interface name="org.a11y.Status">' + properties + '</interface></node>'


def property_xml(name, kind='b', access='readwrite'):
    return f'<property name="{name}" type="{kind}" access="{access}"/>'


class AccessibilityPreflightTests(unittest.TestCase):
    def test_legacy_and_current_activation_require_successful_set_and_readback(self):
        for name, properties in (
                ('ScreenReaderEnabled', property_xml('IsEnabled') + property_xml('ScreenReaderEnabled')),
                ('IsEnabled', property_xml('IsEnabled'))):
            with self.subTest(name=name):
                replies = [interface(properties), '()', '(<true>,)']
                def run(command, **kwargs):
                    self.assertEqual(kwargs['env'], {'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/disposable/bus'})
                    return subprocess.CompletedProcess(command, 0, replies.pop(0), '')
                with patch.object(subprocess, 'run', side_effect=run) as execute:
                    PREFLIGHT['enable_accessibility']({'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/disposable/bus'})
                self.assertEqual(execute.call_count, 3)
                self.assertIn('org.freedesktop.DBus.Properties.Set', execute.call_args_list[1].args[0])
                self.assertEqual(execute.call_args_list[1].args[0][-2:], [name, '<true>'])
                self.assertIn('org.freedesktop.DBus.Properties.Get', execute.call_args_list[2].args[0])

    def test_missing_malformed_readonly_or_duplicate_properties_fail_closed(self):
        for document in ('<node/>', interface(''), interface(property_xml('IsEnabled', 's')),
                         interface(property_xml('IsEnabled', access='read')),
                         interface(property_xml('IsEnabled') * 2),
                         interface(property_xml('ScreenReaderEnabled', access='read') + property_xml('IsEnabled'))):
            with self.subTest(document=document), self.assertRaises(RuntimeError):
                PREFLIGHT['status_property'](document)

    def test_false_readback_and_bus_errors_never_skip_the_accessibility_check(self):
        calls = [subprocess.CompletedProcess([], 0, value, '') for value in
                 (interface(property_xml('IsEnabled')), '()', '(<false>,)')]
        with patch.object(subprocess, 'run', side_effect=calls), self.assertRaisesRegex(RuntimeError, 'did not become true'):
            PREFLIGHT['enable_accessibility']({})
        failure = subprocess.CompletedProcess([], 1, '', 'Unknown property ScreenReaderEnabled\n')
        with patch.object(subprocess, 'run', return_value=failure), self.assertRaisesRegex(RuntimeError, 'Unknown property ScreenReaderEnabled'):
            PREFLIGHT['preflight_dbus']({}, 'call', '--method', 'org.a11y.Bus.GetAddress')


if __name__ == '__main__':
    unittest.main()
