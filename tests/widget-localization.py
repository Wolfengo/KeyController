#!/usr/bin/python3
"""Check the complete widget translation catalog without a graphical session."""
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent.parent

class WidgetLocalizationTests(unittest.TestCase):
    def test_all_source_strings_have_english(self):
        module = (ROOT / 'plugin/KeyLocale.js').read_text()
        english = json.loads(module.split('var english = ', 1)[1].split('\n\nfunction text', 1)[0])
        sources = set()
        for name in ('Panel.qml', 'KeyDuration.qml', 'KeyDependencies.qml'):
            source = (ROOT / 'plugin' / name).read_text()
            for match in re.finditer(r'"(?:[^"\\]|\\.)*"', source):
                value = json.loads(match.group())
                if not re.search('[А-Яа-яЁё]', value):
                    continue
                self.assertEqual(source[max(0, match.start() - 7):match.start()], 'root.t(', (name, value))
                self.assertIn(value, english, (name, value))
                sources.add(value)
        self.assertGreater(len(sources), 100)
        for source, translated in english.items():
            self.assertTrue(translated.strip(), source)
            self.assertIsNone(re.search('[А-Яа-яЁё]', translated), source)

    def test_widget_does_not_send_localized_request_reason(self):
        source = (ROOT / 'plugin/Panel.qml').read_text()
        self.assertIn('interactive: true, reason: ""', source)

if __name__ == '__main__':
    unittest.main()
