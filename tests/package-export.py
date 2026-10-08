"""The repository and the standalone widget load the same code and assets."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PluginExportTests(unittest.TestCase):
    def test_repository_and_packaged_entry_points_resolve(self):
        with tempfile.TemporaryDirectory(prefix='keycontroller-export-test-') as temporary:
            destination = Path(temporary) / 'widget'
            subprocess.run([sys.executable, str(ROOT / 'scripts/package-plugin'),
                            str(destination)], check=True)
            canonical = json.loads((ROOT / 'manifest.json').read_text())
            packaged = json.loads((destination / 'manifest.json').read_text())
            for name, entry in canonical['entryPoints'].items():
                self.assertEqual((ROOT / entry).read_bytes(),
                                 (destination / packaged['entryPoints'][name]).read_bytes())
            packaged['entryPoints'] = canonical['entryPoints']
            self.assertEqual(canonical, packaged)
            for file in ('LICENSE', 'icons/LICENSE.material-icons',
                         'icons/THIRD_PARTY_NOTICES.md', 'icons/mark.svg',
                         'icons/bar.svg', 'KeyLocale.js', 'dependencies', 'dependencies.py'):
                self.assertTrue((destination / file).is_file(), file)
            for file in (ROOT / 'plugin').rglob('*'):
                if file.is_file() and '__pycache__' not in file.parts and file.suffix not in ('.pyc', '.pyo'):
                    self.assertEqual(file.read_bytes(),
                                     (destination / file.relative_to(ROOT / 'plugin')).read_bytes())
            self.assertFalse(list(destination.rglob('__pycache__')))
            validator = shutil.which('omarchy-plugin-validate')
            if validator:
                for directory in (ROOT, destination):
                    subprocess.run([validator, str(directory)], check=True)

    def test_existing_directory_is_not_overwritten(self):
        with tempfile.TemporaryDirectory(prefix='keycontroller-export-test-') as temporary:
            destination = Path(temporary)
            marker = destination / 'manifest.json'
            marker.write_text('existing content')
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/package-plugin'),
                                     str(destination)], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(marker.read_text(), 'existing content')


if __name__ == '__main__':
    unittest.main()
