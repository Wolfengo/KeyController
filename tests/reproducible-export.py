"""Deterministic exports with synthetic metadata; never build/install packages."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
EXPORT = runpy.run_path(str(ROOT / 'scripts/package-source'))
EPOCH = 1_700_000_000


class ReproducibleExportTests(unittest.TestCase):
    def tree(self, base, timestamp):
        base.mkdir()
        (base / 'sub').mkdir()
        for path, content in [('.config', 'config'), ('sub/z', 'z'), ('sub/a', 'a'), ('readme', 'docs'), ('script', 'run')]:
            destination = base / path
            destination.write_text(content)
            destination.chmod(0o750 if path == 'script' else 0o600)
            os.utime(destination, (timestamp, timestamp))
        (base / '__pycache__').mkdir()
        (base / '__pycache__/ignored.pyc').write_bytes(b'not source')
        return base

    def test_different_paths_mtimes_and_owners_have_identical_archives(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            first = self.tree(base / 'short', 100)
            second = self.tree(base / 'different-long-build-path', 2_000_000_000)
            paths = ['sub', 'script', 'readme', '__pycache__', '.config']
            out_a, out_b = base / 'first.tar.gz', base / 'unrelated-name.tar.gz'
            write = EXPORT['write_archive']
            write(out_a, first, 'keycontroller', paths, EPOCH, include_epoch=True)
            original = tarfile.TarFile.gettarinfo
            def different_owner(instance, *args, **kwargs):
                item = original(instance, *args, **kwargs)
                item.uid, item.gid, item.uname, item.gname = 12345, 45678, 'different-user', 'different-group'
                item.pax_headers.update(atime='0.123', ctime='3.456')
                return item
            with patch.object(tarfile.TarFile, 'gettarinfo', different_owner):
                write(out_b, second, 'keycontroller', list(reversed(paths)), EPOCH, include_epoch=True)
            self.assertEqual(out_a.read_bytes(), out_b.read_bytes())
            header = out_a.read_bytes()[:10]
            self.assertEqual(struct.unpack('<I', header[4:8])[0], EPOCH)
            self.assertFalse(header[3] & 8, 'gzip must not carry the output filename')
            with tarfile.open(out_a) as archive:
                members = archive.getmembers()
                self.assertEqual([item.name for item in members], sorted(item.name for item in members))
                for item in members:
                    self.assertEqual((item.uid, item.gid, item.uname, item.gname, item.mtime), (0, 0, '', '', EPOCH))
                    self.assertEqual(item.pax_headers, {})
                self.assertEqual(archive.getmember('keycontroller/script').mode, 0o755)
                self.assertEqual(archive.getmember('keycontroller/readme').mode, 0o644)
                self.assertEqual(archive.extractfile('keycontroller/.source-date-epoch').read(), f'{EPOCH}\n'.encode())
                self.assertFalse(any('__pycache__' in item.name for item in members))

    def test_symlinks_and_special_files_are_not_exported(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE):
            with self.subTest(kind=kind):
                info = tarfile.TarInfo('source/unsafe')
                info.type = kind
                with self.assertRaisesRegex(ValueError, 'Unsupported source file type'):
                    EXPORT['source_file'](info, EPOCH)

    def test_epoch_is_explicit_or_preserved_and_invalid_values_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.source-date-epoch').write_text(f'{EPOCH}\n')
            with patch.dict(os.environ, {}, clear=True):
                self.assertEqual(EXPORT['source_epoch'](root), EPOCH)
            for invalid in ('-1', '', '1.5', '4294967296', ' 123 ', '$(date)'):
                with self.subTest(invalid=invalid), patch.dict(os.environ, SOURCE_DATE_EPOCH=invalid):
                    with self.assertRaises(ValueError):
                        EXPORT['source_epoch'](root)
            with patch.dict(os.environ, SOURCE_DATE_EPOCH='123'):
                self.assertEqual(EXPORT['source_epoch'](root), 123)
            (root / '.source-date-epoch').unlink()
            with patch.dict(os.environ, {}, clear=True), patch.object(subprocess, 'run', side_effect=OSError):
                with self.assertRaisesRegex(ValueError, 'Set SOURCE_DATE_EPOCH'):
                    EXPORT['source_epoch'](root)

    def test_complete_exports_match_and_unpacked_source_reexports_without_git(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            roots = [directory / 'first', directory / 'longer-second-location']
            environment = dict(os.environ, SOURCE_DATE_EPOCH=str(EPOCH))
            for index, root in enumerate(roots):
                root.mkdir()
                for name in EXPORT['SOURCE_PATHS']:
                    source, destination = ROOT / name, root / name
                    if source.is_dir():
                        shutil.copytree(source, destination, ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '*.pyo'))
                    else:
                        shutil.copyfile(source, destination)
                        destination.chmod(source.stat().st_mode & 0o777)
                for path in root.rglob('*'):
                    os.utime(path, (100 + index, 100 + index))
                subprocess.run([sys.executable, str(root / 'scripts/package-source')], env=environment,
                               check=True, capture_output=True, text=True)
            files = sorted(path.name for path in (roots[0] / 'dist').iterdir())
            self.assertEqual(files, sorted(path.name for path in (roots[1] / 'dist').iterdir()))
            for name in files:
                self.assertEqual((roots[0] / 'dist' / name).read_bytes(), (roots[1] / 'dist' / name).read_bytes(), name)
            source = next(path for path in (roots[0] / 'dist').glob('keycontroller-*.tar.gz') if '-plugin-' not in path.name)
            unpacked = directory / 'unpacked'
            with tarfile.open(source) as archive:
                archive.extractall(unpacked, filter='data')
            root = next(unpacked.iterdir())
            environment.pop('SOURCE_DATE_EPOCH')
            subprocess.run([sys.executable, str(root / 'scripts/package-source')], env=environment,
                           check=True, capture_output=True, text=True)
            self.assertEqual(hashlib.sha256(source.read_bytes()).digest(),
                             hashlib.sha256((root / 'dist' / source.name).read_bytes()).digest())


if __name__ == '__main__':
    unittest.main()
