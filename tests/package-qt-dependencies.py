"""A binary package must reject older Qt runtimes even when the SONAME matches."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RECIPE = ROOT / 'packaging/PKGBUILD'


class QtRuntimeDependenciesTests(unittest.TestCase):
    def dependencies(self, directory, versions):
        metadata = directory / 'qt-runtime-versions'
        if versions is not None:
            metadata.write_text(versions)
        result = subprocess.run(
            ['bash', '-c', 'source "$1"; '
             '_set_qt_runtime_dependencies "$2" || exit $?; '
             'printf "%s\\n" "${depends[@]}"',
             'qt-runtime-dependencies', str(RECIPE), str(metadata)],
            cwd=directory, capture_output=True, text=True,
        )
        return result

    def test_missing_or_malformed_versions_stop_packaging(self):
        for versions in (None, '', '6.12.0', '6.12.0 6.12.0 extra\n',
                         '6.12.0\n6.12.0\n', '6.12.0beta1 6.12.0\n',
                         '$(touch unexpected) 6.12.0\n'):
            with self.subTest(versions=versions), tempfile.TemporaryDirectory() as temporary:
                result = self.dependencies(Path(temporary), versions)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertEqual(result.stdout, '')
                self.assertFalse((Path(temporary) / 'unexpected').exists())

    def test_binary_metadata_uses_each_builds_qt_versions(self):
        for base, svg in (('6.11.2', '6.11.2'), ('6.12.0', '6.12.1')):
            with self.subTest(base=base), tempfile.TemporaryDirectory(
                    prefix='keycontroller-qt-package-') as temporary:
                directory = Path(temporary)
                (directory / 'qt-runtime-versions').write_text(f'{base} {svg}\n')
                # Keep the real dependency declaration and helper. The fixture
                # only substitutes an inert payload for compiling/installing code.
                (directory / 'PKGBUILD').write_text(
                    f'source {shlex.quote(str(RECIPE))}\n'
                    "pkgname=keycontroller-qt-metadata-test\n"
                    "source=()\nsha256sums=()\nmakedepends=()\n"
                    "install=\noptions=('!debug' '!strip')\n"
                    "unset -f build check\n"
                    "package() {\n"
                    '  _set_qt_runtime_dependencies "$srcdir/../qt-runtime-versions" || return 1\n'
                    '  install -Dm644 "$srcdir/../qt-runtime-versions" '
                    '"$pkgdir/usr/share/keycontroller/qt-runtime-versions"\n'
                    '}\n'
                )
                result = subprocess.run(
                    ['makepkg', '--nodeps', '--noconfirm', '--nosign'],
                    cwd=directory, capture_output=True, text=True,
                    env={key: value for key, value in os.environ.items()
                         if key not in ('PKGDEST', 'SRCDEST', 'BUILDDIR', 'SRCPKGDEST',
                                        'FAKEROOTKEY', 'LD_PRELOAD')},
                    timeout=90,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                packages = list(directory.glob('keycontroller-qt-metadata-test-*.pkg.tar*'))
                self.assertEqual(len(packages), 1)
                info = subprocess.check_output(
                    ['bsdtar', '-xOf', str(packages[0]), '.PKGINFO'], text=True,
                )
                dependencies = [line.removeprefix('depend = ') for line in info.splitlines()
                                if line.startswith('depend = ')]
                self.assertIn(f'qt6-base>={base}', dependencies)
                self.assertIn(f'qt6-svg>={svg}', dependencies)
                self.assertIn(f'qt6-wayland>={base}', dependencies)
                self.assertFalse({'qt6-base', 'qt6-svg', 'qt6-wayland'} & set(dependencies))
                self.assertIn('openssh>=10.5p1', dependencies)
                # Arch's actual version comparator must reject the failing
                # 6.12-on-6.11 pairing, and permit the matching local build.
                required = next(dep.split('>=')[1] for dep in dependencies
                                if dep.startswith('qt6-base>='))
                comparison = int(subprocess.check_output(
                    ['vercmp', '6.11.2-3', required], text=True,
                ))
                self.assertEqual(comparison >= 0, base == '6.11.2')


if __name__ == '__main__':
    unittest.main()
