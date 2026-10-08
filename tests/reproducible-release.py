#!/usr/bin/python3
"""Inspect the built release helper without executing it or accessing keys."""
from pathlib import Path
import sys


def verify(binary):
    data = binary.read_bytes()
    if b'/usr/lib/ssh-keys/harden.so' not in data:
        raise ValueError('Release helper has no installed hardening-library path')
    if b'/out/harden.so' in data:
        raise ValueError('Release helper contains a build-directory hardening-library path')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Usage: reproducible-release.py RELEASE_HELPER')
    try:
        verify(Path(sys.argv[1]))
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from None
    print('Release hardening-library path is package-owned; build-directory fallback is absent.')
