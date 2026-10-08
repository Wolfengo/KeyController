#!/usr/bin/python3 -I
"""Optional root regression of pre-sleep dependency ordering, without sleeping.

Creates uniquely named disposable units with inert Python commands. It never
starts sleep.target, systemd-sleep, or any real SSH Keys service. Run only after
reviewing this file; ordinary package tests use the unprivileged graph suite.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
SYSTEMCTL = "/usr/bin/systemctl"
UNIT_DIR = Path("/run/systemd/system")
REAL_SLEEP = ["sleep.target", "systemd-suspend.service", "systemd-hibernate.service",
              "systemd-hybrid-sleep.service", "systemd-suspend-then-hibernate.service"]
ENV = {"PATH": "/usr/bin", "LC_ALL": "C", "SYSTEMD_PAGER": "cat"}


def run(*args, check=True, timeout=10):
    result = subprocess.run([SYSTEMCTL, *args], env=ENV, capture_output=True,
                            text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError("mock transaction command failed: " + " ".join(args)
                           + "\n" + result.stderr)
    return result


def wait_for(condition, message, timeout=4):
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() >= deadline:
            raise RuntimeError(message)
        time.sleep(0.025)


def main():
    if os.geteuid() != 0 or sys.argv[1:] != ["--run-disposable-units"]:
        raise SystemExit("Run as root with --run-disposable-units; never performs actual sleep")
    for unit in REAL_SLEEP:
        state = run("show", unit, "--property=ActiveState", "--value").stdout.strip()
        if state not in ("inactive", "failed"):
            raise SystemExit("A real sleep transaction is active; no fixture was installed")
    packaged = (ROOT / "packaging/ssh-keys-sleep.service").read_text()
    for required in ("Before=sleep.target", "StopWhenUnneeded=yes", "Type=oneshot",
                     "RemainAfterExit=yes"):
        if required not in packaged.splitlines():
            raise RuntimeError("Fixture must be reviewed against changed packaged unit: " + required)
    prefix = "ssh-keys-sleep-test-" + uuid.uuid4().hex
    names = [prefix + "-barrier.service", prefix + "-sleep.target", prefix + "-consumer.service"]
    barrier, target, consumer = names
    dependency_dir = UNIT_DIR / (target + ".requires")
    created = []
    with tempfile.TemporaryDirectory(prefix=prefix + "-", dir="/run") as directory:
        work = Path(directory)
        fixture = work / "fixture.py"
        fixture.write_text("""import pathlib,subprocess,sys,time
p=pathlib.Path(sys.argv[1]); action=sys.argv[2]
with (p/'events').open('a') as f: f.write(action+'\\n')
mode=(p/'mode').read_text()
if action=='prepare':
    if mode=='failure': sys.exit(1)
    if mode=='timeout': time.sleep(30)
    (p/'prepared').touch()
elif action=='consume':
    if not (p/'prepared').exists(): sys.exit(9)
    (p/'consumed').touch()
    if mode=='cancel': time.sleep(30)
elif action=='resume':
    probe=subprocess.check_output(['/usr/bin/systemctl','show','--property=ActiveState,Job',sys.argv[3],sys.argv[4]],text=True)
    (p/'resume-unit-state').write_text(probe)
    (p/'resumed').touch()
""")
        command = f"/usr/bin/python3 -I {fixture} {work}"
        units = {
            barrier: ("[Unit]\nDefaultDependencies=no\nStopWhenUnneeded=yes\n"
                      f"Before={target}\n[Service]\nType=oneshot\nRemainAfterExit=yes\n"
                      f"ExecStart={command} prepare\nExecStop={command} resume {target} {consumer}\n"
                      "TimeoutStartSec=1s\nTimeoutStopSec=1s\nLimitCORE=0\n"),
            target: "[Unit]\nDefaultDependencies=no\nStopWhenUnneeded=yes\nRefuseManualStart=yes\n",
            consumer: (f"[Unit]\nDefaultDependencies=no\nRequires={target}\nAfter={target}\n"
                       f"[Service]\nType=oneshot\nExecStart={command} consume\n"
                       "TimeoutStartSec=35s\nTimeoutStopSec=1s\nLimitCORE=0\n"),
        }
        try:
            for name, content in units.items():
                path = UNIT_DIR / name
                with path.open('x') as stream:
                    stream.write(content)
                created.append(path)
            dependency_dir.mkdir(mode=0o755)
            dependency = dependency_dir / barrier
            dependency.symlink_to(Path('..') / barrier)
            run('daemon-reload')
            requires = run('show', target, '--property=Requires', '--value').stdout.split()
            if barrier not in requires:
                raise RuntimeError('Package-style required link was not loaded')
            for mode in ('success', 'failure', 'timeout', 'cancel'):
                run('stop', *names, check=False)
                run('reset-failed', *names, check=False)
                for path in work.iterdir():
                    if path != fixture:
                        path.unlink()
                (work / 'mode').write_text(mode)
                if mode == 'cancel':
                    result = run('start', '--no-block', consumer)
                    wait_for(lambda: (work / 'consumed').exists(), 'Mock consumer did not start')
                    run('stop', consumer)
                else:
                    result = run('start', consumer, check=False)
                if mode in ('failure', 'timeout'):
                    if result.returncode == 0 or (work / 'consumed').exists():
                        raise RuntimeError('Failed pre-step did not block the mock sleep consumer')
                    if (work / 'resumed').exists():
                        raise RuntimeError('Failed preparation unexpectedly ran normal resume')
                else:
                    if result.returncode != 0:
                        raise RuntimeError('Successful mock preparation failed')
                    wait_for(lambda: (work / 'resumed').exists(), 'Resume did not run after mock sleep/cancel')
                    probe = (work / 'resume-unit-state').read_text()
                    for line in probe.splitlines():
                        if line.startswith('ActiveState=') and line not in ('ActiveState=inactive', 'ActiveState=failed'):
                            raise RuntimeError('Resume raced active sleep fixture: ' + probe)
                        if line.startswith('Job=') and line != 'Job=':
                            raise RuntimeError('Resume raced sleep fixture job: ' + probe)
                    events = (work / 'events').read_text().splitlines()
                    if events != ['prepare', 'consume', 'resume']:
                        raise RuntimeError('Unexpected mock ordering: ' + repr(events))
                print('PASS mock systemd sleep:', mode, flush=True)
        finally:
            # Stop only the exact random-prefix fixtures, never a wildcard.
            run('stop', *names, check=False)
            run('reset-failed', *names, check=False)
            if dependency_dir.exists():
                (dependency_dir / barrier).unlink(missing_ok=True)
                dependency_dir.rmdir()
            for path in reversed(created):
                path.unlink(missing_ok=True)
            run('daemon-reload')
        if any((UNIT_DIR / name).exists() for name in names) or dependency_dir.exists():
            raise RuntimeError('Disposable unit cleanup is incomplete')
    print('SSH_KEYS_SLEEP_SYSTEMD_RUNTIME_OK; no real sleep or key operation performed')


if __name__ == '__main__':
    main()
