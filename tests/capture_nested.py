#!/usr/bin/python3
"""Manual synthetic compositor-capture check; never part of package checks.

Requires explicit --run-visible-nested: a temporary original Hyprland window
appears in the desktop. All captures connect to the isolated CHILD compositor,
not the real display. No keys, password prompt, clipboard or authentication.
--startup-race maps immediately to exercise the known first-output resize gap.
"""
import argparse
import json
import os
from pathlib import Path
import resource
import shlex
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def compile_fixtures(output):
    flags = shlex.split(subprocess.check_output(['pkg-config', '--cflags', '--libs', 'Qt6Widgets'], text=True))
    subprocess.run(['c++', '-std=c++17', '-fPIC', str(ROOT / 'tests/capture-layer.cpp'), '-o', str(output / 'layer-fixture'), *flags, '-lLayerShellQtInterface'], check=True)
    protocols = output / 'capture-protocols'
    protocols.mkdir(exist_ok=True)
    specifications = {
        'imagecopy': 'staging/ext-image-copy-capture/ext-image-copy-capture-v1.xml',
        'imagesource': 'staging/ext-image-capture-source/ext-image-capture-source-v1.xml',
        'toplevel': 'staging/ext-foreign-toplevel-list/ext-foreign-toplevel-list-v1.xml',
    }
    for name, relative in specifications.items():
        source = '/usr/share/wayland-protocols/' + relative
        for mode, suffix in [('client-header', '.h'), ('private-code', '.c')]:
            subprocess.run(['wayland-scanner', mode, source, str(protocols / (name + suffix))], check=True)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Wno-unused-parameter', '-I', str(output), str(ROOT / 'tests/capture-imagecopy.c'), *(str(protocols / (name + '.c')) for name in specifications), '-lwayland-client', '-o', str(output / 'imagecopy')], check=True)


def terminate(process, group=False):
    if process is None or process.poll() is not None:
        return
    if group:
        os.killpg(process.pid, signal.SIGTERM)
    else:
        process.terminate()
    try:
        process.wait(timeout=4)
    except subprocess.TimeoutExpired:
        if group:
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
        process.wait(timeout=4)


def run(output, startup_race):
    mode = 'startup-race' if startup_race else 'stable'
    parent_display = Path(os.environ['WAYLAND_DISPLAY'])
    if not parent_display.is_absolute():
        parent_display = Path(os.environ['XDG_RUNTIME_DIR']) / parent_display
    if not parent_display.is_socket():
        raise RuntimeError('An active parent Wayland socket is required')
    result = {
        'binary': subprocess.check_output(['/usr/bin/Hyprland', '--version'], text=True).splitlines()[0],
        'mode': mode,
        'capture_target': 'isolated nested child compositor with synthetic layers only',
        'rule': str(ROOT / 'packaging/keycontroller-hyprland.lua'),
        'frames': [],
    }
    with tempfile.TemporaryDirectory(prefix='kc-') as directory:
        directory = Path(directory)
        runtime = directory / 'runtime'
        runtime.mkdir(mode=0o700)
        (directory / 'home').mkdir()
        config = directory / 'hyprland.lua'
        config_text = ('hl.monitor({output="", mode="640x480@60", position="0x0", scale=SCALE})\n'
                       'hl.config({xwayland={enabled=false},debug={enable_stdout_logs=true},misc={disable_hyprland_logo=true,disable_splash_rendering=true}})\n'
                       'dofile(' + json.dumps(str(ROOT / 'packaging/keycontroller-hyprland.lua')) + ')\n')
        config.write_text(config_text.replace('SCALE', '1'))
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(directory / 'home'), 'XDG_RUNTIME_DIR': str(runtime),
               'XDG_CONFIG_HOME': str(directory / 'config'), 'XDG_DATA_HOME': str(directory / 'data'),
               'XDG_CACHE_HOME': str(directory / 'cache'), 'LANG': 'C.UTF-8', 'WAYLAND_DISPLAY': str(parent_display),
               # Never attempt to take a real DRM/KMS output from the parent.
               'AQ_DRM_DEVICES': '/dev/null', 'XDG_SESSION_TYPE': 'wayland'}
        fixture = compositor = None
        with (output / (mode + '.log')).open('w') as log:
            try:
                compositor = subprocess.Popen(['dbus-run-session', '--', '/usr/bin/Hyprland', '--config', str(config)], env=env, stdout=log, stderr=log, start_new_session=True)
                for _ in range(100):
                    instances = list((runtime / 'hypr').glob('*/.socket.sock'))
                    wayland = [path for path in runtime.glob('wayland-*') if path.is_socket()]
                    if instances and wayland:
                        break
                    if compositor.poll() is not None:
                        raise RuntimeError('Nested compositor exited; see its synthetic test log')
                    time.sleep(.1)
                if len(instances) != 1 or len(wayland) != 1:
                    raise RuntimeError('Expected exactly one private compositor socket')
                env.update(HYPRLAND_INSTANCE_SIGNATURE=instances[0].parent.name, WAYLAND_DISPLAY=wayland[0].name,
                           QT_QPA_PLATFORM='wayland', QT_WAYLAND_SHELL_INTEGRATION='layer-shell')

                def ctl(*arguments):
                    return subprocess.check_output(['hyprctl', *arguments], env=env, text=True, timeout=5)

                if ctl('configerrors').strip():
                    raise RuntimeError('Synthetic compositor config errors')
                monitors = json.loads(ctl('-j', 'monitors'))
                if len(monitors) != 1 or not monitors[0]['name'].startswith('WAYLAND-'):
                    raise RuntimeError('Expected exactly one nested Wayland output')
                output_name = monitors[0]['name']
                result['initial_monitor'] = {key: monitors[0][key] for key in ('name', 'width', 'height', 'scale')}
                # This separates stable-output coverage from the explicit startup
                # race test. It is NOT a production mitigation or protection delay.
                if not startup_race:
                    time.sleep(.75)
                fixture = subprocess.Popen([str(output / 'layer-fixture'), str(directory / 'close')], env=env, stdout=log, stderr=log)

                def layers(expected_protected):
                    state = json.loads(ctl('-j', 'layers'))
                    found = [item for monitor in state.values() for items in monitor.get('levels', {}).values() for item in items]
                    expected = {'keycontroller-capture-control'}
                    if expected_protected:
                        expected.add('keycontroller-prompt')
                    if {item['namespace'] for item in found} != expected or any(item['pid'] != fixture.pid for item in found):
                        raise RuntimeError('Synthetic layer/PID mapping changed')
                    return [{key: item[key] for key in ('namespace', 'pid', 'x', 'y', 'w', 'h')} for item in found]

                for attempt in range(100):
                    try:
                        result['initial_layers'] = layers(True)
                        break
                    except RuntimeError:
                        if fixture.poll() is not None or attempt == 99:
                            raise
                        time.sleep(.02)

                def capture(phase, protocol, protected=True):
                    before = layers(protected)
                    if protocol == 'wlr-screencopy':
                        target = output / f'{mode}-{phase}.png'
                        subprocess.run(['grim', '-o', output_name, str(target)], env=env, check=True, stdout=log, stderr=log, timeout=5)
                        raw = subprocess.check_output(['magick', str(target), '-depth', '8', 'RGB:-'], timeout=5)
                        colors = list(zip(raw[::3], raw[1::3], raw[2::3]))
                        frame = {'green_private_pixels': sum(g > r + 30 and g > b + 30 for r, g, b in colors),
                                 'pink_control_pixels': sum(r > g + 30 and b > g + 30 for r, g, b in colors)}
                    else:
                        frame = json.loads(subprocess.check_output([str(output / 'imagecopy')], env=env, text=True, timeout=6))
                    frame.update(phase=phase, protocol=protocol, layers_before=before, layers_after=layers(protected))
                    result['frames'].append(frame)
                    return frame

                capture('earliest', 'wlr-screencopy')
                capture('earliest', 'ext-imagecopy')
                time.sleep(.5)
                capture('mapped', 'wlr-screencopy')
                capture('mapped', 'ext-imagecopy')
                result['resizes'] = []
                for scale in (2, 1):
                    config.write_text(config_text.replace('SCALE', str(scale)))
                    ctl('reload')
                    actual = json.loads(ctl('-j', 'monitors'))[0]
                    result['resizes'].append({key: actual[key] for key in ('width', 'height', 'scale')})
                    if actual['scale'] != scale or ctl('configerrors').strip():
                        raise RuntimeError('Child output scale change did not apply')
                    for index in range(4):
                        capture(f'resize-{scale}-{index}', 'wlr-screencopy')
                        time.sleep(.03)
                time.sleep(.2)
                (directory / 'close').touch()
                for attempt in range(100):
                    try:
                        layers(False)
                        break
                    except RuntimeError:
                        if attempt == 99:
                            raise
                        time.sleep(.01)
                capture('closed', 'wlr-screencopy', False)
                capture('closed', 'ext-imagecopy', False)
                result['leak_detected'] = any(frame['green_private_pixels'] for frame in result['frames'])
                result['positive_controls_pass'] = all(frame['pink_control_pixels'] > 1000 for frame in result['frames'] if frame['phase'] in ('mapped', 'closed'))
                result['passed'] = not result['leak_detected'] and result['positive_controls_pass']
            finally:
                terminate(fixture)
                terminate(compositor, group=True)
                (output / (mode + '.json')).write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result[key] for key in ('mode', 'leak_detected', 'positive_controls_pass', 'passed')}, indent=2))
    print('Synthetic report:', output / (mode + '.json'))
    return result['passed']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-visible-nested', action='store_true', help='Explicitly allow a temporary synthetic nested compositor window')
    parser.add_argument('--startup-race', action='store_true', help='Exercise the known startup/output-resize gap; a detected leak returns failure')
    args = parser.parse_args()
    if not args.run_visible_nested:
        parser.error('Explicit --run-visible-nested is required; this test displays a temporary window')
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    output = ROOT / 'build/capture-check'
    output.mkdir(parents=True, exist_ok=True)
    compile_fixtures(output)
    return 0 if run(output, args.startup_race) else 1


if __name__ == '__main__':
    raise SystemExit(main())
