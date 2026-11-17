import subprocess
import sys
import pytest


def test_module_help():
    r = subprocess.run(
        [sys.executable, "-m", "venom", "--help"],
        capture_output=True, text=True,
    )
    assert r.returncode == 0
    assert "Venom" in r.stdout or "venom" in r.stdout
    assert "--tui" in r.stdout
    assert "--html" in r.stdout


def test_no_target_noninteractive():
    r = subprocess.run(
        [sys.executable, "-m", "venom"],
        capture_output=True, text=True,
        stdin=subprocess.DEVNULL,
    )
    assert r.returncode != 0


def test_nonexistent_target():
    r = subprocess.run(
        [sys.executable, "-m", "venom", "/nonexistent/path"],
        capture_output=True, text=True,
    )
    assert r.returncode != 0
    assert "does not exist" in r.stderr


def test_version_importable():
    from venom import __version__
    assert __version__ == "0.1.0"
