from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.check_installed_wheel import (
    _PREPARED_PROBE,
    _expected_wheel_version,
    _install_command,
    _run_installed_demo,
    _run_installed_prepared_probe,
    _validate_installed_authority,
)


class InstalledWheelCheckerTests(unittest.TestCase):
    def test_install_command_uses_separate_runtime_wheelhouse(self) -> None:
        self.assertEqual(
            _install_command(Path("python"), Path("dist/locpipe-0.2.0b4-py3-none-any.whl"), Path("wheelhouse")),
            (
                "python", "-m", "pip", "install", "--disable-pip-version-check",
                "--no-index", "--find-links", "wheelhouse",
                str(Path("dist/locpipe-0.2.0b4-py3-none-any.whl")),
            ),
        )
        self.assertEqual(
            _expected_wheel_version(Path("locpipe-0.2.0b4-py3-none-any.whl")),
            "0.2.0b4",
        )
        with self.assertRaises(SystemExit):
            _expected_wheel_version(Path("another-package.whl"))

    def test_installed_authority_requires_both_origins_inside_venv(self) -> None:
        venv = Path("root/venv").resolve()
        installed = {
            "locpipe_origin": str(venv / "Lib/site-packages/locpipe/__init__.py"),
            "rfc8785_origin": str(venv / "Lib/site-packages/rfc8785/__init__.py"),
            "requires": ["rfc8785==0.1.4"],
            "version": "0.2.0b4",
        }
        _validate_installed_authority(installed, venv_root=venv, expected_version="0.2.0b4")
        installed["rfc8785_origin"] = str(Path("outside/rfc8785/__init__.py").resolve())
        with self.assertRaisesRegex(SystemExit, "escaped the temporary environment"):
            _validate_installed_authority(installed, venv_root=venv, expected_version="0.2.0b4")

    def test_successful_captured_demo_behavior_is_unchanged(self) -> None:
        expected = subprocess.CompletedProcess(
            args=("python", "-I", "-m", "locpipe.demo"),
            returncode=0,
            stdout='{"demo":"PASS"}\n',
            stderr="",
        )
        with patch("tools.check_installed_wheel.subprocess.run", return_value=expected) as run:
            actual = _run_installed_demo(Path("python"), root=Path("root"))

        self.assertIs(actual, expected)
        run.assert_called_once_with(
            ("python", "-I", "-m", "locpipe.demo"),
            check=True,
            capture_output=True,
            text=True,
            cwd=Path("root"),
        )

    def test_child_failure_surfaces_output_and_exit_without_retry_or_traceback(self) -> None:
        failure = subprocess.CalledProcessError(
            17,
            ("python", "-I", "-m", "locpipe.demo"),
            output="child stdout",
            stderr="child stderr\n",
        )
        with patch("tools.check_installed_wheel.subprocess.run", side_effect=failure) as run:
            with self.assertRaises(SystemExit) as caught:
                _run_installed_demo(Path("python"), root=Path("root"))

        run.assert_called_once()
        message = str(caught.exception)
        self.assertIn("installed wheel demo failed with exit code 17", message)
        self.assertIn("--- installed demo stdout ---\nchild stdout\n", message)
        self.assertIn("--- installed demo stderr ---\nchild stderr\n", message)
        self.assertNotIn("Traceback", message)
        self.assertNotIn("CalledProcessError", message)
        self.assertIsNone(caught.exception.__cause__)
        self.assertTrue(caught.exception.__suppress_context__)

    def test_prepared_probe_uses_isolated_installed_process(self) -> None:
        expected = subprocess.CompletedProcess(
            args=("python", "-I", "-c", _PREPARED_PROBE),
            returncode=0,
            stdout='{"prepared_api":"PASS","rows":6,"validation_api":"PASS"}\n',
            stderr="",
        )
        with patch("tools.check_installed_wheel.subprocess.run", return_value=expected) as run:
            actual = _run_installed_prepared_probe(Path("python"), root=Path("root"))

        self.assertIs(actual, expected)
        run.assert_called_once_with(
            ("python", "-I", "-c", _PREPARED_PROBE),
            check=True,
            capture_output=True,
            text=True,
            cwd=Path("root"),
        )
        for public_name in (
            "prepare_accepted_source_authority_v0",
            "rebind_prepared_source_authority_v0",
            "build_translation_job_prepared_v0",
            "build_content_validation_job_prepared_v0",
        ):
            self.assertIn(public_name, _PREPARED_PROBE)
        self.assertEqual(1, _PREPARED_PROBE.count("build_content_validation_job_prepared_v0("))
        self.assertIn('"validation_api": "PASS"', _PREPARED_PROBE)

    def test_prepared_probe_failure_has_bounded_diagnostics(self) -> None:
        failure = subprocess.CalledProcessError(
            23,
            ("python", "-I", "-c", _PREPARED_PROBE),
            output="probe stdout\n",
            stderr="probe stderr",
        )
        with patch("tools.check_installed_wheel.subprocess.run", side_effect=failure):
            with self.assertRaises(SystemExit) as caught:
                _run_installed_prepared_probe(Path("python"), root=Path("root"))

        message = str(caught.exception)
        self.assertIn("installed wheel prepared probe failed with exit code 23", message)
        self.assertIn("--- installed prepared probe stdout ---\nprobe stdout\n", message)
        self.assertIn("--- installed prepared probe stderr ---\nprobe stderr", message)
        self.assertNotIn("Traceback", message)


if __name__ == "__main__":
    unittest.main()
