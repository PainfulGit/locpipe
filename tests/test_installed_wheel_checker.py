from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.check_installed_wheel import _run_installed_demo


class InstalledWheelCheckerTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
