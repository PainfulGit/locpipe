from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from tools.compile_build_lock import (
    CANONICAL_HEADER,
    COMPILE_ARGUMENTS,
    CUSTOM_COMPILE_COMMAND,
    _clean_compile_environment,
    _compile_build_lock,
    _lock_stanzas,
    _require_tooling,
    _source_pins,
    _source_pip_version,
    _validate_generated_lock,
)


ROOT = Path(__file__).resolve().parents[1]
CURRENT_PIP_VERSION = "26.2.1"
CURRENT_PIP_WHEEL_SHA256 = "71138adf1f4ca900cdb7d289c21b7494329f2332b6d85f0e1c42108c0384ed3e"
HASH_A = "a" * 64
HASH_B = "b" * 64


def _source(version: str = CURRENT_PIP_VERSION) -> bytes:
    return f"example==1.0\npip=={version}\n-r requirements-runtime.lock\n".encode()


def _lock(version: str = CURRENT_PIP_VERSION) -> bytes:
    return (
        CANONICAL_HEADER
        + f"example==1.0 \\\n    --hash=sha256:{HASH_A}\n\n".encode()
        + f"runtime==1.0 \\\n    --hash=sha256:{HASH_A}\n\n".encode()
        + b"# The following packages are considered to be unsafe in a requirements file:\n"
        + f"pip=={version} \\\n    --hash=sha256:{HASH_B}\n".encode()
    )


def _write_fixture(root: Path, *, lock: bytes = b"seed-lock\n") -> None:
    (root / "requirements-build.in").write_bytes(_source())
    (root / "requirements-build.lock").write_bytes(lock)
    (root / "requirements-runtime.lock").write_bytes(b"runtime==1.0 --hash=sha256:" + HASH_A.encode() + b"\n")


class BuildLockContractTests(unittest.TestCase):
    def test_tooling_and_arguments_fail_closed(self) -> None:
        _require_tooling(
            argv=(),
            implementation="cpython",
            version_info=(3, 11, 9),
            version_reader=lambda name: "7.6.1",
        )
        cases = (
            {"argv": ("--upgrade",), "implementation": "cpython", "version_info": (3, 11, 9), "version_reader": lambda name: "7.6.1"},
            {"argv": (), "implementation": "pypy", "version_info": (3, 11, 9), "version_reader": lambda name: "7.6.1"},
            {"argv": (), "implementation": "cpython", "version_info": (3, 11, 8), "version_reader": lambda name: "7.6.1"},
            {"argv": (), "implementation": "cpython", "version_info": (3, 11, 10), "version_reader": lambda name: "7.6.1"},
            {"argv": (), "implementation": "cpython", "version_info": (3, 12, 0), "version_reader": lambda name: "7.6.1"},
            {"argv": (), "implementation": "cpython", "version_info": (3, 11, 9), "version_reader": lambda name: "7.5.0"},
        )
        for case in cases:
            with self.subTest(case=case), self.assertRaises(SystemExit):
                _require_tooling(**case)

    def test_compile_is_seeded_and_uses_exact_args_and_clean_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = b"exact-current-lock\n"
            _write_fixture(root, lock=original)
            observed: dict[str, object] = {}

            def runner(argv: tuple[str, ...], *, cwd: Path, env: dict[str, str], check: bool) -> object:
                observed.update(argv=argv, cwd=cwd, env=env, check=check)
                self.assertEqual((cwd / "requirements-build.lock").read_bytes(), original)
                (cwd / "requirements-build.lock").write_bytes(_lock())
                return object()

            environment = {
                "PATH": os.environ.get("PATH", ""),
                "PIP_NO_INDEX": "1",
                "PIP_INDEX_URL": "https://invalid.example/simple",
                "PIP_EXTRA_INDEX_URL": "https://extra.invalid/simple",
                "PIP_FIND_LINKS": "private-wheelhouse",
                "PIP_TRUSTED_HOST": "invalid.example",
                "PIP_USE_FEATURE": "truststore",
                "CUSTOM_COMPILE_COMMAND": "untrusted command",
            }
            generated = _compile_build_lock(root=root, runner=runner, environment=environment)
            self.assertEqual(generated, _lock())
            self.assertEqual((root / "requirements-build.lock").read_bytes(), _lock())
            self.assertEqual(observed["argv"][1:], COMPILE_ARGUMENTS)  # type: ignore[index]
            self.assertIn("--no-config", observed["argv"])  # type: ignore[operator]
            self.assertTrue(observed["check"])
            child = observed["env"]
            self.assertEqual(child["CUSTOM_COMPILE_COMMAND"], CUSTOM_COMPILE_COMMAND)  # type: ignore[index]
            self.assertEqual(child["PIP_USE_FEATURE"], "truststore")  # type: ignore[index]
            self.assertNotIn("PIP_NO_INDEX", child)
            self.assertNotIn("PIP_INDEX_URL", child)
            self.assertNotIn("PIP_EXTRA_INDEX_URL", child)
            self.assertNotIn("PIP_FIND_LINKS", child)
            self.assertNotIn("PIP_TRUSTED_HOST", child)
            self.assertTrue(Path(child["PIP_CONFIG_FILE"]).name == "pip-empty.ini")  # type: ignore[index]

    def test_failed_compile_or_validation_never_replaces_working_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = b"accepted-working-lock\n"
            _write_fixture(root, lock=original)

            def compile_failure(*args: object, **kwargs: object) -> object:
                raise RuntimeError("synthetic compile failure")

            with self.assertRaisesRegex(RuntimeError, "synthetic compile failure"):
                _compile_build_lock(root=root, runner=compile_failure)
            self.assertEqual((root / "requirements-build.lock").read_bytes(), original)

            def invalid_output(argv: tuple[str, ...], *, cwd: Path, env: dict[str, str], check: bool) -> object:
                (cwd / "requirements-build.lock").write_bytes(b"invalid generated lock\n")
                return object()

            with self.assertRaisesRegex(SystemExit, "canonical wrapper command"):
                _compile_build_lock(root=root, runner=invalid_output)
            self.assertEqual((root / "requirements-build.lock").read_bytes(), original)

    def test_permanent_lock_validation_is_pin_derived_and_hash_closed(self) -> None:
        self.assertEqual(_source_pip_version(_source()), CURRENT_PIP_VERSION)
        stanzas = _validate_generated_lock(_lock(), source_payload=_source())
        self.assertEqual(stanzas["pip"], (CURRENT_PIP_VERSION, (HASH_B,)))
        failures = (
            (_source() + f"pip=={CURRENT_PIP_VERSION}\n".encode(), _lock(), "duplicate source"),
            (_source("25.0"), _lock(), "does not match"),
            (_source(), _lock().replace(CANONICAL_HEADER, b"# bad header\n"), "canonical wrapper"),
            (_source(), _lock() + b"# --no-index\n", "forbidden option"),
            (_source(), _lock().replace(f"    --hash=sha256:{HASH_A}\n".encode(), b""), "unhashed"),
        )
        for source, lock, message in failures:
            with self.subTest(message=message), self.assertRaisesRegex(SystemExit, message):
                _validate_generated_lock(lock, source_payload=source)

    def test_current_checkpoint_is_exact_and_hash_closed(self) -> None:
        source_payload = (ROOT / "requirements-build.in").read_bytes()
        lock_payload = (ROOT / "requirements-build.lock").read_bytes()
        runtime_payload = (ROOT / "requirements-runtime.lock").read_bytes()
        self.assertEqual(_source_pip_version(source_payload), CURRENT_PIP_VERSION)
        stanzas = _validate_generated_lock(
            lock_payload,
            source_payload=source_payload,
            included_source_payloads=(runtime_payload,),
            private_roots=(ROOT,),
        )
        self.assertIn(CURRENT_PIP_WHEEL_SHA256, stanzas["pip"][1])
        runtime_pins = _source_pins(runtime_payload, label="requirements-runtime.lock")
        self.assertTrue(runtime_pins)
        for name, version in runtime_pins.items():
            self.assertIn(name, stanzas)
            self.assertEqual(stanzas[name][0], version)
            self.assertTrue(stanzas[name][1])

    def test_clean_environment_does_not_inherit_arbitrary_pip_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "empty.ini"
            config.write_bytes(b"")
            cleaned = _clean_compile_environment(
                {
                    "PATH": "kept",
                    "PIP_NO_INDEX": "1",
                    "PIP_CERT": "private-cert",
                    "PIP_CONFIG_FILE": "private-config",
                    "PIP_USE_FEATURE": "not-truststore",
                },
                empty_config=config,
            )
            self.assertEqual(cleaned["PATH"], "kept")
            self.assertEqual(cleaned["PIP_CONFIG_FILE"], str(config))
            self.assertEqual(cleaned["CUSTOM_COMPILE_COMMAND"], CUSTOM_COMPILE_COMMAND)
            self.assertNotIn("PIP_NO_INDEX", cleaned)
            self.assertNotIn("PIP_CERT", cleaned)
            self.assertNotIn("PIP_USE_FEATURE", cleaned)


if __name__ == "__main__":
    unittest.main()
