from __future__ import annotations

import hashlib
import json
import unittest


def _suite() -> unittest.TestSuite:
    from locpipe._demo_support.test_content_lifecycle_slice04 import ContentLifecycleSlice04Tests
    from locpipe._demo_support.test_fluency_lifecycle_v0 import FluencyLifecycleV0Tests

    return unittest.TestSuite((
        ContentLifecycleSlice04Tests(
            "test_flat_and_structured_real_handlers_reach_content_verified"
        ),
        FluencyLifecycleV0Tests(
            "test_initial_state_reaches_existing_content_verified_publication"
        ),
        FluencyLifecycleV0Tests(
            "test_one_correction_recheck_reaches_existing_content_verified_publication"
        ),
    ))


def main() -> int:
    result = unittest.TestResult()
    _suite().run(result)
    if not result.wasSuccessful():
        detail = "; ".join(
            f"{case.id()}:{type(error).__name__}"
            for case, error in (*result.failures, *result.errors)
        )
        print(json.dumps({
            "demo": "FAILED",
            "errors": len(result.errors),
            "failures": len(result.failures),
            "detail_sha256": hashlib.sha256(detail.encode("utf-8")).hexdigest(),
        }, sort_keys=True))
        return 1
    print(json.dumps({
        "demo": "PASS",
        "fixtures": 4,
        "fluency_lifecycles": 2,
        "fluency_provenance_paths": ["CORRECTION_TERMINAL", "INITIAL_STATE"],
        "locales": 1,
        "terminal_state": "CONTENT_VERIFIED",
        "payloads_logged": 0,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
