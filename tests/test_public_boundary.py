from __future__ import annotations

import unittest

from tools.check_public_boundary import _scan_commit_metadata, _validate_commit_metadata


class PublicBoundaryMetadataTests(unittest.TestCase):
    def test_current_history_uses_only_approved_noreply_identity(self) -> None:
        self.assertGreater(_scan_commit_metadata(), 0)

    def test_personal_or_unapproved_identity_is_rejected(self) -> None:
        with self.assertRaisesRegex(SystemExit, "unapproved author identity"):
            _validate_commit_metadata((
                ("a" * 40, "Contributor", "name@example.com", "PainfulGit", "258659461+PainfulGit@users.noreply.github.com"),
            ))
        with self.assertRaisesRegex(SystemExit, "unapproved committer identity"):
            _validate_commit_metadata((
                ("b" * 40, "PainfulGit", "258659461+PainfulGit@users.noreply.github.com", "Contributor", "name@example.com"),
            ))


if __name__ == "__main__":
    unittest.main()
