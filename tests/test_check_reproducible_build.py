"""Exit-code contract of the reproducible-build checker: 0 match, 1 mismatch, 2 build error."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CHECKER = Path(__file__).resolve().parent.parent / "scripts" / "check_reproducible_build.py"


class ReproducibleBuildCheckerTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name) / "repo"
        self.repo.mkdir()
        env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
        self.env = env
        for args in (
            ["init", "--quiet"],
            ["config", "user.email", "ci@example.invalid"],
            ["config", "user.name", "ci"],
            ["config", "commit.gpgsign", "false"],
        ):
            subprocess.run(["git", "-C", str(self.repo), *args], check=True, env=env)
        (self.repo / "payload.txt").write_text("fixed content\n")
        subprocess.run(["git", "-C", str(self.repo), "add", "payload.txt"], check=True, env=env)
        subprocess.run(
            ["git", "-C", str(self.repo), "commit", "--quiet", "-m", "fixture"], check=True, env=env
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def run_checker(self, build: str, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(CHECKER), "--build", build, *extra],
            cwd=self.repo,
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_identical_builds_exit_zero(self) -> None:
        result = self.run_checker("cp payload.txt {out}/payload.tgz")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("reproducible: 1 artifact(s) identical", result.stdout)

    def test_differing_builds_exit_one(self) -> None:
        result = self.run_checker("head -c 32 /dev/urandom > {out}/payload.tgz")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("NOT reproducible", result.stderr)

    def test_no_artifacts_exit_one(self) -> None:
        result = self.run_checker("true {out}")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_failed_build_exits_two(self) -> None:
        result = self.run_checker("exit 3; echo {out}")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("failed with exit code 3", result.stderr)

    def test_reference_mismatch_exits_one(self) -> None:
        reference = Path(self._tmp.name) / "reference"
        reference.mkdir()
        (reference / "payload.tgz").write_text("tampered\n")
        result = self.run_checker("cp payload.txt {out}/payload.tgz", "--reference", str(reference))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_build_command_without_placeholder_is_a_usage_error(self) -> None:
        result = self.run_checker("true")
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
