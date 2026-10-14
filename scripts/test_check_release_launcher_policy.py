#!/usr/bin/env python3
"""Focused acceptance/rejection tests for the release-helper source gate."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from check_release_launcher_policy import LauncherPolicyError, verify_source


def write_policy(root: Path, paths: tuple[str, ...] = ()) -> dict:
    """Fixture usable before git init in native-only source/manifest tests."""
    policy = {
        "schema_version": 1,
        "launchers": [
            {"path": path, "sha256": hashlib.sha256((root / path).read_bytes()).hexdigest()}
            for path in paths
        ],
    }
    (root / "config").mkdir(exist_ok=True)
    (root / "config/release-launcher-policy.json").write_text(json.dumps(policy), encoding="utf-8")
    return policy


class ReleaseLauncherPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write(self, path: str, content: str | bytes) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content.encode() if isinstance(content, str) else content)

    def assert_rejected(self, phrase: str) -> None:
        with self.assertRaisesRegex(LauncherPolicyError, phrase):
            verify_source(self.root)

    def test_native_only_requires_explicit_empty_policy(self) -> None:
        policy = write_policy(self.root)
        self.assertEqual(verify_source(self.root), policy)

    def test_missing_policy_fails(self) -> None:
        self.assert_rejected("missing required file")

    def test_repaired_cmd_and_documentation_pass(self) -> None:
        self.write("testnet-release/testnet-start.cmd", '@echo off\r\n"%~dp0hegemon-node.exe" --testnet %*\r\n')
        self.write("testnet-release/README-WINDOWS.txt", "Example: powershell -ExecutionPolicy Bypass is forbidden.\n")
        self.write("testnet-release/RELEASE-NOTES.md", "The old script used powershell -ep Bypass.\n")
        policy = write_policy(self.root, ("testnet-release/testnet-start.cmd", "testnet-release/README-WINDOWS.txt"))
        self.assertEqual(verify_source(self.root), policy)

    def test_original_bypass_is_rejected_even_with_approved_digest(self) -> None:
        self.write("testnet-release/testnet-start.cmd", 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0testnet-start.ps1" %*\n')
        write_policy(self.root, ("testnet-release/testnet-start.cmd",))
        self.assert_rejected("execution-policy weakening")

    def test_hash_change_requires_new_review(self) -> None:
        self.write("testnet-release/start.cmd", "@echo off\nhegemon-node.exe --testnet\n")
        write_policy(self.root, ("testnet-release/start.cmd",))
        self.write("testnet-release/start.cmd", "@echo off\nhegemon-node.exe --dev\n")
        self.assert_rejected("digest differs")

    def test_unlisted_executable_fails(self) -> None:
        self.write("testnet-release/new.bat", "hegemon-node.exe\n")
        write_policy(self.root)
        self.assert_rejected("missing from the reviewed policy")

    def test_unlisted_other_files_fail_closed(self) -> None:
        write_policy(self.root)
        for filename in ("loader.py", "loader.exe", "loader.com", "loader.wsf", "README.txt", "opaque"):
            with self.subTest(filename=filename):
                self.write("testnet-release/" + filename, b"unapproved")
                self.assert_rejected("missing from the reviewed policy")
                (self.root / "testnet-release" / filename).unlink()

    def test_retained_markdown_docs_are_allowed_but_cannot_be_listed(self) -> None:
        write_policy(self.root)
        self.write("testnet-release/VALIDATION-0.10.2.md", "Retained evidence, never packaged.\n")
        self.write("testnet-release/ACTIVATION-FORECAST.md", "Forecast, never packaged.\n")
        self.assertEqual(verify_source(self.root)["launchers"], [])
        write_policy(self.root, ("testnet-release/VALIDATION-0.10.2.md",))
        self.assert_rejected("unsupported shipped helper extension")

    def test_cmd_rem_separator_cannot_hide_execution(self) -> None:
        for command in ("@rem benign & powershell.exe -ExecutionPolicy Bypass", "REM benign | pwsh -ep Unrestricted"):
            with self.subTest(command=command):
                self.write("testnet-release/start.cmd", command + "\n")
                write_policy(self.root, ("testnet-release/start.cmd",))
                self.assert_rejected("execution-policy weakening")

    def test_prohibited_extensions_fail_in_inventory(self) -> None:
        for extension in (".ps1", ".vbs", ".js", ".PS1"):
            with self.subTest(extension=extension):
                self.write(f"testnet-release/new{extension}", "benign\n")
                write_policy(self.root)
                self.assert_rejected("unsupported executable helper")
                (self.root / f"testnet-release/new{extension}").unlink()

    def test_unsupported_listed_extension_fails(self) -> None:
        self.write("testnet-release/start.py", "print('hello')\n")
        write_policy(self.root, ("testnet-release/start.py",))
        self.assert_rejected("unsupported shipped helper extension")

    def test_powershell_invocation_without_bypass_is_rejected(self) -> None:
        for command in ('powershell.exe -NoProfile -File helper.ps1', 'pWsh -File helper.ps1', 'po"wer"^shell.exe -File helper.ps1'):
            with self.subTest(command=command):
                self.write("testnet-release/start.cmd", command + "\n")
                write_policy(self.root, ("testnet-release/start.cmd",))
                self.assert_rejected("PowerShell/pwsh invocation")

    def test_policy_switch_obfuscations_fail_in_producers(self) -> None:
        commands = (
            'powershell -eP Bypass',
            'powershell -ExecutionPol^\r\nicy Unrestricted',
            'powershell -e^p "By"^pass',
            'powershell -"ExecutionPolicy" "Bypass"',
            'powershell -executionpolicy:unrestricted',
            'Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass',
            'Set-ExecutionPolicy Bypass -Scope Process',
        )
        write_policy(self.root)
        for path in ("scripts/build_release_artifacts.sh", "scripts/release_artifact_manifest.py", "scripts/package_testnet_downloads.py", ".github/workflows/release.yml"):
            for command in commands:
                with self.subTest(path=path, command=command):
                    self.write(path, command + "\n")
                    self.assert_rejected("execution-policy weakening")
            (self.root / path).unlink()

    def test_producer_prose_names_and_comments_pass(self) -> None:
        write_policy(self.root)
        self.write("scripts/build_release_artifacts.sh", '# Historical example: powershell -ep Bypass\n# ExecutionPolicy Bypass is prohibited.\nprintf "%s" "PowerShell support removed"\n')
        self.assertEqual(verify_source(self.root)["launchers"], [])

    def test_path_traversal_and_noncanonical_paths_fail(self) -> None:
        bad_paths = ("../outside.cmd", "testnet-release/../outside.cmd", "/testnet-release/start.cmd", "testnet-release//start.cmd", "testnet-release/./start.cmd", "testnet-release\\start.cmd", "testnet-release/start.cmd/", "testnet-release/dir:name/start.cmd")
        for path in bad_paths:
            with self.subTest(path=path):
                self.write("config/release-launcher-policy.json", json.dumps({"schema_version": 1, "launchers": [{"path": path, "sha256": "0" * 64}]}))
                self.assert_rejected("canonical beneath")

    def test_symlink_helper_fails(self) -> None:
        self.write("outside.cmd", "hegemon-node.exe\n")
        (self.root / "testnet-release").mkdir()
        (self.root / "testnet-release/start.cmd").symlink_to(self.root / "outside.cmd")
        write_policy(self.root)
        self.assert_rejected("symlink")

    def test_symlink_directory_component_fails(self) -> None:
        self.write("outside/start.cmd", "hegemon-node.exe\n")
        (self.root / "testnet-release").mkdir()
        (self.root / "testnet-release/nested").symlink_to(self.root / "outside", target_is_directory=True)
        self.write("config/release-launcher-policy.json", json.dumps({"schema_version": 1, "launchers": [{"path": "testnet-release/nested/start.cmd", "sha256": "0" * 64}]}))
        self.assert_rejected("symlink")

    def test_symlink_policy_fails(self) -> None:
        self.write("outside.json", '{"schema_version": 1, "launchers": []}')
        (self.root / "config").mkdir()
        (self.root / "config/release-launcher-policy.json").symlink_to(self.root / "outside.json")
        self.assert_rejected("symlink")

    def test_symlink_producer_fails(self) -> None:
        write_policy(self.root)
        self.write("outside.sh", "true\n")
        (self.root / "scripts").mkdir()
        (self.root / "scripts/build_release_artifacts.sh").symlink_to(self.root / "outside.sh")
        self.assert_rejected("symlink")

    def test_symlink_release_directory_fails(self) -> None:
        write_policy(self.root)
        (self.root / "outside").mkdir()
        (self.root / "testnet-release").symlink_to(self.root / "outside", target_is_directory=True)
        self.assert_rejected("symlink")

    def test_directory_in_place_of_policy_fails(self) -> None:
        (self.root / "config/release-launcher-policy.json").mkdir(parents=True)
        self.assert_rejected("regular file")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO test requires mkfifo")
    def test_fifo_helper_fails_without_opening_a_blocking_stream(self) -> None:
        write_policy(self.root)
        (self.root / "testnet-release").mkdir()
        os.mkfifo(self.root / "testnet-release/start.cmd")
        self.assert_rejected("regular file")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO test requires mkfifo")
    def test_fifo_policy_is_rejected_before_any_open(self) -> None:
        (self.root / "config").mkdir()
        os.mkfifo(self.root / "config/release-launcher-policy.json")
        with patch(
            "check_release_launcher_policy.os.open",
            side_effect=AssertionError("nonregular policy must be rejected before os.open"),
        ) as opened:
            self.assert_rejected("regular file")
            opened.assert_not_called()

    def test_invalid_json_duplicate_keys_and_schema_fail(self) -> None:
        policies = (
            '{',
            '{"schema_version": 1, "schema_version": 1, "launchers": []}',
            '{"schema_version": true, "launchers": []}',
            '{"schema_version": 2, "launchers": []}',
            '{"schema_version": 1, "launchers": {}}',
            '{"schema_version": 1, "launchers": [], "extra": 0}',
            '{"schema_version": 1, "launchers": [{"path": "testnet-release/a.cmd", "sha256": "oops"}]}',
            '{"schema_version": 1, "launchers": [{"path": "testnet-release/a.cmd", "sha256": "' + "A" * 64 + '"}]}',
            '{"schema_version": 1, "launchers": [{"path": "testnet-release/a.cmd", "sha256": "' + "0" * 64 + '", "extra": true}]}',
        )
        for policy in policies:
            with self.subTest(policy=policy):
                self.write("config/release-launcher-policy.json", policy)
                with self.assertRaises(LauncherPolicyError):
                    verify_source(self.root)

    def test_duplicate_paths_fail(self) -> None:
        entry = {"path": "testnet-release/a.cmd", "sha256": "0" * 64}
        self.write("config/release-launcher-policy.json", json.dumps({"schema_version": 1, "launchers": [entry, entry]}))
        self.assert_rejected("duplicate launcher path")

    def test_file_size_bounds_fail(self) -> None:
        self.write("config/release-launcher-policy.json", b" " * (64 * 1024 + 1))
        self.assert_rejected("exceeds")
        self.write("testnet-release/start.cmd", b"x" * (2 * 1024 * 1024 + 1))
        write_policy(self.root, ("testnet-release/start.cmd",))
        self.assert_rejected("exceeds")

    def test_source_outside_bounded_paths_is_not_scanned(self) -> None:
        write_policy(self.root)
        self.write("unrelated/example.ps1", "powershell -ep Bypass\n")
        self.assertEqual(verify_source(self.root)["launchers"], [])


if __name__ == "__main__":
    unittest.main()
