"""Offline unit tests for integrity/file_integrity.py; synthetic temporary files only."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE = Path(__file__).resolve().parents[1] / "integrity" / "file_integrity.py"
spec = importlib.util.spec_from_file_location("file_integrity", MODULE)
fi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fi)


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.root = self.home / "watched"
        self.root.mkdir()
        self.manifest = self.home / "baseline.json"

    def write(self, name, content):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        return target

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result = fi.main(args)
        return result, out.getvalue(), err.getvalue()

    def test_empty_snapshot(self):
        self.assertEqual(fi.snapshot(self.root), {"schema_version": 1, "algorithm": "sha256", "files": []})

    def test_sha256_and_nested_relative_path(self):
        self.write("config/app.ini", b"demo\n")
        rows = fi.snapshot(self.root)["files"]
        self.assertEqual(rows, [{"path": "config/app.ini", "size": 5, "sha256": hashlib.sha256(b"demo\n").hexdigest()}])

    def test_deterministic_order(self):
        self.write("z", b"z")
        self.write("a", b"a")
        self.assertEqual([r["path"] for r in fi.snapshot(self.root)["files"]], ["a", "z"])

    def test_baseline_and_clean_check(self):
        self.write("settings.txt", b"safe")
        self.assertEqual(self.run_cli("baseline", "--root", str(self.root), "--output", str(self.manifest))[0], 0)
        code, out, _ = self.run_cli("check", "--root", str(self.root), "--baseline", str(self.manifest), "--format", "json", "--fail-on-drift")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out), {"added": [], "removed": [], "modified": [], "unchanged_count": 1})

    def test_detect_add_remove_modify(self):
        self.write("gone", b"gone")
        self.write("changed", b"before")
        old = fi.snapshot(self.root)
        (self.root / "gone").unlink()
        self.write("changed", b"after")
        self.write("new", b"new")
        self.assertEqual(fi.diff(old, fi.snapshot(self.root)), {"added": ["new"], "removed": ["gone"], "modified": ["changed"], "unchanged_count": 0})

    def test_detect_same_length_content_change(self):
        self.write("x", b"abc")
        old = fi.snapshot(self.root)
        self.write("x", b"xyz")
        self.assertEqual(fi.diff(old, fi.snapshot(self.root))["modified"], ["x"])

    def test_fail_on_drift_exit_code(self):
        self.write("x", b"a")
        self.run_cli("baseline", "--root", str(self.root), "--output", str(self.manifest))
        self.write("x", b"b")
        args = ("check", "--root", str(self.root), "--baseline", str(self.manifest))
        self.assertEqual(self.run_cli(*args)[0], 0)
        self.assertEqual(self.run_cli(*args, "--fail-on-drift")[0], 1)

    def test_refuse_overwrite_without_flag(self):
        self.assertEqual(self.run_cli("baseline", "--root", str(self.root), "--output", str(self.manifest))[0], 0)
        self.assertEqual(self.run_cli("baseline", "--root", str(self.root), "--output", str(self.manifest))[0], 2)
        self.assertEqual(self.run_cli("baseline", "--root", str(self.root), "--output", str(self.manifest), "--overwrite")[0], 0)

    def test_refuse_manifest_inside_root(self):
        code, _, err = self.run_cli("baseline", "--root", str(self.root), "--output", str(self.root / "base.json"))
        self.assertEqual(code, 2)
        self.assertIn("outside", err)

    def test_refuse_symlink_file(self):
        target = self.write("real", b"x")
        try:
            (self.root / "link").symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaisesRegex(fi.IntegrityError, "symlinks"):
            fi.snapshot(self.root)

    def test_refuse_symlink_directory(self):
        outside = self.home / "outside"
        outside.mkdir()
        try:
            (self.root / "linkdir").symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaisesRegex(fi.IntegrityError, "symlinks"):
            fi.snapshot(self.root)

    def test_refuse_symlink_root(self):
        link = self.home / "rootlink"
        try:
            link.symlink_to(self.root, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        self.assertEqual(self.run_cli("baseline", "--root", str(link), "--output", str(self.manifest))[0], 2)

    def test_reject_special_fifo(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO unavailable")
        os.mkfifo(self.root / "pipe")
        with self.assertRaisesRegex(fi.IntegrityError, "special"):
            fi.snapshot(self.root)

    def test_file_size_limit(self):
        self.write("big", b"abc")
        with mock.patch.object(fi, "MAX_FILE_BYTES", 2):
            with self.assertRaisesRegex(fi.IntegrityError, "file exceeds"):
                fi.snapshot(self.root)

    def test_total_size_limit(self):
        self.write("a", b"abc")
        self.write("b", b"def")
        with mock.patch.object(fi, "MAX_TOTAL_BYTES", 5):
            with self.assertRaisesRegex(fi.IntegrityError, "total file size"):
                fi.snapshot(self.root)

    def test_file_count_limit(self):
        self.write("a", b"a")
        self.write("b", b"b")
        with mock.patch.object(fi, "MAX_FILES", 1):
            with self.assertRaisesRegex(fi.IntegrityError, "more than"):
                fi.snapshot(self.root)

    def test_invalid_manifest_json(self):
        self.manifest.write_text("{bad", encoding="utf-8")
        with self.assertRaisesRegex(fi.IntegrityError, "UTF-8 JSON"):
            fi.load_manifest(self.manifest)

    def test_reject_duplicate_json_keys(self):
        self.manifest.write_text('{"schema_version":1,"schema_version":1,"algorithm":"sha256","files":[]}')
        with self.assertRaisesRegex(fi.IntegrityError, "duplicate keys"):
            fi.load_manifest(self.manifest)

    def test_directory_depth_limit(self):
        self.write("a/b/file", b"x")
        with mock.patch.object(fi, "MAX_DEPTH", 1):
            with self.assertRaisesRegex(fi.IntegrityError, "depth limit"):
                fi.snapshot(self.root)

    def test_directory_count_limit(self):
        (self.root / "one").mkdir()
        (self.root / "two").mkdir()
        with mock.patch.object(fi, "MAX_DIRECTORIES", 2):
            with self.assertRaisesRegex(fi.IntegrityError, "count"):
                fi.snapshot(self.root)

    def test_invalid_manifest_utf8(self):
        self.manifest.write_bytes(b"\xff")
        with self.assertRaisesRegex(fi.IntegrityError, "UTF-8 JSON"):
            fi.load_manifest(self.manifest)

    def test_manifest_size_limit(self):
        self.manifest.write_bytes(b"x" * 12)
        with mock.patch.object(fi, "MAX_MANIFEST_BYTES", 10):
            with self.assertRaisesRegex(fi.IntegrityError, "size limit"):
                fi.load_manifest(self.manifest)

    def test_reject_duplicate_paths(self):
        digest = "0" * 64
        self.manifest.write_text(json.dumps({"schema_version": 1, "algorithm": "sha256", "files": [{"path": "x", "size": 1, "sha256": digest}, {"path": "x", "size": 1, "sha256": digest}]}))
        with self.assertRaisesRegex(fi.IntegrityError, "duplicate"):
            fi.load_manifest(self.manifest)

    def test_reject_path_traversal(self):
        self.assertFalse(fi._valid_relpath("../secret"))
        self.assertFalse(fi._valid_relpath("/absolute"))
        self.assertFalse(fi._valid_relpath("a\\b"))
        self.assertFalse(fi._valid_relpath("a//b"))
        self.assertFalse(fi._valid_relpath("a/./b"))
        self.assertFalse(fi._valid_relpath("x\n"))

    def test_reject_boolean_size_and_schema(self):
        base = {"schema_version": True, "algorithm": "sha256", "files": []}
        self.manifest.write_text(json.dumps(base))
        with self.assertRaisesRegex(fi.IntegrityError, "schema"):
            fi.load_manifest(self.manifest)
        base = {"schema_version": 1, "algorithm": "sha256", "files": [{"path": "x", "size": True, "sha256": "0" * 64}]}
        self.manifest.write_text(json.dumps(base))
        with self.assertRaisesRegex(fi.IntegrityError, "file size"):
            fi.load_manifest(self.manifest)

    def test_reject_bad_digest(self):
        self.manifest.write_text(json.dumps({"schema_version": 1, "algorithm": "sha256", "files": [{"path": "x", "size": 0, "sha256": "bad"}]}))
        with self.assertRaisesRegex(fi.IntegrityError, "digest"):
            fi.load_manifest(self.manifest)

    def test_missing_root_error(self):
        code, _, err = self.run_cli("baseline", "--root", str(self.home / "missing"), "--output", str(self.manifest))
        self.assertEqual(code, 2)
        self.assertIn("root", err)

    def test_json_report_escapes_filename(self):
        self.write('quote".txt', b"safe")
        old = fi.snapshot(self.root)
        self.write("other", b"new")
        self.assertEqual(fi.diff(old, fi.snapshot(self.root))["added"], ["other"])
        self.assertIn('quote".txt', json.loads(json.dumps(old))["files"][0]["path"])


if __name__ == "__main__":
    unittest.main()
