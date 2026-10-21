"""Independently unpack, hash-check, patch-replay and rerun the completed ZIP."""
import argparse
import json
import pathlib
import stat
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone

from build_return import (
    PACKAGE, PACKAGE_NAME, REPO, TARGET, ZIP_PATH, digest, files_in,
    original_files, run_gates, write_json,
)


def unpack_safe(zip_path, destination):
    with zipfile.ZipFile(zip_path) as archive:
        assert archive.testzip() is None, "CRC failure"
        seen = set()
        seen_folded = set()
        for item in archive.infolist():
            name = item.filename
            parts = name.rstrip("/").split("/")
            assert parts[0] == PACKAGE_NAME and len(parts) > 1, name
            assert all(part not in ("", ".", "..") for part in parts), name
            assert not name.startswith("/") and "\\" not in name and ":" not in name, name
            assert name not in seen and name.casefold() not in seen_folded, name
            seen.add(name)
            seen_folded.add(name.casefold())
            assert not stat.S_ISLNK(item.external_attr >> 16), name
            path = destination.joinpath(*parts)
            if item.is_dir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(archive.read(item))
    return destination / PACKAGE_NAME


def verify(zip_path, compare_worktree=True):
    assert sys.version_info[:2] == (3, 12), "Python 3.12 required"
    original = original_files()
    with tempfile.TemporaryDirectory(prefix="p46-run-return-check-") as directory:
        temporary = pathlib.Path(directory)
        package = unpack_safe(zip_path, temporary / "submitted")
        current = files_in(package)
        assert current[TARGET] != original[TARGET], "Implementation is still the input stub"
        for relative, raw in original.items():
            assert relative in current, "Missing original: " + relative
            if relative != TARGET:
                assert current[relative] == raw, "Changed original: " + relative
        for relative in current:
            assert (
                relative in original or relative.startswith("return/")
                or (relative.startswith("candidate_tests/")
                    and pathlib.PurePosixPath(relative).name.startswith("test_")
                    and relative.endswith(".py"))
            ), "Unauthorized file: " + relative
        protected = json.loads(current["PROTECTED_SHA256.json"])
        for relative, expected in protected.items():
            assert digest(current[relative]) == expected, "Protected hash: " + relative

        manifest = json.loads(current["return/OUTPUT_SHA256.json"])
        expected_manifest = {
            relative: digest(raw) for relative, raw in current.items()
            if relative != "return/OUTPUT_SHA256.json" and original.get(relative) != raw
        }
        assert manifest == expected_manifest, "Output manifest coverage/content mismatch"
        for relative in ("IMPLEMENTATION_RU.md", "REPORT_RU.md", "INTEGRATION_RU.md", "PATCH.diff"):
            assert "return/" + relative in current, relative
        round1 = json.loads(current["return/logs/RUNS.json"])["runs"]
        assert len(round1) == 3 and all(run["exit_code"] == 0 for run in round1)
        for index, run in enumerate(round1, 1):
            prefix = "%02d_%s" % (index, run["script"].removesuffix(".py"))
            assert json.loads(current["return/logs/" + prefix + ".result.json"]) == run
            for stream in ("stdout", "stderr"):
                raw = current["return/logs/" + run[stream + "_file"]]
                assert digest(raw) == run[stream + "_sha256"]

        replay = temporary / "patch_replay"
        replay.mkdir()
        for relative, raw in original.items():
            path = replay / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        patch = package / "return/PATCH.diff"
        patch_logs = []
        for command in (["git", "apply", "--check", str(patch)], ["git", "apply", str(patch)]):
            completed = subprocess.run(command, cwd=replay, capture_output=True)
            patch_logs.append({
                "command": command, "cwd": str(replay), "exit_code": completed.returncode,
                "stdout": completed.stdout.decode("utf-8"), "stderr": completed.stderr.decode("utf-8"),
            })
            assert completed.returncode == 0, patch_logs[-1]
        expected_replay = {
            relative: raw for relative, raw in current.items()
            if relative not in ("return/PATCH.diff", "return/OUTPUT_SHA256.json")
        }
        assert files_in(replay) == expected_replay, "Patch does not reproduce covered submitted files"
        if compare_worktree:
            assert files_in(PACKAGE) == current, "ZIP differs from final working package"

        external_logs = REPO / "artifacts/verification/round2"
        runs = run_gates(package, external_logs)
        assert all(run["exit_code"] == 0 for run in runs), "Clean extracted gates failed"
        assert [run["tests_run"] for run in runs] == [run["tests_run"] for run in round1]
        # Running with -B must not change the submitted bytes either.
        assert files_in(package) == current, "Verification changed submitted files"
        write_json(external_logs / "PATCH_REPLAY.json", {"runs": patch_logs, "reproduced_files": len(expected_replay)})
        summary = {
            "status": "PASS",
            "checked_at_utc": datetime.now(timezone.utc).isoformat(),
            "zip": str(zip_path.resolve()),
            "zip_sha256": digest(zip_path.read_bytes()),
            "zip_size_bytes": zip_path.stat().st_size,
            "files": len(current),
            "original_files": len(original),
            "protected_files": len(protected),
            "manifest_entries": len(manifest),
            "crc_and_paths": "PASS",
            "original_and_protected_bytes": "PASS",
            "output_manifest_exact": "PASS",
            "raw_log_hashes": "PASS",
            "patch_check_and_replay": "PASS",
            "zip_equals_worktree": "PASS" if compare_worktree else "NOT_REQUESTED",
            "clean_extracted_gate_exit_codes": [run["exit_code"] for run in runs],
            "clean_extracted_tests_run": [run["tests_run"] for run in runs],
            "product_integration": "NOT_CONNECTED",
            "product_acceptance": "OPEN",
        }
        write_json(zip_path.with_suffix(".validation.json"), summary)
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("zip", type=pathlib.Path, nargs="?", default=ZIP_PATH)
    parser.add_argument("--no-worktree-compare", action="store_true")
    args = parser.parse_args()
    verify(args.zip, compare_worktree=not args.no_worktree_compare)
