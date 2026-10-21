"""Побайтовая точность, детерминизм и чистая граница адаптера."""

from contextlib import ExitStack
from copy import deepcopy
import hashlib
import inspect
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import unittest
from unittest.mock import patch

from audit_release.command_evidence import build_run_evidence


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def inputs():
    report = {
        "schema_version": "FIRST_OFFLINE_UNITTEST_RUN_V1",
        "records": [{
            "release_id": "r", "suite_id": "s", "case_id": "z",
            "attempt": 7, "status": "PASS", "exit_code": 0, "skip_count": 0,
        }, {
            "release_id": "r", "suite_id": "s", "case_id": "a",
            "attempt": 7, "status": "FAIL", "exit_code": 1, "skip_count": 0,
        }],
        "counts": {"tests_run": 2, "failures": 1, "errors": 0, "skips": 0},
        "stdout": "Привет\r\nCafe\u0301\n\x00\t\x7f",
        "stderr": "ошибка\r\n",
    }
    kwargs = {
        "release_id": "r", "attempt": 7,
        "bindings": [{"test_id": "tests.z", "suite_id": "s", "case_id": "z"},
                     {"test_id": "tests.a", "suite_id": "s", "case_id": "a"}],
        "command": {"key": "RUN/Main", "argv": ["python", "тест.py", "Cafe\u0301"],
                    "cwd": "C:/Путь", "interpreter": "Python 3.12"},
        "test_artifacts": [{"key": "Tests/Z.py", "content": b"\xff\x00\r\n"},
                           {"key": "Tests/A.py", "content": b""}],
    }
    return report, kwargs


class HashAndPurityTests(unittest.TestCase):
    def test_public_function_signature(self):
        parameters = inspect.signature(build_run_evidence).parameters
        self.assertEqual(tuple(parameters), ("report", "release_id", "bindings", "attempt",
                                             "command", "test_artifacts"))
        self.assertEqual(parameters["report"].kind, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        self.assertIs(parameters["report"].default, inspect.Parameter.empty)
        for name in ("release_id", "bindings", "attempt", "command", "test_artifacts"):
            self.assertEqual(parameters[name].kind, inspect.Parameter.KEYWORD_ONLY)
            if name != "attempt":
                self.assertIs(parameters[name].default, inspect.Parameter.empty)
        self.assertEqual(parameters["attempt"].default, 1)

    def test_exact_envelope_fields_types_and_flags(self):
        report, kwargs = inputs()
        output = build_run_evidence(report, **kwargs)
        self.assertIs(type(output), dict)
        self.assertEqual(set(output), {"schema_version", "records", "report_sha256",
                                      "identity_snapshot", "raw_outputs",
                                      "external_effect_authorized", "gate_acceptance"})
        self.assertEqual(output["schema_version"], "FIRST_RUN_EVIDENCE_ENVELOPE_V1")
        self.assertIs(output["external_effect_authorized"], False)
        self.assertIs(output["gate_acceptance"], False)
        self.assertIs(type(output["records"]), list)
        self.assertTrue(all(type(record) is dict for record in output["records"]))
        snapshot = output["identity_snapshot"]
        self.assertIs(type(snapshot), dict)
        self.assertEqual(set(snapshot), {"schema_version", "artifacts"})
        self.assertEqual(snapshot["schema_version"], "FIRST_TEST_IDENTITY_SNAPSHOT_V1")
        self.assertIs(type(snapshot["artifacts"]), list)
        for artifact in snapshot["artifacts"]:
            self.assertIs(type(artifact), dict)
            self.assertEqual(set(artifact), {"kind", "key", "sha256"})
            self.assertTrue(all(type(value) is str for value in artifact.values()))
            self.assertRegex(artifact["sha256"], r"^[0-9a-f]{64}$")
        self.assertIs(type(output["raw_outputs"]), dict)
        self.assertEqual(set(output["raw_outputs"]), {"stdout", "stderr"})
        for stream in output["raw_outputs"].values():
            self.assertIs(type(stream), dict)
            self.assertEqual(set(stream), {"content", "sha256", "size_bytes"})
            self.assertIs(type(stream["content"]), bytes)
            self.assertIs(type(stream["size_bytes"]), int)
            self.assertIs(type(stream["sha256"]), str)

    def test_report_canonical_hash_preserves_record_list_order(self):
        report, kwargs = inputs()
        output = build_run_evidence(report, **kwargs)
        self.assertEqual(output["records"], report["records"])
        self.assertEqual([r["case_id"] for r in output["records"]], ["z", "a"])
        self.assertEqual(output["report_sha256"], hashlib.sha256(canonical(report)).hexdigest())
        report["records"].reverse()
        changed = build_run_evidence(report, **kwargs)
        self.assertNotEqual(output["report_sha256"], changed["report_sha256"])

    def test_mapping_insertion_order_does_not_change_hashes(self):
        report, kwargs = inputs()
        expected = build_run_evidence(report, **kwargs)
        report = dict(reversed(list(report.items())))
        report["counts"] = dict(reversed(list(report["counts"].items())))
        report["records"] = [dict(reversed(list(record.items()))) for record in report["records"]]
        kwargs["command"] = dict(reversed(list(kwargs["command"].items())))
        self.assertEqual(build_run_evidence(report, **kwargs), expected)

    def test_command_hash_exact_canonical_bytes_and_key_excluded(self):
        report, kwargs = inputs()
        command = kwargs["command"]
        output = build_run_evidence(report, **kwargs)
        entry = output["identity_snapshot"]["artifacts"][0]
        expected = hashlib.sha256(canonical({k: command[k]
                                           for k in ("argv", "cwd", "interpreter")})).hexdigest()
        self.assertEqual(entry, {"kind": "COMMAND", "key": "run/main", "sha256": expected})
        kwargs["command"]["key"] = "another/key"
        changed = build_run_evidence(report, **kwargs)["identity_snapshot"]["artifacts"][0]
        self.assertEqual(changed["sha256"], entry["sha256"])
        self.assertEqual(changed["key"], "another/key")

    def test_every_command_component_affects_hash(self):
        report, kwargs = inputs()
        original = build_run_evidence(report, **kwargs)["identity_snapshot"]["artifacts"][0]["sha256"]
        for field in ("argv", "cwd", "interpreter"):
            with self.subTest(field=field):
                changed = deepcopy(kwargs)
                if field == "argv":
                    changed["command"][field].reverse()
                else:
                    changed["command"][field] += "x"
                actual = build_run_evidence(report, **changed)["identity_snapshot"]["artifacts"][0]["sha256"]
                self.assertNotEqual(actual, original)

    def test_snapshot_sorted_and_test_hashes_use_arbitrary_exact_bytes(self):
        report, kwargs = inputs()
        snapshot = build_run_evidence(report, **kwargs)["identity_snapshot"]
        self.assertEqual([(x["kind"], x["key"]) for x in snapshot["artifacts"]],
                         [("COMMAND", "run/main"), ("TEST", "tests/a.py"), ("TEST", "tests/z.py")])
        expected = {item["key"].lower(): hashlib.sha256(item["content"]).hexdigest()
                    for item in kwargs["test_artifacts"]}
        for item in snapshot["artifacts"][1:]:
            self.assertEqual(item["sha256"], expected[item["key"]])

    def test_raw_outputs_preserve_unicode_crlf_controls_hash_and_size(self):
        report, kwargs = inputs()
        output = build_run_evidence(report, **kwargs)
        for name in ("stdout", "stderr"):
            raw = report[name].encode("utf-8")
            self.assertEqual(output["raw_outputs"][name], {
                "content": raw, "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw),
            })

    def test_no_unicode_or_line_ending_normalization(self):
        report, kwargs = inputs()
        original = build_run_evidence(report, **kwargs)
        for name in ("stdout", "stderr"):
            changed = deepcopy(report)
            changed[name] = changed[name].replace("\r\n", "\n")
            output = build_run_evidence(changed, **kwargs)
            self.assertNotEqual(output["report_sha256"], original["report_sha256"])
            self.assertNotEqual(output["raw_outputs"][name], original["raw_outputs"][name])
        changed = deepcopy(kwargs)
        changed["command"]["argv"][-1] = "Café"
        output = build_run_evidence(report, **changed)
        self.assertNotEqual(output["identity_snapshot"], original["identity_snapshot"])

    def test_input_preserved_and_output_containers_detached(self):
        report, kwargs = inputs()
        before = deepcopy((report, kwargs))
        first = build_run_evidence(report, **kwargs)
        second = build_run_evidence(report, **kwargs)
        expected_second = deepcopy(second)
        self.assertEqual((report, kwargs), before)
        self.assertIsNot(first, second)
        self.assertIsNot(first["records"], report["records"])
        for index, record in enumerate(first["records"]):
            self.assertIsNot(record, report["records"][index])
            self.assertIsNot(record, second["records"][index])
        self.assertIsNot(first["identity_snapshot"], second["identity_snapshot"])
        self.assertIsNot(first["identity_snapshot"]["artifacts"],
                         second["identity_snapshot"]["artifacts"])
        self.assertIsNot(first["raw_outputs"], second["raw_outputs"])
        self.assertIsNot(first["raw_outputs"]["stdout"], second["raw_outputs"]["stdout"])
        first["records"][0]["status"] = "mutated"
        first["identity_snapshot"]["artifacts"][0]["sha256"] = "mutated"
        first["identity_snapshot"]["artifacts"].clear()
        first["raw_outputs"]["stdout"]["content"] = b"mutated"
        self.assertEqual((report, kwargs), before)
        self.assertEqual(second, expected_second)
        report["records"][0]["status"] = "mutated"
        kwargs["command"]["argv"].clear()
        kwargs["test_artifacts"].clear()
        self.assertEqual(second, expected_second)

    def test_nondefault_attempt_preserved_without_latest_attempt_policy(self):
        report, kwargs = inputs()
        first = build_run_evidence(report, **kwargs)
        kwargs["attempt"] = 2
        for record in report["records"]:
            record["attempt"] = 2
        second = build_run_evidence(report, **kwargs)
        self.assertTrue(all(record["attempt"] == 7 for record in first["records"]))
        self.assertTrue(all(record["attempt"] == 2 for record in second["records"]))
        self.assertNotEqual(first["report_sha256"], second["report_sha256"])

    def test_import_and_call_have_no_own_io_environment_clock_or_process(self):
        source = (Path(__file__).resolve().parents[1] / "source" / "audit_release" /
                  "command_evidence.py").read_text(encoding="utf-8")
        code = compile(source, "command_evidence.py", "exec")
        report, kwargs = inputs()

        def forbidden(*args, **kwargs):
            raise AssertionError("Forbidden own side effect")

        class Environment(dict):
            def __getitem__(self, key):
                forbidden()

            def get(self, *args, **kwargs):
                forbidden()

        with ExitStack() as stack:
            for target in ("builtins.open", "builtins.print", "socket.socket",
                           "subprocess.Popen", "subprocess.run", "os.open", "os.getenv",
                           "os.listdir", "os.scandir", "os.getcwd", "time.time",
                           "time.monotonic", "time.perf_counter"):
                stack.enter_context(patch(target, side_effect=forbidden))
            stack.enter_context(patch.object(os, "environ", Environment()))
            for method in ("open", "read_bytes", "read_text", "write_bytes", "write_text",
                           "stat", "lstat", "resolve", "exists", "is_file", "is_dir",
                           "iterdir", "glob", "rglob", "cwd"):
                stack.enter_context(patch.object(Path, method, side_effect=forbidden))
            namespace = {"__name__": "audit_release.candidate_import_check",
                         "__package__": "audit_release"}
            exec(code, namespace)
            actual = namespace["build_run_evidence"](report, **kwargs)
        self.assertEqual(actual["records"], report["records"])


if __name__ == "__main__":
    unittest.main()
