"""Проверки входного контракта SFA-P46-RUN-EVIDENCE R1."""

from copy import deepcopy
import unittest
from unittest.mock import patch

from audit_release.command_evidence import RunEvidenceError, build_run_evidence
from audit_release.unittest_evidence import RecordingError, RecordingResult


class StringSubclass(str):
    pass


class IntegerSubclass(int):
    pass


class ListSubclass(list):
    pass


class DictSubclass(dict):
    pass


class BytesSubclass(bytes):
    pass


def inputs():
    report = {
        "schema_version": "FIRST_OFFLINE_UNITTEST_RUN_V1",
        "records": [{
            "release_id": "release", "suite_id": "suite", "case_id": "case",
            "attempt": 1, "status": "PASS", "exit_code": 0, "skip_count": 0,
        }],
        "counts": {"tests_run": 1, "failures": 0, "errors": 0, "skips": 0},
        "stdout": "", "stderr": "",
    }
    kwargs = {
        "release_id": "release",
        "bindings": [{"test_id": "tests.case", "suite_id": "suite", "case_id": "case"}],
        "command": {"key": "run/main", "argv": ["python", "RUN.py"],
                    "cwd": ".", "interpreter": "Python 3.12"},
        "test_artifacts": [{"key": "tests/unit.py", "content": b"pass\n"}],
    }
    return report, kwargs


class ValidationTests(unittest.TestCase):
    def reject(self, report, kwargs):
        with self.assertRaises(RunEvidenceError) as caught:
            build_run_evidence(report, **kwargs)
        self.assertIs(type(caught.exception.code), str)
        self.assertEqual(caught.exception.code, "INVALID_INPUT")
        self.assertEqual(str(caught.exception), "INVALID_INPUT")

    def test_error_is_value_error(self):
        self.assertTrue(issubclass(RunEvidenceError, ValueError))

    def test_configuration_reuses_recording_validation_and_cause(self):
        configurations = [
            {"release_id": ""}, {"release_id": StringSubclass("release")},
            {"attempt": 0}, {"attempt": -1}, {"attempt": True},
            {"attempt": 1.0}, {"attempt": IntegerSubclass(1)},
            {"bindings": ()}, {"bindings": ListSubclass()},
            {"bindings": [{"test_id": "a", "suite_id": "s", "case_id": "c"},
                          {"test_id": "b", "suite_id": "s", "case_id": "c"}]},
            {"bindings": [{"test_id": "a", "suite_id": "s", "case_id": "a"},
                          {"test_id": "a", "suite_id": "s", "case_id": "b"}]},
        ]
        for changes in configurations:
            with self.subTest(changes=changes):
                report, kwargs = inputs()
                kwargs.update(changes)
                with self.assertRaises(RunEvidenceError) as caught:
                    build_run_evidence(report, **kwargs)
                error = caught.exception
                self.assertEqual(error.code, "INVALID_INPUT")
                self.assertEqual(str(error), "INVALID_INPUT")
                self.assertIsInstance(error.__cause__, RecordingError)
                self.assertEqual(error.__cause__.code, "INVALID_CONFIGURATION")

    def test_constructor_is_used_without_running_tests(self):
        report, kwargs = inputs()
        original = RecordingResult.__init__
        calls = []

        def observe(instance, **configuration):
            calls.append(deepcopy(configuration))
            return original(instance, **configuration)

        with patch.object(RecordingResult, "__init__", observe), patch.object(
            RecordingResult, "startTest", side_effect=AssertionError("test executed")
        ), patch.object(
            RecordingResult, "startTestRun", side_effect=AssertionError("run started")
        ):
            build_run_evidence(report, **kwargs)
        self.assertEqual(calls, [{"release_id": "release", "bindings": kwargs["bindings"],
                                  "attempt": 1}])

    def test_recording_error_keeps_original_exception_identity(self):
        report, kwargs = inputs()
        original = RecordingError("INVALID_CONFIGURATION")
        with patch.object(RecordingResult, "__init__", side_effect=original):
            with self.assertRaises(RunEvidenceError) as caught:
                build_run_evidence(report, **kwargs)
        self.assertEqual(str(caught.exception), "INVALID_INPUT")
        self.assertIs(caught.exception.__cause__, original)

    def test_unexpected_constructor_exceptions_are_not_masked(self):
        for error in (RuntimeError("sentinel"), MemoryError("sentinel"),
                      KeyboardInterrupt(), SystemExit(8), ValueError("unexpected")):
            with self.subTest(kind=type(error).__name__):
                report, kwargs = inputs()
                with patch.object(RecordingResult, "__init__", side_effect=error):
                    with self.assertRaises(type(error)) as caught:
                        build_run_evidence(report, **kwargs)
                self.assertIs(caught.exception, error)

    def test_configuration_identifier_boundaries_and_unicode_test_id(self):
        report, kwargs = inputs()
        kwargs["release_id"] = "r" * 128
        kwargs["attempt"] = 123456789
        kwargs["bindings"] = [{"test_id": "я" * 512,
                               "suite_id": "s" * 128, "case_id": "c" * 128}]
        report["records"][0].update(release_id=kwargs["release_id"],
                                     attempt=kwargs["attempt"],
                                     suite_id="s" * 128, case_id="c" * 128)
        self.assertEqual(build_run_evidence(report, **kwargs)["records"], report["records"])

    def test_binding_configuration_invalid_shapes_and_limits_keep_cause(self):
        template = {"test_id": "tests.case", "suite_id": "suite", "case_id": "case"}
        bad_bindings = [
            [None], [DictSubclass(template)], [dict(template, extra=1)],
            [{"test_id": "tests.case", "suite_id": "suite"}],
            [{StringSubclass(k) if k == "test_id" else k: v for k, v in template.items()}],
            [dict(template, test_id="x" * 513)], [dict(template, test_id="bad id")],
            [dict(template, test_id="a\ud800")], [dict(template, suite_id="s" * 129)],
            [dict(template, case_id="c" * 129)],
            [dict(template, case_id="кириллица")],
            [{"test_id": f"t{i}", "suite_id": "s", "case_id": f"c{i}"}
             for i in range(10001)],
        ]
        for index, bindings in enumerate(bad_bindings):
            with self.subTest(configuration=index):
                report, kwargs = inputs()
                kwargs["bindings"] = bindings
                with self.assertRaises(RunEvidenceError) as caught:
                    build_run_evidence(report, **kwargs)
                self.assertEqual(str(caught.exception), "INVALID_INPUT")
                self.assertIsInstance(caught.exception.__cause__, RecordingError)

    def test_report_exact_type_and_fields(self):
        report, kwargs = inputs()
        for value in (None, [], DictSubclass(report)):
            with self.subTest(value_type=type(value).__name__):
                self.reject(value, kwargs)
        for field in report:
            value = deepcopy(report)
            del value[field]
            with self.subTest(missing=field):
                self.reject(value, kwargs)
        value = deepcopy(report)
        value["extra"] = None
        self.reject(value, kwargs)
        value = {StringSubclass(k) if k == "stdout" else k: v for k, v in report.items()}
        self.reject(value, kwargs)

    def test_schema_exact_value_and_type(self):
        for value in ("OTHER", None, 1, StringSubclass("FIRST_OFFLINE_UNITTEST_RUN_V1")):
            with self.subTest(value=value):
                report, kwargs = inputs()
                report["schema_version"] = value
                self.reject(report, kwargs)

    def test_records_exact_container_and_limit(self):
        for value in (None, (), {}, ListSubclass()):
            with self.subTest(kind=type(value).__name__):
                report, kwargs = inputs()
                report["records"] = value
                self.reject(report, kwargs)
        report, kwargs = inputs()
        report["records"] *= 10001
        report["counts"]["tests_run"] = 10001
        self.reject(report, kwargs)

    def test_records_and_bindings_allow_exactly_ten_thousand(self):
        report, kwargs = inputs()
        kwargs["bindings"] = [
            {"test_id": f"tests.c{i}", "suite_id": "suite", "case_id": f"c{i}"}
            for i in range(10000)
        ]
        template = report["records"][0]
        report["records"] = [dict(template, case_id=f"c{i}") for i in range(10000)]
        report["counts"]["tests_run"] = 10000
        output = build_run_evidence(report, **kwargs)
        self.assertEqual(output["records"], report["records"])

    def test_record_exact_type_and_fields(self):
        report, kwargs = inputs()
        original = report["records"][0]
        for value in (None, [], DictSubclass(original)):
            with self.subTest(kind=type(value).__name__):
                changed = deepcopy(report)
                changed["records"] = [value]
                self.reject(changed, kwargs)
        for field in original:
            with self.subTest(missing=field):
                changed = deepcopy(report)
                del changed["records"][0][field]
                self.reject(changed, kwargs)
        for value in (dict(original, extra=1),
                      {StringSubclass(k) if k == "status" else k: v
                       for k, v in original.items()}):
            changed = deepcopy(report)
            changed["records"] = [value]
            self.reject(changed, kwargs)

    def test_record_identifiers_attempt_and_exact_types(self):
        changes = {
            "release_id": ["other", None, StringSubclass("release")],
            "suite_id": ["other", None, StringSubclass("suite")],
            "case_id": ["other", None, StringSubclass("case")],
            "attempt": [2, True, 1.0, IntegerSubclass(1)],
            "status": ["UNKNOWN", None, StringSubclass("PASS")],
            "exit_code": [True, 0.0, IntegerSubclass(0), -1],
            "skip_count": [False, 0.0, IntegerSubclass(0), -1],
        }
        for field, values in changes.items():
            for value in values:
                with self.subTest(field=field, value_type=type(value).__name__, value=value):
                    report, kwargs = inputs()
                    report["records"][0][field] = value
                    self.reject(report, kwargs)

    def test_status_triplets_are_exact(self):
        valid = {"PASS": (0, 0), "FAIL": (1, 0), "ERROR": (1, 0), "SKIP": (0, 1)}
        for status, pair in valid.items():
            for exit_code in (0, 1, 2):
                for skip_count in (0, 1, 2):
                    with self.subTest(status=status, exit_code=exit_code, skip_count=skip_count):
                        report, kwargs = inputs()
                        record = report["records"][0]
                        record.update(status=status, exit_code=exit_code, skip_count=skip_count)
                        report["counts"].update(failures=int(status == "FAIL"),
                                                errors=int(status == "ERROR"),
                                                skips=int(status == "SKIP"))
                        if (exit_code, skip_count) == pair:
                            self.assertEqual(build_run_evidence(report, **kwargs)["records"],
                                             report["records"])
                        else:
                            self.reject(report, kwargs)

    def test_duplicate_or_unbound_record_pair_rejected(self):
        report, kwargs = inputs()
        report["records"].append(deepcopy(report["records"][0]))
        report["counts"]["tests_run"] = 2
        self.reject(report, kwargs)
        report, kwargs = inputs()
        kwargs["bindings"] = []
        self.reject(report, kwargs)

    def test_counts_exact_type_fields_values_and_consistency(self):
        report, kwargs = inputs()
        for value in (None, [], DictSubclass(report["counts"])):
            with self.subTest(kind=type(value).__name__):
                changed = deepcopy(report)
                changed["counts"] = value
                self.reject(changed, kwargs)
        for field in report["counts"]:
            for value in (True, -1, 0.0, None, IntegerSubclass(report["counts"][field])):
                with self.subTest(field=field, value=value):
                    changed = deepcopy(report)
                    changed["counts"][field] = value
                    self.reject(changed, kwargs)
            changed = deepcopy(report)
            del changed["counts"][field]
            self.reject(changed, kwargs)
            changed = deepcopy(report)
            changed["counts"][field] += 1
            self.reject(changed, kwargs)
        changed = deepcopy(report)
        changed["counts"]["extra"] = 0
        self.reject(changed, kwargs)
        changed = deepcopy(report)
        changed["counts"] = {StringSubclass(k) if k == "errors" else k: v
                             for k, v in report["counts"].items()}
        self.reject(changed, kwargs)

    def test_output_text_exact_type_and_surrogates(self):
        for field in ("stdout", "stderr"):
            for value in (None, b"text", 0, StringSubclass("text"), "\ud800", "a\udfff"):
                with self.subTest(field=field, kind=type(value).__name__):
                    report, kwargs = inputs()
                    report[field] = value
                    self.reject(report, kwargs)

    def test_output_byte_limits_independent_per_stream(self):
        limit = 4194304
        report, kwargs = inputs()
        report["stdout"] = "я" * (limit // 2)
        report["stderr"] = "x" * limit
        output = build_run_evidence(report, **kwargs)
        self.assertEqual(output["raw_outputs"]["stdout"]["size_bytes"], limit)
        self.assertEqual(output["raw_outputs"]["stderr"]["size_bytes"], limit)
        for field in ("stdout", "stderr"):
            with self.subTest(field=field):
                changed = deepcopy(report)
                changed[field] += "x"
                self.reject(changed, kwargs)

    def test_command_exact_type_and_fields(self):
        report, kwargs = inputs()
        original = kwargs["command"]
        for value in (None, [], DictSubclass(original)):
            with self.subTest(kind=type(value).__name__):
                changed = deepcopy(kwargs)
                changed["command"] = value
                self.reject(report, changed)
        for field in original:
            changed = deepcopy(kwargs)
            del changed["command"][field]
            self.reject(report, changed)
        changed = deepcopy(kwargs)
        changed["command"]["extra"] = 1
        self.reject(report, changed)
        changed = deepcopy(kwargs)
        changed["command"] = {StringSubclass(k) if k == "key" else k: v
                              for k, v in original.items()}
        self.reject(report, changed)

    def test_argv_exact_container_count_and_members(self):
        for value in (None, (), [], ListSubclass(["python"]), [None], [0],
                      [""], [StringSubclass("python")], ["a"] * 257):
            with self.subTest(kind=type(value).__name__, count=len(value) if value else 0):
                report, kwargs = inputs()
                kwargs["command"]["argv"] = value
                self.reject(report, kwargs)
        report, kwargs = inputs()
        kwargs["command"]["argv"] = ["x"] * 256
        build_run_evidence(report, **kwargs)

    def test_command_string_character_limits_and_forbidden_characters(self):
        for field in ("argv", "cwd", "interpreter"):
            for value in (None, 0, "", StringSubclass("x"), "x" * 4097,
                          "a\x00b", "a\x1fb", "a\x7fb", "a\ud800b", "a\udfffb"):
                with self.subTest(field=field, kind=type(value).__name__):
                    report, kwargs = inputs()
                    kwargs["command"][field] = [value] if field == "argv" else value
                    self.reject(report, kwargs)
            report, kwargs = inputs()
            value = "я" * 4096
            kwargs["command"][field] = [value] if field == "argv" else value
            build_run_evidence(report, **kwargs)

    def test_all_c0_command_controls_rejected(self):
        for field in ("argv", "cwd", "interpreter"):
            for code in list(range(32)) + [127]:
                with self.subTest(field=field, code=code):
                    report, kwargs = inputs()
                    value = "x" + chr(code)
                    kwargs["command"][field] = [value] if field == "argv" else value
                    self.reject(report, kwargs)

    def test_artifact_keys_invalid_types_paths_and_windows_names(self):
        invalid = [None, 1, StringSubclass("valid"), "", "/a", "a/", "a//b", ".", "..",
                   "a/./b", "a/../b", "a.", "a./b", "a\\b", "a:b", "тест", "a b",
                   "a\x00b", "a" * 2049]
        reserved = ["CON", "PRN", "AUX", "NUL"] + [f"COM{i}" for i in range(1, 10)]
        reserved += [f"LPT{i}" for i in range(1, 10)]
        invalid += [f"a/{name.lower()}.txt" for name in reserved]
        invalid += reserved
        for value in invalid:
            for location in ("command", "test_artifacts"):
                with self.subTest(location=location, value_type=type(value).__name__, value=value):
                    report, kwargs = inputs()
                    if location == "command":
                        kwargs["command"]["key"] = value
                    else:
                        kwargs["test_artifacts"][0]["key"] = value
                    self.reject(report, kwargs)

    def test_artifact_key_limits_valid_names_and_cross_kind_collision(self):
        for key in ("a" * 2048, "a-b/C_d/file.ext", "COM0", "COM10", "LPT10", ".hidden"):
            with self.subTest(key=key[:40]):
                report, kwargs = inputs()
                kwargs["command"]["key"] = key
                kwargs["test_artifacts"][0]["key"] = key.upper()
                output = build_run_evidence(report, **kwargs)
                self.assertEqual([(x["kind"], x["key"]) for x in output["identity_snapshot"]["artifacts"]],
                                 [("COMMAND", key.lower()), ("TEST", key.lower())])

    def test_artifact_list_and_records_exact_types_and_fields(self):
        report, kwargs = inputs()
        for value in (None, (), ListSubclass()):
            changed = deepcopy(kwargs)
            changed["test_artifacts"] = value
            self.reject(report, changed)
        original = kwargs["test_artifacts"][0]
        for value in (None, [], DictSubclass(original), {"key": "a"}, {"content": b""},
                      dict(original, extra=1),
                      {StringSubclass(k) if k == "content" else k: v
                       for k, v in original.items()}):
            changed = deepcopy(kwargs)
            changed["test_artifacts"] = [value]
            self.reject(report, changed)

    def test_artifact_content_exact_bytes(self):
        for value in (None, "text", bytearray(b"text"), memoryview(b"text"), BytesSubclass(b"text")):
            with self.subTest(kind=type(value).__name__):
                report, kwargs = inputs()
                kwargs["test_artifacts"][0]["content"] = value
                self.reject(report, kwargs)

    def test_artifact_count_and_empty_artifacts(self):
        report, kwargs = inputs()
        kwargs["test_artifacts"] = []
        self.assertEqual(len(build_run_evidence(report, **kwargs)["identity_snapshot"]["artifacts"]), 1)
        kwargs["test_artifacts"] = [{"key": f"tests/{i}", "content": b""} for i in range(256)]
        self.assertEqual(len(build_run_evidence(report, **kwargs)["identity_snapshot"]["artifacts"]), 257)
        kwargs["test_artifacts"].append({"key": "tests/overflow", "content": b""})
        self.reject(report, kwargs)

    def test_artifact_duplicates_case_insensitive(self):
        for key in ("tests/unit.py", "TESTS/UNIT.PY", "Tests/Unit.py"):
            report, kwargs = inputs()
            kwargs["test_artifacts"].append({"key": key, "content": b"different"})
            self.reject(report, kwargs)

    def test_artifact_individual_and_total_byte_limits(self):
        limit = 4194304
        report, kwargs = inputs()
        kwargs["test_artifacts"] = [{"key": "a", "content": b"x" * limit},
                                     {"key": "b", "content": b"y" * limit}]
        self.assertEqual(len(build_run_evidence(report, **kwargs)["identity_snapshot"]["artifacts"]), 3)
        kwargs["test_artifacts"].append({"key": "c", "content": b"z"})
        self.reject(report, kwargs)
        kwargs["test_artifacts"] = [{"key": "a", "content": b"x" * (limit + 1)}]
        self.reject(report, kwargs)


if __name__ == "__main__":
    unittest.main()
