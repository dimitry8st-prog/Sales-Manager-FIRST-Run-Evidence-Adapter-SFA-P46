"""Настоящие зависимости P23/P46/P47, без имитации их результатов."""

from copy import deepcopy
import hashlib
import sys
import unittest

from audit_release.command_evidence import build_run_evidence
from audit_release.test_applicability import assess_applicability
from audit_release.unittest_evidence import RecordingResult
from qa_completion.offline.unittest_runner import run_suite


def make_case(case_id, outcome, calls):
    class ActualCase(unittest.TestCase):
        def id(self):
            return f"actual.{case_id}"

        def runTest(self):
            calls.append(case_id)
            print(f"вывод:{case_id}")
            print(f"диагностика:{case_id}", file=sys.stderr)
            if outcome == "FAIL":
                self.fail("actual failed assertion")
            if outcome == "ERROR":
                raise RuntimeError("actual error")
            if outcome == "SKIP":
                self.skipTest("actual skip")

    return ActualCase()


def configuration(case_ids):
    return {
        "release_id": "real-release", "attempt": 3,
        "bindings": [{"test_id": f"actual.{case_id}", "suite_id": "real-suite",
                      "case_id": case_id} for case_id in case_ids],
        "command": {"key": "Runs/Actual", "argv": ["python", "RUN.py"],
                    "cwd": ".", "interpreter": "Python 3.12"},
        "test_artifacts": [{"key": "Tests/Actual.py", "content": b"assert True\r\n"}],
    }


def runner_report(suite, config, **options):
    return run_suite(suite, release_id=config["release_id"], bindings=config["bindings"],
                     attempt=config["attempt"], result_factory=RecordingResult, **options)


def full_snapshot(snapshot):
    result = deepcopy(snapshot)
    for kind in ("SOURCE", "SCHEMA", "CONFIG", "DEPENDENCY", "RUNTIME"):
        result["artifacts"].append({"kind": kind, "key": "trusted/pin",
                                    "sha256": hashlib.sha256(kind.encode()).hexdigest()})
    return result


def assess(before, after):
    pins = [{"kind": item["kind"], "key": item["key"]} for item in before["artifacts"]]
    cases = [{"case_id": "consumer", "before_required": pins,
              "after_required": deepcopy(pins), "footprint_complete": True}]
    return assess_applicability(before, after, cases)["cases"][0]


class RealIntegrationTests(unittest.TestCase):
    def test_real_p23_p46_mixed_four_statuses_execute_exactly_once(self):
        case_ids = ["success", "failure", "error", "skip"]
        outcomes = ["PASS", "FAIL", "ERROR", "SKIP"]
        calls = []
        config = configuration(case_ids)
        before = deepcopy(config)
        suite = unittest.TestSuite([
            unittest.TestSuite([make_case(case_ids[0], outcomes[0], calls)]),
            unittest.TestSuite([make_case(case_id, outcome, calls)
                                for case_id, outcome in zip(case_ids[1:], outcomes[1:])]),
        ])
        report = runner_report(suite, config)
        self.assertEqual(report["counts"], {"tests_run": 4, "failures": 1, "errors": 1, "skips": 1})
        report_before = deepcopy(report)
        output = build_run_evidence(report, **config)
        self.assertEqual(calls, case_ids)
        self.assertEqual(config, before)
        self.assertEqual(report, report_before)
        self.assertEqual(output["records"], report["records"])
        by_case = {record["case_id"]: record for record in output["records"]}
        for case_id, outcome in zip(case_ids, outcomes):
            self.assertEqual(by_case[case_id]["status"], outcome)
            self.assertEqual(by_case[case_id]["attempt"], 3)
        self.assertEqual(output["raw_outputs"]["stdout"]["content"],
                         "".join(f"вывод:{case_id}\n" for case_id in case_ids).encode())
        self.assertEqual(output["raw_outputs"]["stderr"]["content"],
                         "".join(f"диагностика:{case_id}\n" for case_id in case_ids).encode())

    def test_real_failfast_preserves_only_visited_case_without_invented_pass(self):
        calls = []
        config = configuration(["failed", "unvisited"])
        suite = unittest.TestSuite([make_case("failed", "FAIL", calls),
                                    make_case("unvisited", "PASS", calls)])
        report = runner_report(suite, config, failfast=True)
        output = build_run_evidence(report, **config)
        self.assertEqual(calls, ["failed"])
        self.assertEqual(len(output["records"]), 1)
        self.assertEqual(output["records"][0]["case_id"], "failed")
        self.assertEqual(output["records"][0]["status"], "FAIL")
        self.assertEqual(report["counts"], {"tests_run": 1, "failures": 1, "errors": 0, "skips": 0})

    def test_real_empty_suite_does_not_become_general_pass(self):
        config = configuration([])
        report = runner_report(unittest.TestSuite(), config)
        output = build_run_evidence(report, **config)
        self.assertEqual(output["records"], [])
        self.assertEqual(output["raw_outputs"]["stdout"]["content"], b"")
        self.assertEqual(output["raw_outputs"]["stderr"]["content"], b"")
        self.assertNotIn("PASS", output)
        self.assertIs(output["gate_acceptance"], False)
        self.assertIs(output["external_effect_authorized"], False)

    def test_empty_report_can_have_unvisited_bindings(self):
        config = configuration(["unvisited"])
        report = {"schema_version": "FIRST_OFFLINE_UNITTEST_RUN_V1", "records": [],
                  "counts": {"tests_run": 0, "failures": 0, "errors": 0, "skips": 0},
                  "stdout": "", "stderr": ""}
        self.assertEqual(build_run_evidence(report, **config)["records"], [])

    def real_output(self):
        calls = []
        config = configuration(["success"])
        report = runner_report(unittest.TestSuite([make_case("success", "PASS", calls)]), config)
        return report, config, build_run_evidence(report, **config)

    def test_real_p47_equal_partial_identity_is_unknown(self):
        _, _, output = self.real_output()
        result = assess(output["identity_snapshot"], output["identity_snapshot"])
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual(result["missing_dimensions"],
                         sorted(["SOURCE", "SCHEMA", "CONFIG", "DEPENDENCY", "RUNTIME"]))
        self.assertEqual(result["changed"], [])

    def test_real_p47_full_dimensions_match(self):
        _, _, output = self.real_output()
        snapshot = full_snapshot(output["identity_snapshot"])
        result = assess(snapshot, snapshot)
        self.assertEqual(result["status"], "MATCH")
        self.assertEqual(result["missing_dimensions"], [])
        self.assertEqual(result["unknown"], [])

    def test_real_p47_changed_command_is_affected(self):
        report, config, output = self.real_output()
        config["command"]["argv"].append("--changed")
        current = build_run_evidence(report, **config)
        result = assess(full_snapshot(output["identity_snapshot"]),
                        full_snapshot(current["identity_snapshot"]))
        self.assertEqual(result["status"], "CHANGED_AFFECTED")
        self.assertEqual([(x["kind"], x["key"], x["reason"]) for x in result["changed"]],
                         [("COMMAND", "runs/actual", "HASH_CHANGED")])

    def test_real_p47_changed_test_bytes_are_affected(self):
        report, config, output = self.real_output()
        config["test_artifacts"][0]["content"] += b"# changed\n"
        current = build_run_evidence(report, **config)
        result = assess(full_snapshot(output["identity_snapshot"]),
                        full_snapshot(current["identity_snapshot"]))
        self.assertEqual(result["status"], "CHANGED_AFFECTED")
        self.assertEqual([(x["kind"], x["key"], x["reason"]) for x in result["changed"]],
                         [("TEST", "tests/actual.py", "HASH_CHANGED")])

    def test_known_changed_identity_takes_priority_over_missing_dimensions(self):
        report, config, output = self.real_output()
        config["test_artifacts"][0]["content"] += b"changed"
        current = build_run_evidence(report, **config)
        result = assess(output["identity_snapshot"], current["identity_snapshot"])
        self.assertEqual(result["status"], "CHANGED_AFFECTED")
        self.assertEqual(len(result["missing_dimensions"]), 5)


if __name__ == "__main__":
    unittest.main()
