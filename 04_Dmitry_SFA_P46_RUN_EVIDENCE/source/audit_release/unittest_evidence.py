"""Record actual unittest callbacks as per-case F1-27 evidence.

This result never runs tests or decides release readiness. The trusted runner
owns execution, source identity and the relationship of bindings to its plan.
"""

import re
import unittest


_IDENTIFIER = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_BINDING_FIELDS = frozenset(("test_id", "suite_id", "case_id"))


class RecordingError(ValueError):
    """Contract error containing a public code only, never caller data."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _is_identifier(value):
    return type(value) is str and _IDENTIFIER.fullmatch(value) is not None


def _is_test_id(value):
    return (
        type(value) is str
        and 1 <= len(value) <= 512
        and not any(
            char.isspace() or ord(char) < 32 or ord(char) == 127
            or 0xD800 <= ord(char) <= 0xDFFF
            for char in value
        )
    )


def _copy_bindings(release_id, bindings, attempt):
    if (
        not _is_identifier(release_id)
        or type(attempt) is not int or attempt < 1
        or type(bindings) is not list or len(bindings) > 10000
    ):
        raise RecordingError("INVALID_CONFIGURATION")
    copied = {}
    pairs = set()
    for binding in bindings:
        if (
            type(binding) is not dict
            or any(type(key) is not str for key in binding)
            or binding.keys() != _BINDING_FIELDS
        ):
            raise RecordingError("INVALID_CONFIGURATION")
        test_id, suite_id, case_id = (
            binding["test_id"], binding["suite_id"], binding["case_id"]
        )
        if (
            not _is_test_id(test_id)
            or not _is_identifier(suite_id)
            or not _is_identifier(case_id)
        ):
            raise RecordingError("INVALID_CONFIGURATION")
        pair = (suite_id, case_id)
        if test_id in copied or pair in pairs:
            raise RecordingError("INVALID_CONFIGURATION")
        copied[test_id] = pair
        pairs.add(pair)
    return copied


class RecordingResult(unittest.TestResult):
    """Sequential callback recorder with an irreversible invalid-run latch."""

    def __init__(self, *, release_id, bindings, attempt=1):
        copied = _copy_bindings(release_id, bindings, attempt)
        super().__init__()
        self._release_id = release_id
        self._bindings = copied
        self._attempt = attempt
        self._started = set()
        self._active = None
        self._outcome = None
        self._completed = {}
        self._invalid = False

    def _identify(self, test):
        # Only errors from the supplied id() are normalized. In particular,
        # MemoryError is an Exception subclass and must be re-raised explicitly.
        try:
            test_id = test.id()
        except MemoryError:
            raise
        except Exception:
            self._invalid = True
            return None
        if not _is_test_id(test_id) or test_id not in self._bindings:
            self._invalid = True
            return None
        return test_id

    def startTest(self, test):
        test_id = self._identify(test)
        if test_id is not None:
            if self._active is not None or test_id in self._started:
                self._invalid = True
            else:
                self._started.add(test_id)
                self._active = test_id
                self._outcome = None
        super().startTest(test)

    def _terminal(self, test, status, exit_code, skip_count):
        test_id = self._identify(test)
        if test_id is None:
            return
        if self._active != test_id or self._outcome is not None:
            self._invalid = True
            return
        self._outcome = (status, exit_code, skip_count)

    def stopTest(self, test):
        # Restore standard buffered output even when the callback's id is bad.
        super().stopTest(test)
        test_id = self._identify(test)
        if test_id is None:
            return
        if self._active != test_id or self._outcome is None:
            self._invalid = True
            return
        self._completed[test_id] = self._outcome
        self._active = None
        self._outcome = None

    def addSuccess(self, test):
        super().addSuccess(test)
        self._terminal(test, "PASS", 0, 0)

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self._terminal(test, "FAIL", 1, 0)

    def addError(self, test, err):
        super().addError(test, err)
        self._terminal(test, "ERROR", 1, 0)

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self._terminal(test, "SKIP", 0, 1)

    def addSubTest(self, test, subtest, err):
        self._invalid = True
        super().addSubTest(test, subtest, err)

    def addExpectedFailure(self, test, err):
        self._invalid = True
        super().addExpectedFailure(test, err)

    def addUnexpectedSuccess(self, test):
        self._invalid = True
        super().addUnexpectedSuccess(test)

    def records(self):
        if self._invalid or self._active is not None:
            self._invalid = True
            raise RecordingError("INVALID_EXECUTION")
        result = []
        for test_id in sorted(self._completed, key=self._bindings.__getitem__):
            suite_id, case_id = self._bindings[test_id]
            status, exit_code, skip_count = self._completed[test_id]
            result.append({
                "release_id": self._release_id,
                "suite_id": suite_id,
                "case_id": case_id,
                "attempt": self._attempt,
                "status": status,
                "exit_code": exit_code,
                "skip_count": skip_count,
            })
        return result
