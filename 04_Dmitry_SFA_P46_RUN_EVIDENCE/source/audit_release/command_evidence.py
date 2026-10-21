"""Связать переданный отчёт P23 с байтами COMMAND/TEST без выполнения и I/O.

Хеши описывают полученные данные. Происхождение отчёта и доверие к запуску
обеспечивает внешний вызывающий код, а применимость снимка оценивает P47.
"""

import hashlib
import json
import re

from audit_release.unittest_evidence import RecordingError, RecordingResult


_REPORT_FIELDS = frozenset(("schema_version", "records", "counts", "stdout", "stderr"))
_RECORD_FIELDS = (
    "release_id", "suite_id", "case_id", "attempt", "status", "exit_code", "skip_count",
)
_RECORD_FIELD_SET = frozenset(_RECORD_FIELDS)
_COUNT_FIELDS = frozenset(("tests_run", "failures", "errors", "skips"))
_COMMAND_FIELDS = frozenset(("key", "argv", "cwd", "interpreter"))
_TEST_FIELDS = frozenset(("key", "content"))
_OUTCOMES = {"PASS": (0, 0), "FAIL": (1, 0), "ERROR": (1, 0), "SKIP": (0, 1)}
_KEY_SEGMENT = re.compile(r"[A-Za-z0-9_.-]+")
_RESERVED = frozenset(
    ("CON", "PRN", "AUX", "NUL")
    + tuple("COM%d" % number for number in range(1, 10))
    + tuple("LPT%d" % number for number in range(1, 10))
)
_MAX_BYTES = 4_194_304


class RunEvidenceError(ValueError):
    """Ошибка входа с публичным кодом, без содержимого входных данных."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _invalid():
    raise RunEvidenceError("INVALID_INPUT")


def _exact_fields(value, fields):
    # Проверяем тип ключа до сравнения: подклассы и чужие __eq__ не нужны.
    if type(value) is not dict or len(value) != len(fields):
        _invalid()
    for key in value:
        if type(key) is not str or key not in fields:
            _invalid()


def _sha256(content):
    return hashlib.sha256(content).hexdigest()


def _canonical_sha256(value):
    raw = json.dumps(
        value, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")
    return _sha256(raw)


def _output_bytes(value):
    if type(value) is not str:
        _invalid()
    try:
        raw = value.encode("utf-8")
    except UnicodeEncodeError:
        raise RunEvidenceError("INVALID_INPUT") from None
    if len(raw) > _MAX_BYTES:
        _invalid()
    return raw


def _check_report(report, release_id, bindings, attempt):
    _exact_fields(report, _REPORT_FIELDS)
    version = report["schema_version"]
    if type(version) is not str or version != "FIRST_OFFLINE_UNITTEST_RUN_V1":
        _invalid()
    records = report["records"]
    if type(records) is not list or len(records) > 10_000:
        _invalid()
    counts = report["counts"]
    _exact_fields(counts, _COUNT_FIELDS)
    if any(type(value) is not int or value < 0 for value in counts.values()):
        _invalid()

    allowed = {(item["suite_id"], item["case_id"]) for item in bindings}
    seen = set()
    actual = {"tests_run": len(records), "failures": 0, "errors": 0, "skips": 0}
    count_names = {"FAIL": "failures", "ERROR": "errors", "SKIP": "skips"}
    copied = []
    for record in records:
        _exact_fields(record, _RECORD_FIELD_SET)
        if (
            type(record["release_id"]) is not str
            or record["release_id"] != release_id
            or type(record["attempt"]) is not int
            or record["attempt"] != attempt
            or type(record["suite_id"]) is not str
            or type(record["case_id"]) is not str
        ):
            _invalid()
        pair = (record["suite_id"], record["case_id"])
        if pair not in allowed or pair in seen:
            _invalid()
        seen.add(pair)
        status = record["status"]
        if (
            type(status) is not str or status not in _OUTCOMES
            or type(record["exit_code"]) is not int
            or type(record["skip_count"]) is not int
            or (record["exit_code"], record["skip_count"]) != _OUTCOMES[status]
        ):
            _invalid()
        if status in count_names:
            actual[count_names[status]] += 1
        # Порядок входного списка сохраняется, отсутствующие случаи не добавляем.
        copied.append({field: record[field] for field in _RECORD_FIELDS})
    if counts != actual:
        _invalid()
    return copied, {
        name: _output_bytes(report[name]) for name in ("stdout", "stderr")
    }


def _artifact_key(value):
    if type(value) is not str or not 1 <= len(value) <= 2048 or not value.isascii():
        _invalid()
    for segment in value.split("/"):
        if (
            _KEY_SEGMENT.fullmatch(segment) is None
            or segment in (".", "..") or segment.endswith(".")
            or segment.split(".", 1)[0].upper() in _RESERVED
        ):
            _invalid()
    return value.lower()


def _command_text(value):
    if (
        type(value) is not str or not 1 <= len(value) <= 4096
        or any(
            ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF
            for char in value
        )
    ):
        _invalid()


def _command_artifact(command):
    _exact_fields(command, _COMMAND_FIELDS)
    key = _artifact_key(command["key"])
    argv = command["argv"]
    if type(argv) is not list or not 1 <= len(argv) <= 256:
        _invalid()
    for value in argv:
        _command_text(value)
    _command_text(command["cwd"])
    _command_text(command["interpreter"])
    # key — адрес артефакта, а хеш относится только к описанию команды.
    description = {name: command[name] for name in ("argv", "cwd", "interpreter")}
    return {"kind": "COMMAND", "key": key, "sha256": _canonical_sha256(description)}


def _test_artifacts(test_artifacts):
    if type(test_artifacts) is not list or len(test_artifacts) > 256:
        _invalid()
    seen = set()
    total = 0
    result = []
    for artifact in test_artifacts:
        _exact_fields(artifact, _TEST_FIELDS)
        key = _artifact_key(artifact["key"])
        content = artifact["content"]
        if key in seen or type(content) is not bytes or len(content) > _MAX_BYTES:
            _invalid()
        seen.add(key)
        total += len(content)
        if total > 8_388_608:
            _invalid()
        result.append({"kind": "TEST", "key": key, "sha256": _sha256(content)})
    return result


def build_run_evidence(report, *, release_id, bindings, attempt=1, command, test_artifacts):
    """Проверить данные и построить FIRST_RUN_EVIDENCE_ENVELOPE_V1."""
    # Правила конфигурации принадлежат принятому P46. Тесты здесь не запускаются.
    try:
        RecordingResult(release_id=release_id, bindings=bindings, attempt=attempt)
    except RecordingError as error:
        raise RunEvidenceError("INVALID_INPUT") from error

    records, outputs = _check_report(report, release_id, bindings, attempt)
    artifacts = [_command_artifact(command)] + _test_artifacts(test_artifacts)
    artifacts.sort(key=lambda artifact: (artifact["kind"], artifact["key"]))
    return {
        "schema_version": "FIRST_RUN_EVIDENCE_ENVELOPE_V1",
        "records": records,
        "report_sha256": _canonical_sha256(report),
        "identity_snapshot": {
            "schema_version": "FIRST_TEST_IDENTITY_SNAPSHOT_V1",
            "artifacts": artifacts,
        },
        "raw_outputs": {
            name: {"content": raw, "sha256": _sha256(raw), "size_bytes": len(raw)}
            for name, raw in outputs.items()
        },
        "external_effect_authorized": False,
        "gate_acceptance": False,
    }
