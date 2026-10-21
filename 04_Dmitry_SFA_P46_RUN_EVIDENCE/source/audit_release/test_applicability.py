"""SFA-P47-APPLICABILITY R1: применимость исторических проверок к текущей сборке.

Чистый алгоритм (граница PURE_APPLICABILITY_ALGORITHM_ONLY): без I/O, сети,
окружения, часов, случайности, subprocess и логирования. Входы не изменяются,
результат строится только из новых контейнеров.
"""
import re

SNAPSHOT_SCHEMA = "FIRST_TEST_IDENTITY_SNAPSHOT_V1"
REPORT_SCHEMA = "FIRST_TEST_APPLICABILITY_V1"
KINDS = ("SOURCE", "SCHEMA", "CONFIG", "DEPENDENCY", "RUNTIME", "TEST", "COMMAND")
_KIND_SET = frozenset(KINDS)

MAX_ARTIFACTS = 4096
MAX_CASES = 256
MAX_PINS = 4096
MAX_KEY_LENGTH = 2048

_SNAPSHOT_FIELDS = frozenset(("schema_version", "artifacts"))
_ARTIFACT_FIELDS = frozenset(("kind", "key", "sha256"))
_CASE_FIELDS = frozenset(("case_id", "before_required", "after_required", "footprint_complete"))
_PIN_FIELDS = frozenset(("kind", "key"))

_SEGMENT_RE = re.compile(r"[A-Za-z0-9_.-]+")
_CASE_ID_RE = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_HEX = frozenset("0123456789abcdef")
_RESERVED = frozenset(
    ["CON", "PRN", "AUX", "NUL"]
    + ["COM%d" % i for i in range(1, 10)]
    + ["LPT%d" % i for i in range(1, 10)]
)


class ApplicabilityError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class _Invalid(Exception):
    """Внутренний сигнал невалидности; код группы назначает вызывающий уровень."""


def _exact_fields(value, fields):
    # Ключи проверяются по точному типу до любого сравнения с ними, чтобы
    # не вызывать __eq__/__hash__/__str__ пользовательских объектов.
    if type(value) is not dict or len(value) != len(fields):
        raise _Invalid
    for name in value:
        if type(name) is not str or name not in fields:
            raise _Invalid


def _check_kind(value):
    if type(value) is not str or value not in _KIND_SET:
        raise _Invalid
    return value


def _check_key(value):
    if type(value) is not str or not 1 <= len(value) <= MAX_KEY_LENGTH or not value.isascii():
        raise _Invalid
    for segment in value.split("/"):
        if _SEGMENT_RE.fullmatch(segment) is None or segment.endswith("."):
            raise _Invalid
        if segment.split(".", 1)[0].upper() in _RESERVED:
            raise _Invalid
    return value.lower()


def _check_sha256(value):
    if value is None:
        return None
    if type(value) is not str or len(value) != 64 or not _HEX.issuperset(value):
        raise _Invalid
    return value


def _check_snapshot(snapshot):
    """Вернуть {(kind, key_lower): sha256 | None}."""
    _exact_fields(snapshot, _SNAPSHOT_FIELDS)
    version = snapshot["schema_version"]
    if type(version) is not str or version != SNAPSHOT_SCHEMA:
        raise _Invalid
    artifacts = snapshot["artifacts"]
    if type(artifacts) is not list or len(artifacts) > MAX_ARTIFACTS:
        raise _Invalid
    index = {}
    for artifact in artifacts:
        _exact_fields(artifact, _ARTIFACT_FIELDS)
        pair = (_check_kind(artifact["kind"]), _check_key(artifact["key"]))
        sha256 = _check_sha256(artifact["sha256"])
        if pair in index:
            raise _Invalid
        index[pair] = sha256
    return index


def _check_pins(pins):
    """Вернуть frozenset нормализованных пар (kind, key_lower)."""
    if type(pins) is not list or len(pins) > MAX_PINS:
        raise _Invalid
    seen = set()
    for pin in pins:
        _exact_fields(pin, _PIN_FIELDS)
        pair = (_check_kind(pin["kind"]), _check_key(pin["key"]))
        if pair in seen:
            raise _Invalid
        seen.add(pair)
    return frozenset(seen)


def _check_cases(cases):
    """Вернуть список (case_id, B, C, footprint_complete)."""
    if type(cases) is not list or len(cases) > MAX_CASES:
        raise _Invalid
    parsed = []
    ids = set()
    for case in cases:
        _exact_fields(case, _CASE_FIELDS)
        case_id = case["case_id"]
        if type(case_id) is not str or not case_id.isascii() or _CASE_ID_RE.fullmatch(case_id) is None:
            raise _Invalid
        if case_id in ids:
            raise _Invalid
        ids.add(case_id)
        complete = case["footprint_complete"]
        if type(complete) is not bool:
            raise _Invalid
        before = _check_pins(case["before_required"])
        after = _check_pins(case["after_required"])
        parsed.append((case_id, before, after, complete))
    return parsed


def _validate(check, data, code):
    try:
        return check(data)
    except _Invalid:
        pass
    raise ApplicabilityError(code)


def _unknown_entries(pins, index, side):
    entries = []
    for kind, key in pins:
        if (kind, key) not in index:
            entries.append((kind, key, side, "MISSING_ARTIFACT"))
        elif index[(kind, key)] is None:
            entries.append((kind, key, side, "UNKNOWN_HASH"))
    return entries


def _assess_case(case_id, before, after, complete, base_index, curr_index):
    changed = []
    for kind, key in after - before:
        changed.append((kind, key, "DEPENDENCY_ADDED", None, curr_index.get((kind, key))))
    for kind, key in before - after:
        changed.append((kind, key, "DEPENDENCY_REMOVED", base_index.get((kind, key)), None))
    for pair in before & after:
        old = base_index.get(pair)
        new = curr_index.get(pair)
        if old is not None and new is not None and old != new:
            changed.append((pair[0], pair[1], "HASH_CHANGED", old, new))
    changed.sort(key=lambda e: (e[0], e[1], e[2]))

    unknown = _unknown_entries(before, base_index, "BASELINE") + _unknown_entries(after, curr_index, "CURRENT")
    unknown.sort()

    present_before = {kind for kind, _ in before}
    present_after = {kind for kind, _ in after}
    missing = sorted(k for k in KINDS if k not in present_before or k not in present_after)

    if changed:
        status = "CHANGED_AFFECTED"
    elif unknown or missing or not complete:
        status = "UNKNOWN"
    else:
        status = "MATCH"

    return {
        "case_id": case_id,
        "status": status,
        "changed": [
            {"kind": k, "key": p, "reason": r, "before_sha256": b, "after_sha256": a}
            for k, p, r, b, a in changed
        ],
        "unknown": [{"kind": k, "key": p, "side": s, "reason": r} for k, p, s, r in unknown],
        "missing_dimensions": missing,
        "footprint_complete": complete,
    }


def assess_applicability(baseline, current, cases):
    base_index = _validate(_check_snapshot, baseline, "INVALID_BASELINE")
    curr_index = _validate(_check_snapshot, current, "INVALID_CURRENT")
    parsed = _validate(_check_cases, cases, "INVALID_CASES")
    parsed.sort(key=lambda c: c[0])
    return {
        "schema_version": REPORT_SCHEMA,
        "cases": [_assess_case(*case, base_index, curr_index) for case in parsed],
        "external_effect_authorized": False,
        "gate_acceptance": False,
    }
