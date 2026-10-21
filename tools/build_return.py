"""Build the component return from its original ZIP and actual gate outputs.

This repository utility performs I/O; the submitted production adapter does not.
Run with Python 3.12. The --baseline option records the untouched input package.
"""
import argparse
import difflib
import hashlib
import json
import pathlib
import platform
import re
import subprocess
import sys
import zipfile
from datetime import datetime, timezone


REPO = pathlib.Path(__file__).resolve().parents[1]
PACKAGE_NAME = "04_Dmitry_SFA_P46_RUN_EVIDENCE"
PACKAGE = REPO / PACKAGE_NAME
ORIGINAL = REPO / "originals" / (PACKAGE_NAME + ".zip")
ORIGINAL_SHA256 = "6f2ba8255620c1cf3af4d8e4de717157be739ec572d688a4dae8453def4709c5"
TARGET = "source/audit_release/command_evidence.py"
ZIP_PATH = REPO / "artifacts" / (PACKAGE_NAME + "_RETURN_R1.zip")
SCRIPTS = ("CHECK_PACKAGE.py", "RUN_PUBLIC_TESTS.py", "RUN_CANDIDATE_TESTS.py")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def original_files():
    assert digest(ORIGINAL.read_bytes()) == ORIGINAL_SHA256, "Wrong original archive"
    with zipfile.ZipFile(ORIGINAL) as archive:
        assert archive.testzip() is None
        return {
            item.filename.removeprefix(PACKAGE_NAME + "/"): archive.read(item)
            for item in archive.infolist() if not item.is_dir()
        }


def files_in(package):
    result = {}
    for path in sorted(package.rglob("*")):
        assert not path.is_symlink(), "Symlink: " + str(path)
        if path.is_file():
            relative = path.relative_to(package).as_posix()
            assert "__pycache__" not in path.parts and path.suffix != ".pyc", relative
            result[relative] = path.read_bytes()
    return result


def run_gates(package, log_dir):
    log_dir.mkdir(parents=True, exist_ok=True)
    runs = []
    for index, script in enumerate(SCRIPTS, 1):
        command = [sys.executable, "-B", script]
        started = datetime.now(timezone.utc).isoformat()
        completed = subprocess.run(command, cwd=package, capture_output=True)
        prefix = "%02d_%s" % (index, script.removesuffix(".py"))
        stdout_name = prefix + ".stdout.log"
        stderr_name = prefix + ".stderr.log"
        (log_dir / stdout_name).write_bytes(completed.stdout)
        (log_dir / stderr_name).write_bytes(completed.stderr)
        tests = re.search(rb"Ran (\d+) tests? in", completed.stderr)
        run = {
            "script": script,
            "command": command,
            "cwd": str(package.resolve()),
            "python_version": platform.python_version(),
            "python_full_version": sys.version,
            "started_at_utc": started,
            "finished_at_utc": datetime.now(timezone.utc).isoformat(),
            "exit_code": completed.returncode,
            "tests_run": int(tests.group(1)) if tests else None,
            "stdout_file": stdout_name,
            "stderr_file": stderr_name,
            "stdout_sha256": digest(completed.stdout),
            "stderr_sha256": digest(completed.stderr),
        }
        write_json(log_dir / (prefix + ".result.json"), run)
        runs.append(run)
    write_json(log_dir / "RUNS.json", {"runs": runs})
    return runs


def make_patch(original, current):
    """All changed/added UTF-8 files except the patch and its outer manifest."""
    parts = []
    excluded = {"return/PATCH.diff", "return/OUTPUT_SHA256.json"}
    for relative, raw in sorted(current.items()):
        if relative in excluded or original.get(relative) == raw:
            continue
        old = original.get(relative)
        parts.append("diff --git a/%s b/%s\n" % (relative, relative))
        if old is None:
            parts.append("new file mode 100644\n")
        lines = difflib.unified_diff(
            [] if old is None else old.decode("utf-8").splitlines(keepends=True),
            raw.decode("utf-8").splitlines(keepends=True),
            fromfile="/dev/null" if old is None else "a/" + relative,
            tofile="b/" + relative,
            lineterm="\n",
        )
        for line in lines:
            parts.append(line)
            if not line.endswith("\n"):
                parts.append("\n\\ No newline at end of file\n")
    return "".join(parts).encode("utf-8")


def report(runs):
    public_count = runs[1]["tests_run"]
    candidate_count = runs[2]["tests_run"]
    rows = "\n".join(
        "| `%s` | `%s` | %s | %s |" % (
            run["script"], " ".join(run["command"]), run["exit_code"],
            "—" if run["tests_run"] is None else run["tests_run"],
        ) for run in runs
    )
    return f"""# Отчёт о возврате SFA-P46-RUN-EVIDENCE R1

Компонент реализован в `source/audit_release/command_evidence.py` по редакции
H2-RU-CHECK выданного комплекта. Проверки компонента завершились успешно;
общая регрессия и приёмка Sales First остаются открытыми.

## Среда и фактические команды

Python: **{platform.python_version()}**. Полная строка: `{sys.version}`.
Рабочий каталог всех трёх запусков: `{PACKAGE.resolve()}`.
Использована только стандартная библиотека. Опция `-B` отключает создание кэша;
соответствует командам README с явным интерпретатором Python 3.12.

| Проверка | Фактическая команда | Код выхода | Число тестов |
|---|---|---:|---:|
{rows}

Итого функциональных тестов: **{public_count + candidate_count}**
({public_count} публичных и {candidate_count} собственных).
Штатные программы запуска отклоняют пустой набор, пропуски, ожидаемые неудачи
и неожиданные успехи. Итоговые коды всех трёх команд равны 0.

В `return/logs/` находятся полные фактические stdout/stderr каждой команды,
отдельные `*.result.json` с кодами завершения, командами, каталогом, версией и
SHA-256 журналов; `RUNS.json` объединяет метаданные. Пустой stdout допустим:
стандартный unittest пишет протокол в stderr. Журналы не пересказывались.

## Исходная база и целостность

Исходный ZIP: `04_Dmitry_SFA_P46_RUN_EVIDENCE.zip`,
SHA-256 `{ORIGINAL_SHA256}`.
Все 17 защищённых файлов сохранены побайтно; проверен также весь исходный
комплект, кроме единственного разрешённого изменяемого целевого модуля.
Принятые P23, P46 RecordingResult и P47 не менялись.

Исходный каркас намеренно завершался `IMPLEMENTATION_REQUIRED`: 13 публичных
проверок с кодом 1. Собственных тестов было 0, также код 1. Проверка целостности
исходной базы завершалась кодом 0. Эти исходные прогоны хранятся в репозитории
отдельно от финальных журналов, в `artifacts/verification/baseline/`.

## Состав и воспроизводимость

Возврат — один ZIP с корнем `04_Dmitry_SFA_P46_RUN_EVIDENCE/`.
`PATCH.diff` восстанавливает все изменённые/добавленные UTF-8 файлы относительно
выданного архива, кроме самого `return/PATCH.diff` и `return/OUTPUT_SHA256.json`.
В том числе он содержит код, тесты, документы и журналы. Эти два служебных файла
переданы отдельно внутри ZIP; такое исключение устраняет самоссылки.

`OUTPUT_SHA256.json` содержит SHA-256 всех изменённых/добавленных файлов,
включая патч и сырые журналы, исключая только сам манифест. Защищённые файлы
проверяются исходным `PROTECTED_SHA256.json` и сравнением с исходным ZIP.

Повторная проверка готового ZIP после распаковки и проверка применения патча
запускаются утилитой репозитория `tools/verify_return.py`. Их внешние журналы
сохраняются в `artifacts/verification/round2/`, а сводка — рядом с ZIP в
`*.validation.json`. Они не дописываются в уже собранный архив.

## Фактическая граница результата

Проверены компонентный контракт и реальные включённые зависимости P23/P46/P47.
Продуктовая сборка, рабочая установка, служебная активация, БД и реальные отправки
не выполнялись. `external_effect_authorized` и `gate_acceptance` всегда False.
Хеши связывают переданные байты, не доказывают выполнение описанной команды,
подлинность отчёта, происхождение исходников или готовность продукта.
Источники отчёта, артефактов и остальных пяти измерений P47 контролирует интегратор.
"""


def build():
    assert sys.version_info[:2] == (3, 12), "Python 3.12 required"
    original = original_files()
    returned = PACKAGE / "return"
    for document in ("IMPLEMENTATION_RU.md", "INTEGRATION_RU.md"):
        assert (returned / document).is_file(), document
    runs = run_gates(PACKAGE, returned / "logs")
    assert all(run["exit_code"] == 0 for run in runs), "Gate failed; inspect raw logs"
    (returned / "REPORT_RU.md").write_text(report(runs), encoding="utf-8")
    current = files_in(PACKAGE)
    for relative, raw in original.items():
        if relative != TARGET:
            assert current.get(relative) == raw, "Changed input: " + relative
    (returned / "PATCH.diff").write_bytes(make_patch(original, current))
    current = files_in(PACKAGE)
    changed = {
        relative: digest(raw) for relative, raw in sorted(current.items())
        if relative != "return/OUTPUT_SHA256.json" and original.get(relative) != raw
    }
    write_json(returned / "OUTPUT_SHA256.json", changed)
    current = files_in(PACKAGE)
    ZIP_PATH.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(ZIP_PATH, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for relative, raw in sorted(current.items()):
            info = zipfile.ZipInfo(PACKAGE_NAME + "/" + relative, (2026, 10, 21, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, raw)
    print(json.dumps({"zip": str(ZIP_PATH), "files": len(current), "sha256": digest(ZIP_PATH.read_bytes()), "runs": runs}, ensure_ascii=False, indent=2))


def baseline(path):
    assert files_in(path) == original_files(), "Baseline must be byte-exact original package"
    runs = run_gates(path, REPO / "artifacts/verification/baseline")
    assert [run["exit_code"] for run in runs] == [0, 1, 1]
    assert [run["tests_run"] for run in runs] == [None, 13, 0]
    print(json.dumps({"baseline": str(path), "runs": runs}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=pathlib.Path)
    args = parser.parse_args()
    if args.baseline:
        baseline(args.baseline)
    else:
        build()
