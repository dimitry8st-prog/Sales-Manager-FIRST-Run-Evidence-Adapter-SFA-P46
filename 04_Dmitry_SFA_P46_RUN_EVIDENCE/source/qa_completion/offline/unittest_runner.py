"""Управляемый запуск явно переданного проверенного unittest-набора.

Компонент P23: исполнитель тестов, а не сборщик, не отбор регрессии и не
разрешение внешних действий. Запускает ровно один переданный набор через
стандартный ``unittest.TestSuite.run``, сохраняет фактический текст
``sys.stdout``/``sys.stderr`` и возвращает записи закреплённого адаптера P46.
"""
import copy
import io
import sys
import threading
import unittest
from collections.abc import Mapping

SCHEMA_VERSION = "FIRST_OFFLINE_UNITTEST_RUN_V1"

# Один активный вызов на импортированный экземпляр модуля. Неблокирующий
# захват даёт немедленный RUN_IN_PROGRESS вместо ожидания.
_RUN_LOCK = threading.Lock()


class RunnerError(ValueError):
    """Ошибка контракта исполнителя; ``code`` и ``str(error)`` совпадают."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


class RunnerExecutionError(RunnerError):
    """Прерванное выполнение: точный захваченный текст и причина в ``__cause__``."""

    def __init__(self, stdout, stderr):
        super().__init__("EXECUTION_ABORTED")
        self.stdout = stdout
        self.stderr = stderr


def _cleanup_enabled(node):
    """Включена ли стандартная очистка ``_tests`` после каждого ребёнка.

    ``BaseTestSuite`` объявляет ``_cleanup = True``; вызывающий вправе
    выставить ``False``. Значение читается как обычное условие ``run``.
    """
    try:
        cleanup = node._cleanup
    except AttributeError:
        return True
    try:
        return bool(cleanup)
    except MemoryError:
        raise
    except Exception:
        raise RunnerError("INVALID_SUITE") from None


def _storage_length(children):
    """Длина хранилища или ``None``, если её нельзя получить без потребления.

    Для встроенных подклассов используется базовый слот, чтобы не исполнять
    переопределённый ``__len__``. Обычные исключения означают непригодное
    хранилище; ``MemoryError`` и прочие ``BaseException`` не переписываются.
    """
    kind = type(children)
    try:
        if issubclass(kind, tuple):
            return tuple.__len__(children)
        if issubclass(kind, dict):
            return dict.__len__(children)
        return len(children)
    except TypeError:
        return None
    except MemoryError:
        raise
    except Exception:
        raise RunnerError("INVALID_SUITE") from None


def _check_cleanup_compatibility(node, children):
    """Совместимо ли хранилище со стандартной очисткой ``run``.

    ``_removeTestAtIndex`` читает ``self._tests[index]``; ``TypeError`` при
    чтении проглатывается (очистка пропускается), иначе выполняется
    присваивание ``self._tests[index] = None``. Поэтому при включённой
    очистке непустое отображение (индекс — не ключ, возможен ``KeyError``) и
    непустая последовательность только для чтения (присваивание невозможно)
    отвергаются до выполнения тел. Пустое хранилище совместимо всегда.
    """
    if not _cleanup_enabled(node):
        return
    kind = type(children)
    if not hasattr(kind, "__getitem__"):
        return  # TypeError при чтении → стандартная очистка пропускается
    if issubclass(kind, Mapping) or not hasattr(kind, "__setitem__"):
        if _storage_length(children) != 0:
            raise RunnerError("INVALID_SUITE")


def _suite_children(node):
    """Итератор детей TestSuite из повторно итерируемого хранилища.

    Допускается любое повторно итерируемое хранилище: ``list``, ``tuple``,
    ``set``, ``dict``, ``deque``, пользовательские последовательности и
    контейнеры. Повторяемость проверяется двумя независимыми вызовами
    ``iter``: объект, возвращающий себя или один и тот же кэшированный
    итератор, одноразов и отвергается, потому что проверка не должна его
    потреблять. Обход идёт первым независимым итератором; для стандартных
    контейнеров это не потребляет хранилище, а для генератора на каждый
    вызов создаётся отдельный итератор, поэтому последующий ``suite.run``
    видит те же элементы.
    Поддержка произвольных одноразовых итераторов контрактом не требуется.

    Совместимость с ``_cleanup`` проверяется для каждого узла отдельно:
    при включённой очистке непустое отображение или последовательность
    только для чтения отвергаются до тел. Хранилища без ``__getitem__``
    (множества, пользовательские iterable) совместимы: стандартный ``run``
    пропускает очистку. Порядок обхода — стандартный порядок итерации самого
    хранилища. Проверка реального типа не исполняет пользовательский
    ``__class__``.
    """
    try:
        children = node._tests
    except AttributeError:
        raise RunnerError("INVALID_SUITE") from None
    try:
        first = iter(children)
        second = iter(children)
    except MemoryError:
        raise
    except Exception:
        raise RunnerError("INVALID_SUITE") from None
    if first is second:
        # Итератор или кэшированный одноразовый итератор: обход потребил бы его.
        raise RunnerError("INVALID_SUITE")
    _check_cleanup_compatibility(node, children)
    return first


def _collect_leaves(root):
    """Обойти дерево набора без выполнения и вернуть листья слева направо.

    Обход итеративный (явный стек итераторов), поэтому глубина вложенности не
    ограничена пределом рекурсии Python. Повтор ссылки на набор, включая цикл,
    и любой недопустимый узел дают INVALID_SUITE. Проверка ничего не потребляет:
    для каждого набора берётся независимый итератор повторно итерируемого
    хранилища, поэтому последующий ``suite.run`` видит те же элементы.
    Повреждённое хранилище, бросающее при итерации, даёт INVALID_SUITE.
    """
    leaves = []
    seen = {id(root)}
    stack = [_suite_children(root)]
    while stack:
        try:
            child = next(stack[-1])
        except StopIteration:
            stack.pop()
            continue
        except MemoryError:
            raise
        except Exception:
            raise RunnerError("INVALID_SUITE") from None
        if type(child) is unittest.TestSuite:
            marker = id(child)
            if marker in seen:
                # Повтор набора, в том числе цикл: один объект набора не может
                # встречаться в дереве дважды.
                raise RunnerError("INVALID_SUITE")
            seen.add(marker)
            stack.append(_suite_children(child))
        elif issubclass(type(child), unittest.TestCase):
            leaves.append(child)
        else:
            # Произвольные вызываемые объекты, None и другие контейнеры.
            raise RunnerError("INVALID_SUITE")
    return leaves


def _bound_test_ids(bindings):
    """Извлечь test_id из уже проверенного P46 bindings.

    Правила bindings принадлежат P46 (ABI). Здесь нужен только набор строк,
    чтобы сверить его с листьями. Если структура не позволяет это сделать,
    возвращается None, и вызывающий код сообщает SUITE_BINDINGS_MISMATCH.
    """
    if type(bindings) is not list:
        return None
    test_ids = []
    for item in bindings:
        if type(item) is not dict:
            return None
        try:
            test_id = item.get("test_id")
        except MemoryError:
            raise
        except Exception:
            # Враждебный ключ, бросающий при сравнении, не повод выпускать
            # сырое исключение: структура bindings непригодна для сверки.
            return None
        if type(test_id) is not str:
            return None
        test_ids.append(test_id)
    return test_ids


def _execute(suite, result):
    """Единственное выполнение под перенаправлением потоков и сбор ответа."""
    saved_stdout = sys.stdout
    saved_stderr = sys.stderr
    captured_stdout = io.StringIO()
    captured_stderr = io.StringIO()
    sys.stdout = captured_stdout
    sys.stderr = captured_stderr
    try:
        try:
            result.startTestRun()
            try:
                suite.run(result)
            finally:
                # stopTestRun вызывается, если suite.run уже начался, и при
                # его исключении; при исключении startTestRun — не вызывается.
                result.stopTestRun()
            records = result.records()
        except Exception as exc:
            # MemoryError и BaseException, не являющиеся Exception, уходят
            # неизменными; остальные обычные исключения фаз становятся
            # RunnerExecutionError с уже захваченным текстом и причиной.
            # Проверяется реальный тип: isinstance исполняет пользовательский
            # __class__ и мог бы подменить исходную причину сырым исключением.
            if issubclass(type(exc), MemoryError):
                raise
            raise RunnerExecutionError(
                captured_stdout.getvalue(), captured_stderr.getvalue()
            ) from exc
    finally:
        sys.stdout = saved_stdout
        sys.stderr = saved_stderr
    return {
        "schema_version": SCHEMA_VERSION,
        "records": copy.deepcopy(records),
        "counts": {
            "tests_run": result.testsRun,
            "failures": len(result.failures),
            "errors": len(result.errors),
            "skips": len(result.skipped),
        },
        "stdout": captured_stdout.getvalue(),
        "stderr": captured_stderr.getvalue(),
    }


def run_suite(suite, *, release_id, bindings, result_factory, attempt=1, failfast=False):
    """Выполнить ровно один переданный набор и вернуть отчёт P23."""
    if type(suite) is not unittest.TestSuite:
        raise RunnerError("INVALID_RUN_INPUT")
    if type(failfast) is not bool:
        raise RunnerError("INVALID_RUN_INPUT")
    if not callable(result_factory):
        raise RunnerError("INVALID_RUN_INPUT")
    if not _RUN_LOCK.acquire(blocking=False):
        raise RunnerError("RUN_IN_PROGRESS")
    try:
        # Доверенная фабрика P46 проверяет release_id/bindings/attempt; её
        # исключение передаётся неизменным, тестовые тела не выполняются.
        result = result_factory(
            release_id=release_id, bindings=bindings, attempt=attempt
        )
        # Реальный тип, а не isinstance: последний исполняет пользовательский
        # __class__ и может подменить объявленный код сырым исключением.
        if not issubclass(type(result), unittest.TestResult):
            raise RunnerError("INVALID_RESULT_FACTORY")

        leaves = _collect_leaves(suite)

        leaf_ids = []
        for leaf in leaves:
            # Доверенный код тестового класса: ошибки id() уходят неизменными.
            test_id = leaf.id()
            if type(test_id) is not str:
                raise RunnerError("INVALID_SUITE")
            leaf_ids.append(test_id)

        if len(set(leaf_ids)) != len(leaf_ids):
            raise RunnerError("SUITE_BINDINGS_MISMATCH")
        bound_ids = _bound_test_ids(bindings)
        if bound_ids is None or set(bound_ids) != set(leaf_ids):
            raise RunnerError("SUITE_BINDINGS_MISMATCH")

        result.failfast = failfast
        return _execute(suite, result)
    finally:
        _RUN_LOCK.release()
