# Реализация SFA-P46-RUN-EVIDENCE R1

Реализован один новый компонент: `audit_release.command_evidence`.
Публичный интерфейс сохранён в точности:

```python
class RunEvidenceError(ValueError): ...
def build_run_evidence(report, *, release_id, bindings, attempt=1,
                       command, test_artifacts) -> dict: ...
```

Адаптер принимает уже полученный отчёт P23 и переданные вызывающим кодом
описание команды и байты тестов. Он проверяет внутреннюю согласованность данных
и возвращает `FIRST_RUN_EVIDENCE_ENVELOPE_V1`. Сам адаптер не запускает тесты
или описанную команду. Принятые P23, P46 RecordingResult и P47 остаются исходными.

## Алгоритм

1. Создать принятый `RecordingResult` только для проверки `release_id`, `bindings`,
   `attempt`. Только `RecordingError` переводится в `RunEvidenceError('INVALID_INPUT')`
   через `raise ... from error`. Неожиданные ошибки распространяются неизменными.
2. `_check_report` проверяет точные типы, наборы полей, схему, записи и счётчики.
   Пары `(suite_id, case_id)` должны принадлежать проверенному bindings и быть
   уникальны. Семь полей каждой записи копируются в новые dict в исходном порядке.
   Отсутствующие случаи после failfast не добавляются; пустой список не означает PASS.
3. `_output_bytes` кодирует stdout/stderr строгим UTF-8 без нормализации Unicode
   или переводов строк, отклоняет суррогаты и превышение ограничения каждого потока.
   Управляющие символы в этих потоках разрешены; это не правила command-строк.
4. `_command_artifact` проверяет command. `_artifact_key` обеспечивает правила ключа
   P47 и приводит ASCII-регистр к нижнему. `_command_text` проверяет аргументы,
   рабочий каталог и интерпретатор. Хешируется только `{argv,cwd,interpreter}`;
   `key` служит идентификатором и в хеш команды не входит.
5. `_test_artifacts` проверяет список тестовых артефактов, точный тип bytes,
   индивидуальный/суммарный размер и отсутствие дубликатов TEST без учёта регистра.
   Каждому TEST соответствует SHA-256 точных переданных байтов. Совпадение ключа
   COMMAND и TEST разрешено, поскольку kind различается.
6. `_canonical_sha256` использует точно `json.dumps(..., ensure_ascii=False,
   sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')`.
   Хеш отчёта охватывает весь принятый report. Словарные ключи канонизируются,
   порядок списка records сохраняется. Снимок артефактов сортируется по `(kind,key)`.
7. Возвращаются ровно семь полей оболочки, новые независимые контейнеры и точные
   UTF-8 bytes вывода с их фактическими размерами и SHA-256.
   `external_effect_authorized=False`, `gate_acceptance=False`.

## Ограничения входа

| Вход | Ограничение |
|---|---|
| Контейнеры/ключи | Точные встроенные dict/list/str; поля ровно по контракту |
| release/bindings/attempt | Проверяет исходный RecordingResult; bool вместо int запрещён |
| records | 0..10 000; точные семь полей; уникальные известные пары |
| PASS / FAIL / ERROR / SKIP | `(exit_code,skip_count)`: `(0,0)/(1,0)/(1,0)/(0,1)` |
| counts | Точные неотрицательные int; tests_run и исходы совпадают с records |
| stdout / stderr | Строгий UTF-8; каждый до 4 194 304 байт включительно |
| Ключ артефакта | ASCII 1..2048, сегменты `[A-Za-z0-9_.-]+`, без `.`, `..`, конечной точки, Windows reserved basename |
| argv | Точный list 1..256 непустых точных str, до 4096 символов каждая |
| cwd / interpreter | Непустые точные str до 4096 символов |
| command-строки | Запрещены C0 U+0000..001F, DEL U+007F и суррогаты |
| test_artifacts | Точный list 0..256; каждый dict ровно key/content |
| content | Точные bytes, до 4 194 304 каждый, суммарно до 8 388 608 |

## Карта «требование → код → собственная проверка → сырой журнал»

Все перечисленные проверки находятся в `candidate_tests/`.
Полный фактический вывод: `return/logs/03_RUN_CANDIDATE_TESTS.stderr.log`.
Публичная совместимость отдельно подтверждается
`return/logs/02_RUN_PUBLIC_TESTS.stderr.log`. Коды завершения и версии находятся
в одноимённых `*.result.json` и в `return/logs/RUNS.json`.

| Требование | Место реализации | Файл / тест |
|---|---|---|
| Точный ABI и семь полей результата | `build_run_evidence`, `RunEvidenceError` | `test_hashes.py`: `test_public_function_signature`, `test_exact_envelope_fields_types_and_flags`; `test_validation.py`: `test_error_is_value_error` |
| Проверка конфигурации исходным P46, без запуска тестов | `build_run_evidence` | `test_validation.py`: `test_configuration_reuses_recording_validation_and_cause`, `test_constructor_is_used_without_running_tests`, `test_recording_error_keeps_original_exception_identity`, `test_unexpected_constructor_exceptions_are_not_masked` |
| Границы/типы release/bindings/attempt | `build_run_evidence` → `RecordingResult` | `test_validation.py`: `test_configuration_identifier_boundaries_and_unicode_test_id`, `test_binding_configuration_invalid_shapes_and_limits_keep_cause` |
| Поля, точные типы, подклассы, схема | `_exact_fields`, `_check_report` | `test_validation.py`: `test_report_exact_type_and_fields`, `test_schema_exact_value_and_type`, `test_record_exact_type_and_fields`, `test_record_identifiers_attempt_and_exact_types` |
| 10 000 записей, известные уникальные пары | `_check_report` | `test_validation.py`: `test_records_exact_container_and_limit`, `test_records_and_bindings_allow_exactly_ten_thousand`, `test_duplicate_or_unbound_record_pair_rejected` |
| Точные исходы и согласованные счётчики | `_check_report` | `test_validation.py`: `test_status_triplets_are_exact`, `test_counts_exact_type_fields_values_and_consistency` |
| UTF-8, размер каждого потока, суррогаты | `_output_bytes` | `test_validation.py`: `test_output_text_exact_type_and_surrogates`, `test_output_byte_limits_independent_per_stream` |
| Точная команда, длины, запрет C0/DEL/суррогатов | `_command_artifact`, `_command_text` | `test_validation.py`: `test_command_exact_type_and_fields`, `test_argv_exact_container_count_and_members`, `test_command_string_character_limits_and_forbidden_characters`, `test_all_c0_command_controls_rejected` |
| Ключи P47, зарезервированные имена, регистр | `_artifact_key`, `_test_artifacts` | `test_validation.py`: `test_artifact_keys_invalid_types_paths_and_windows_names`, `test_artifact_key_limits_valid_names_and_cross_kind_collision`, `test_artifact_duplicates_case_insensitive` |
| TEST: тип bytes, количество, индивидуальный/общий размер | `_test_artifacts` | `test_validation.py`: `test_artifact_list_and_records_exact_types_and_fields`, `test_artifact_content_exact_bytes`, `test_artifact_count_and_empty_artifacts`, `test_artifact_individual_and_total_byte_limits` |
| Канонические хеши и исключение key команды | `_canonical_sha256`, `_command_artifact` | `test_hashes.py`: `test_command_hash_exact_canonical_bytes_and_key_excluded`, `test_every_command_component_affects_hash`, `test_mapping_insertion_order_does_not_change_hashes` |
| Исходный порядок records, точные raw bytes, отсутствие нормализации | `_check_report`, `_output_bytes`, `build_run_evidence` | `test_hashes.py`: `test_report_canonical_hash_preserves_record_list_order`, `test_raw_outputs_preserve_unicode_crlf_controls_hash_and_size`, `test_no_unicode_or_line_ending_normalization`, `test_snapshot_sorted_and_test_hashes_use_arbitrary_exact_bytes` |
| Независимые контейнеры, неизменность входа, attempt без новой политики | `build_run_evidence` | `test_hashes.py`: `test_input_preserved_and_output_containers_detached`, `test_nondefault_attempt_preserved_without_latest_attempt_policy` |
| Нет собственных I/O, окружения, часов, subprocess и вывода | Весь новый модуль | `test_hashes.py`: `test_import_and_call_have_no_own_io_environment_clock_or_process` |
| Настоящий отчёт P23/P46 со всеми четырьмя исходами | Вход `report` | `test_integration.py`: `test_real_p23_p46_mixed_four_statuses_execute_exactly_once` |
| failfast/пустой запуск без выдуманного PASS | `_check_report` | `test_integration.py`: `test_real_failfast_preserves_only_visited_case_without_invented_pass`, `test_real_empty_suite_does_not_become_general_pass`, `test_empty_report_can_have_unvisited_bindings` |
| Реальный P47: UNKNOWN/MATCH/CHANGED_AFFECTED | `identity_snapshot` | `test_integration.py`: `test_real_p47_equal_partial_identity_is_unknown`, `test_real_p47_full_dimensions_match`, `test_real_p47_changed_command_is_affected`, `test_real_p47_changed_test_bytes_are_affected`, `test_known_changed_identity_takes_priority_over_missing_dimensions` |

Собственные проверки: 29 ValidationTests + 12 HashAndPurityTests +
9 RealIntegrationTests = 50. Публичных тестов в исходном комплекте — 13.

## Граница доверия и ограничения результата

Снимок описывает только COMMAND и TEST. При одинаковых снимках без остальных
пяти измерений P47 возвращает UNKNOWN, а не MATCH. Для MATCH тест интеграции
явно добавляет SOURCE/SCHEMA/CONFIG/DEPENDENCY/RUNTIME и полное описание влияния.
Известное релевантное изменение команды или теста даёт CHANGED_AFFECTED;
оно имеет приоритет перед неполнотой других измерений.

Хеш подтверждает только переданные байты. Адаптер не отличает внутренне
согласованный поддельный report от настоящего и не удостоверяет факт запуска
описанной команды. Доверенный вызывающий код отвечает за отчёт P23, идентичность
исходников/среды/зависимостей, полные журналы и их сохранение. Здесь нет агрегатного
PASS, готовности релиза, выбора последней попытки или разрешения внешних действий.
Полная продуктовая регрессия и приёмка остаются отдельными этапами.
