# PipeSec Test Report

## 1) Как запускать

### Static module

```bash
cd Project/static
uv run python -m unittest discover -s tests -q
```

### Dynamic module

```bash
cd Project/dynamic
go test ./...
```

## 2) Матрица требований

| ID | Требование | Тест(ы), которые закрывают | Статус |
|---|---|---|---|
| T1 | Все правила зарегистрированы и покрыты кейсами | `static/tests/test_rules_registry_coverage.py` | PASS |
| T2 | Каждое правило срабатывает на позитивном сценарии | `static/tests/test_rules_positive_cases.py` | PASS |
| T3 | На безопасных сценариях нет ложных срабатываний | `static/tests/test_rules_negative_cases.py` | PASS |
| T4 | Корректное определение платформы (GitHub/GitLab/auto/env) | `static/tests/test_platform_detection.py`, `static/tests/test_analyzer_platform_filter.py` | PASS |
| T5 | CLI корректно работает с GitLab-конфигурациями | `static/tests/test_cli_gitlab_integration.py`, `static/tests/test_gitlab_rules.py` | PASS |
| T5.1 | CLI корректно работает на реальных sample-сценариях (safe/vulnerable/log/fix) | `static/tests/test_cli_samples_integration.py` | PASS |
| T6 | Каналы уведомлений формируются и отправляют payload | `static/tests/test_notifications.py`, `dynamic/internal/notify/notify_test.go` | PASS |
| T7 | Парсинг и quality gate отчёта в динамическом модуле корректны | `dynamic/internal/report/report_test.go` | PASS |
| T8 | Linux `/proc`-мониторинг: env/maps/caps/FD/namespace | `dynamic/internal/dynscan/procmon_linux_test.go` | PASS |
| T9 | Linux `/proc/net` адреса парсятся корректно | `dynamic/internal/dynscan/procnet_linux_test.go` | PASS |
| T10 | Policy-driven `/proc` конфигурация загружается и применяется | `dynamic/internal/dynscan/proc_policy_test.go` | PASS |
| T11 | Runtime детект секретов в дочерних процессах работает | `dynamic/internal/app/run_integration_linux_test.go::TestRunModeDetectsProcessEnvironmentSecrets` | PASS |
| T12 | E2E scan mode корректно детектит секреты из файла лога | `dynamic/internal/app/run_cli_integration_linux_test.go::TestRunScanModeLogFileDetectsSecrets` | PASS |
| T13 | Проактивность: процесс останавливается при finding >= `--fail-on` | `dynamic/internal/app/run_cli_integration_linux_test.go::TestRunModeStopsProcessOnThresholdViaCLI`, `dynamic/internal/app/run_integration_linux_test.go::TestRunModeStopsProcessOnThreshold` | PASS |
| T14 | `--allow-list` понижает критичность egress finding до LOW | `dynamic/internal/app/run_cli_integration_linux_test.go::TestRunModeAllowListLowersEgressSeverityViaCLI` | PASS |
| T15 | `--deny-list` повышает критичность egress finding до CRITICAL | `dynamic/internal/app/run_cli_integration_linux_test.go::TestRunModeDenyListRaisesEgressSeverityViaCLI` | PASS |
| T16 | `--fail-on-egress` принудительно квалифицирует egress как CRITICAL | `dynamic/internal/app/run_cli_integration_linux_test.go::TestRunModeFailOnEgressForcesCriticalViaCLI` | PASS |

## 3) Короткий итог

- Static unit/integration tests: PASS
- Dynamic tests: PASS

## 4) Что это доказывает

1. Детект-правила и платформа-анализ работают как заявлено.
2. Linux-специфичный мониторинг (`/proc`, `/proc/net`) покрыт автоматическими тестами.
3. Реализована проактивная защита: в `run` режиме процесс аварийно останавливается,
   если найдено событие уровня `--fail-on` и выше.
4. Политики исходящего трафика (`--allow-list`, `--deny-list`, `--fail-on-egress`) проверяются программно и дают ожидаемую критичность findings.
