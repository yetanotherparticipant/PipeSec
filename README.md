# PipeSec

## Описание

PipeSec — гибридный инструмент для статического и динамического анализа CI/CD пайплайнов на предмет утечек секретов.

## Требования

- Python 3.11+
- Golang 1.25+

## Установка

### Статический модуль

```bash
# Создание виртуального окружения и активация
python3 -m venv venv
source venv/bin/activate

# Установка как пакета (появится команда pipesec)
pip install "git+https://github.com/yetanotherparticipant/PipeSec.git#subdirectory=static"
```

### Динамический модуль

```bash
# собраный бинарник появится в $(go env GOPATH)/bin/pipesec-dynamic
# не забудьте добавить $(go env GOPATH)/bin в PATH
GOPROXY=direct go install github.com/yetanotherparticipant/PipeSec/dynamic/cmd/pipesec-dynamic@latest
```

## Использование

### Базовое использование

#### Статический модуль

**Статический анализ:**

```bash
# через CLI entrypoint:
pipesec <путь к workflow.yml>

# или запуск как модуль:
python -m pipesec <путь к workflow.yml>
```

**Гибридный анализ:**

```bash
pipesec <путь к workflow.yml> --log <путь к логу>
```

**Выбор платформы CI:**

```bash
# auto (по умолчанию): env -> YAML -> github
pipesec samples/vulnerable-gitlab.yml --format json

# принудительно GitLab
pipesec samples/vulnerable-gitlab.yml --platform gitlab --format json

# принудительно GitHub Actions
pipesec samples/vulnerable-all.yml --platform github --format json
```

**Форматы отчёта:**

```bash
# JSON
pipesec samples/vulnerable-all.yml --format json

# вывод в файл
pipesec samples/vulnerable-all.yml --format json --out out.json
```

**Паттерны секретов (единый источник):**

По умолчанию инструмент использует [data/secret_patterns.json](data/secret_patterns.json), если файл существует.

```bash
# явное указание файла паттернов (по дефолту берётся либо data/secret_patterns.json либо ../data/secret_patterns.json)
pipesec samples/vulnerable-all.yml --patterns data/secret_patterns.json
```

**Справка**

```bash
pipesec --help
```

```bash
usage: pipesec [-h] [--platform {github,gitlab,auto}] [--log LOG_PATH] [--fail-on {LOW,MEDIUM,HIGH,CRITICAL}]
               [--fix] [--format {console,json}] [--out OUT_PATH]
               [--patterns PATTERNS_PATH] [--list-rules]
               [--enable-rule ENABLE_RULES] [--disable-rule DISABLE_RULES]
               [workflow]

PipeSec: CI/CD security scanner

positional arguments:
  workflow              Path to workflow YAML (.github/workflows/* or .gitlab-ci.yml)

options:
  -h, --help            show this help message and exit
  --platform {github,gitlab,auto}
                        Workflow platform mode (default: auto)
  --log LOG_PATH        Path to log (optional)
  --fail-on {LOW,MEDIUM,HIGH,CRITICAL}
                        Return exit code 1 when there is finding with severity
                        >= this value
  --fix                 Suggest fixes
  --format {console,json}
                        Report format
  --out OUT_PATH        Output report to file instead of stdout
  --patterns PATTERNS_PATH
                        Path to JSON with RegEx patterns (optional). By
                        default using data/secret_patterns.json, if it is
                        present.
  --list-rules          Output list of existing rules
  --enable-rule ENABLE_RULES
                        Enable only listed rules (repeatable). Value: rule id
                        (example: dangerous_triggers) or full class name
                        (example: static.rules.dangerous_triggers.DangerousTri
                        ggersRule).
  --disable-rule DISABLE_RULES
                        Disable listed rules (repeatable). Value: rule id or
                        full class name.

Environment variables:
- TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID for Telegram alerts
- PIPESEC_WEBHOOK_URL, PIPESEC_WEBHOOK_HEADERS for generic webhook alerts
```

#### Динамический модуль

Динамический модуль поддерживает два режима:

- `scan` — сканирование stdin/файла лога на утечки секретов;
- `run` — запуск команды и потоковый анализ её stdout/stderr; дополнительно на Linux: egress-мониторинг и process-monitoring через `/proc`. При нахождении события уровня `--fail-on` и выше команда завершается досрочно (proactive stop).

**Сканирование логов (scan):**

```bash
# сканирование файла лога
pipesec-dynamic -mode scan --log ./samples/build.log -source build.log

# сканирование stdin
cat ./samples/build.log | pipesec-dynamic -mode scan -source stdin
```

**Запуск стороннего кода (run):**

```bash
# запуск команды и анализ stdout/stderr
pipesec-dynamic -mode run -source runtime -- bash -lc 'echo "AKIAIOSFODNN7EXAMPLE"'

# запуск команды с анализом egress трафика
pipesec-dynamic -mode run -source runtime -- curl https://example.com
```

**Форматы отчёта:**

```bash
# JSON
pipesec-dynamic -mode scan --log ./samples/build.log -source build.log -format json
```

**Паттерны секретов (единый источник):**

По умолчанию модуль пытается автоматически загрузить паттерны секретов из `data/secret_patterns.json`.
Можно явно указать файл через `--patterns`.

```bash
pipesec-dynamic -mode scan --patterns ./data/secret_patterns.json --log ./samples/build.log -source build.log
```

**Политики process-monitoring (FD) без хардкода в коде:**

```bash
# Явная политика
pipesec-dynamic -mode run --proc-policy ./data/proc_monitor_policy.json -- bash -lc 'echo test'

# Автозагрузка: data/proc_monitor_policy.json (если файл существует)
pipesec-dynamic -mode run -- bash -lc 'echo test'
```

**Справка:**

```bash
pipesec-dynamic -h
```

```bash
Usage of pipesec-dynamic:
  -allow-list string
    	comma-separated list of allowed IPs (LOW severity)
  -deny-list string
    	comma-separated list of denied IPs (CRITICAL severity)
  -fail-on string
    	return exit 1 if severity >= LEVEL (LOW|MEDIUM|HIGH|CRITICAL) (default "CRITICAL"); in run mode also stops process proactively
  -fail-on-egress
    	treat any egress as CRITICAL
  -format string
    	console|json (default "console")
  -log string
    	path to log file (optional; default stdin)
  -mode string
    	scan|run (default "scan")
  -patterns string
    	path to secret_patterns.json (optional)
  -proc-policy string
    	path to proc monitor policy json (optional)
  -source string
    	source label for findings (default "stdin")
  -timeout duration
    	timeout for run mode (0 = none)
```

**Замечание про Linux-only поведение:**

- finding `Network Egress (Observed)` появляется только в Linux (используется `/proc/net/*`).
- process-monitoring findings (`Secret in Process Environment`, `Suspicious Shared Object`, `Dangerous Process Capabilities` и др.) также доступны только в Linux.
- на macOS/Windows модуль работает, но `/proc`-наблюдение возвращает stub-поведение.

### Примеры

**Сканирование уязвимого workflow:**

```bash
pipesec samples/vulnerable-all.yml
```

Ожидаемый результат: Обнаружение 25 проблем различной критичности.

**Сканирование уязвимого GitLab CI:**

```bash
pipesec samples/vulnerable-gitlab.yml --platform gitlab --format json
```

Ожидаемый результат: срабатывания GitLab-правил (`Hardcoded Secret`, `Supply Chain`, `Runner`, `Artifact Exposure`).

**Сканирование безопасного workflow:**

```bash
pipesec samples/safe-all.yml
```

Ожидаемый результат: Уязвимостей не обнаружено.

### Расширенные возможности

#### Auto-remediation (--fix)

```bash
# JSON с предложениями по исправлению
pipesec samples/vulnerable-all.yml --format json --fix

# Консольный вывод с Fix
pipesec samples/vulnerable-all.yml --format console --fix
```

#### Гибкий порог отказа (--fail-on)

```bash
# exit 1 при HIGH или выше
pipesec samples/vulnerable-all.yml --fail-on HIGH

# exit 1 при любой находке
pipesec samples/vulnerable-all.yml --fail-on LOW
```

#### Allow/Deny списки для egress (Linux)

```bash
# IP в allow-list получает LOW severity
pipesec-dynamic -mode run --allow-list '93.184.215.14,8.8.8.8' -- curl https://example.com

# IP в deny-list получает CRITICAL severity
pipesec-dynamic -mode run --deny-list 1.1.1.1 -- curl http://1.1.1.1

# Любой egress = CRITICAL
pipesec-dynamic -mode run --fail-on-egress -- curl https://example.com
```

#### Уведомления (Telegram + generic webhook)

При наличии переменных окружения отправляются уведомления:

```bash
export TELEGRAM_BOT_TOKEN="123456:ABC..."
export TELEGRAM_CHAT_ID="-100123456789"
export PIPESEC_WEBHOOK_URL="https://hooks.example.net/pipesec"
export PIPESEC_WEBHOOK_HEADERS='{"Authorization":"Bearer <token>"}'
pipesec samples/vulnerable-all.yml
# → Telegram и/или Webhook: summary + findings + count
```

**Динамический анализ (scan) лога с утечками:**

```bash
pipesec-dynamic -mode scan -format json --log ./samples/build.log -source build.log
```

Ожидаемый результат: CRITICAL-находки по секретам из лога, exit code = 1.

**Динамический анализ (run) утечки в stdout:**

```bash
pipesec-dynamic -mode run -format json -source runtime -- bash -lc 'echo "AKIAIOSFODNN7EXAMPLE"'
```

Ожидаемый результат: CRITICAL-находка по утечке, exit code = 1.

**Динамический анализ (run) с process-monitoring:**

```bash
pipesec-dynamic -mode run --proc-policy ./data/proc_monitor_policy.json -format json \
  -- bash -lc 'export AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE; (curl -s http://1.1.1.1 >/dev/null 2>&1 || true) & sleep 1; wait'
```

Ожидаемый результат: findings по `/proc` (например `Secret in Process Environment`, `Suspicious Child Process`) и при egress — `Network Egress (Observed)`.
