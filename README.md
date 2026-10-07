# HA-Diagnostics

Предварительная alpha-версия `1.0.0-alpha.1`: локальная диагностика Home Assistant и ограниченные очищенные выборки через MCP. Продукт читает HA и устройства; управляющих tools, service calls, restart/reload и изменения конфигурации нет. Настройки собственного приложения меняет только владелец локально.

Python packaging нормализует имя/metadata wheel этой версии как `1.0.0a1` по PEP440; исходный pyproject, приложение HA, plugin.json, CHANGELOG и image tags используют `1.0.0-alpha.1`.

Доступный этап — исходники, import-only demo, fixtures/контракт, HA app build contexts и private plugin skill. Для HTTPS relay реализована локальная привязка через одноразовый код gateway CLI. Реальная установка HA OS, границы Linux процессов, полный owner pairing/IdP OAuth flow, Inspector, Secure MCP Tunnel и диалог ChatGPT требуют отдельной приёмки. Эти ограничения не позволяют объявить весь MVP завершённым.

## Ветка alpha: установка Live из GitHub

Добавьте `https://github.com/ant0lk/HA-Diagnostics#alpha` в репозитории магазина приложений HA. Ветка содержит один устанавливаемый профиль — **HA-Diagnostics — Live alpha** (`ha_diagnostics_live/`), с полным build context и закреплённым Tunnel runtime. Это подготовленная alpha-поставка: сборка/установка HA OS и реальный ChatGPT ещё не проверены.

Шаблоны Import/Live для локального упаковщика находятся в `containers/ha-app/`; они не являются отдельными приложениями магазина. Локальная исходная `ha_diagnostics/` сохранена вне Git.

## Локальный запуск в Windows

В PowerShell из корня проекта используйте существующую `.venv`; если её нет, создайте `py -3.13 -m venv .venv`. Контейнер закреплён на Python3.13.12; локальные проверки текущего стенда выполнялись Python3.12.14.

```powershell
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements.lock
$env:PYTHONPATH = (Resolve-Path .\src).Path
.\.venv\Scripts\python.exe -m ha_diagnostics.runtime --demo --data .\.local-data --web .\web
```

Откройте [локальную панель](http://127.0.0.1:8099/). Импортируйте обезличенный `tests/fixtures/archive_multiline.log`, просмотрите очистку и сохраните собственную копию. Панель позволяет отдельно разрешить/отозвать передачу импорта, посмотреть evidence и аудит, удалить очищенную копию. Demo использует loopback и не требует credentials HA; это не проверка ОС-изоляции или реального MCP подключения. Завершение процесса — Ctrl+C, свой архив остаётся в исключённой из Git `.local-data`.

В Linux аналогичный development запуск: `PYTHONPATH=src python -m ha_diagnostics.runtime --demo --data .local-data --web web`. Не включайте demo на HA OS.

## Установка и подключение

Целевой первый стенд: HA OS18.0, Core2026.9.4, Supervisor2026.09.3, amd64, timezone HA Asia/Krasnoyarsk. Поддержка aarch64 также требует реального стенда. Начните с import profile; live profile даёт broad manager credential только trusted broker и оставляет документированный риск его компрометации.

Следуйте [INSTALL](docs/INSTALL.md): проверка pinned artifacts, сборка локального HA приложения, Ingress owner ID, безопасный helper getpass, OAuth и отзыв. Для личного подключения выбран Secure MCP Tunnel после подтверждения аккаунта и действующего вызова. [HTTPS fallback](deploy/README.md) готовится на личном шлюзе с исходящим relay; внешняя инфраструктура не развёрнута. Не помещайте ключи в чат, environment, репозиторий или поставку.

`plugin/` содержит настоящий portable manifest и diagnostic skill. Пакет skills-only самостоятельно не читает HA. Для полного частного подключения нужен реальный зарегистрированный server ID из аккаунта и проверенный OAuth; [упаковщик](scripts/package_plugin.py) не выдумывает регистрацию.

Статус проверок и незакрытые критерии: [ACCEPTANCE](docs/ACCEPTANCE.md), [live runbook](docs/LIVE_ACCEPTANCE.md), [feasibility](docs/FEASIBILITY.md), [безопасность](docs/SECURITY.md), [ADR](docs/adr/). Версия продукта не повышается автоматически. Исходные ТЗ, ARCHITECTURE и CHATGPT_PROMPT сохранены и не включаются в distributable source ZIP.
