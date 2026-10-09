# CHANGELOG

## 1.0.0-alpha.5 — 2026-10-09

ZIP includes retained automation/script traces, Repairs, notifications, System Health/System Log, device diagnostics, floor/label registries, host services/disk/swap and Supervisor jobs/repositories. Recorder metadata/issues and up to 64 daily statistic series for seven days are exported. Referenced blueprints, YAML dashboards and literal Jinja imports are read without execution. Host overview JSON/TXT, previous-archive comparison (including Alpha 4), observed coverage and pseudonymized network traits are included. Read operations and limits remain fixed; missing API/data is explicit. No background event/load collection. HA OS acceptance remains unverified.

## 1.0.0-alpha.4 — 2026-10-08

Live ZIP includes sanitized HA YAML/includes, saved UI/helper settings, integration data/options and Supervisor addon settings. `configuration/index.json` records origins and gaps. Home Assistant config is mounted read-only; secrets/env tags are not evaluated and secret fields/password schema options are redacted before writing. File/path/size limits are enforced. Daily scheduling and 7 automatic / 3 manual archive retention remain. Private addon files and live HA OS acceptance are outside local verification.

## 1.0.0-alpha.3 — 2026-10-08

Ежедневные автоархивы включены по умолчанию: сбор в 03:00 по часовому поясу Home Assistant. В панели можно изменить время или отключить расписание без перезапуска; настройки и отметки запусков сохраняются. Автосбор работает при закрытой панели, пропущенный сегодняшний запуск догоняется после запуска дополнения. Хранятся отдельно последние 7 автоматических и 3 ручных ZIP без прежнего удаления через 24 часа. Старые ZIP Alpha 2 распознаются как ручные. В каждый новый архив добавлен `ARCHIVE_STRUCTURE.txt` с названием ZIP и полным деревом фактического содержимого; manifest включает тип сбора и SHA-256 файла структуры.

## 1.0.0-alpha.2 — 2026-10-08

Основной сценарий изменён на сбор и скачивание диагностического ZIP: все доступные журналы, системные сведения, каталоги, диагностика интеграций, история и события за 24 часа. Добавлены прогресс, отмена, защищённое скачивание, manifest с пробелами и SHA-256, очистка до записи. В ZIP-режиме MCP/OAuth/Tunnel не запускаются. Предыдущие компоненты сохранены отдельно.

Настройка Secure MCP Tunnel через локальную панель: Tunnel ID и скрытый runtime key, атомарное сохранение, отдельный transport worker и требование перезапуска. OAuth и реальный вызов ChatGPT проверяются отдельно.

## 1.0.0-alpha.1 — 2026-10-07

Предварительная alpha-поставка: локальные Import/Live профили, ограниченный диагностический контракт, исходники и воспроизводимая упаковка. Реальная установка на HA OS amd64/aarch64 и диалог ChatGPT требуют отдельной приёмки. Версия продукта закреплена; схемы и MCP имеют независимые версии.
