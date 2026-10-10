# ADR-0003: source build contexts и portable private plugin

Дата 2026-10-07; статус: принято для source alpha, установка ожидается.

Версия HA app и plugin `1.0.0-alpha.8`, контейнерные build tags такие же. JSON Schema 1.0 и MCP protocol версии самостоятельны. Цель baseline HA OS18.0 / Core2026.9.4 / Supervisor2026.09.3, amd64; aarch64 обязателен для финальной приёмки, но здесь не испытан.

База: glibc Python3.13.12 slim-bookworm по OCI index digest и обоим platform manifests в supply-chain.lock.json. Это позволяет не предполагать Alpine ABI для Tunnel. Python packages закрепляются requirements.lock с hashes. Build.yaml не включён: текущая HA документация перевела FROM/LABEL/ARG в Dockerfile.

Архив требует SQLite≥3.40.0 с FTS5: индекс очищенных logger/message и фиксированные triggers, database schema2 с миграцией существующей schema1. Версия output/data schema остаётся1. Локальная проверка использовала SQLite3.53.1; SQLite внутри pinned Linux image ещё не запущен и проверяется отдельным release gate. FTS5 secure-delete включается условно при наличии функции; обычная FTS работа совместима с3.40. Core PRAGMA secure_delete не доказывает удаление всех forensic traces.

FTS5 secure-delete появился в3.42 и после update/delete делает индекс несовместимым с более старым SQLite, пока его не rebuild на совместимой версии. Поэтому development DB3.53 нельзя автоматически переносить в image со SQLite3.40: используйте новый archive или заранее проверенную миграцию/восстановление своих очищенных copies; rollback проверяет и engine, и DB/FTS format. Источник: [официальный FTS5 secure-delete](https://sqlite.org/fts5.html#the_secure_delete_configuration_option).

App contexts генерируются из allowlisted src/schemas/web/lockfiles; не копируют пользовательские state/secrets/.venv/.git. Import и Live — отдельные staged apps. Local build используется, registry image field отсутствует: публикации образов не было. Финальный immutable product digest появится только после реальной сборки и фиксируется отдельным отчётом, без изменения версии.

Plugin root plugin.json использует Agent Plugins1.0.0 schema; skill и references поставляются независимо от custom MCP регистрации. Базовый skills-only пакет устанавливаем, но не имеет диагностики без подключённого сервера. Персональный builder требует реальный plugin_asdk_app ID и генерирует .app.json mapping. Portable mcp.json можно создать по реальному HTTPS URL; он не удостоверяет ChatGPT регистрацию. Никаких hooks, credentials, вымышленных IDs.

Источники: [HA packaging](https://developers.home-assistant.io/docs/apps/configuration/), [portable plugin](https://developers.openai.com/plugins/build/plugins), [Agent Plugins schema](https://agent-plugins.org/schemas/1.0.0/plugin.schema.json).
