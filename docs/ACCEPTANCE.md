# Фактическая проверка HA-Diagnostics 1.0.0-alpha.1

Дата: 2026-10-07. Закончен доступный локальный alpha-этап: исходники, import-only запуск, отрицательные проверки, контракты и подготовленная установка. **Полный MVP по исходному ТЗ ещё не принят.** ТЗ, ARCHITECTURE и пользовательский CHATGPT_PROMPT сохранены; критерии live-приёмки не изменены. Коммитов, push, публикации, регистрации в чужом аккаунте и платной инфраструктуры не было.

## Что проверено

Последний полный прогон: **237 passed, 1 skipped**, 52,26 s по выводу pytest. Пропуск: Windows не позволил создать настоящий symlink в проверке защищённых gateway-файлов. Соответствующая Linux проверка остаётся обязательной. Предыдущие неуспешные прогоны не считаются приёмкой; после compaction тест backfill проверяет 24 отдельных upstream GET и сохранённый полный интервал unknown, вместо количества внутренних coverage-строк.

Среда: Windows, Python 3.12.14, SQLite 3.53.1, MCP SDK 2.3.0. Контейнерная база закреплена на Python 3.13.12, но её выполнение здесь не проверено. Database schema **2**, output/data schema **1**; версия продукта осталась **1.0.0-alpha.1**.

| Уровень | Реальное свидетельство | Граница результата |
|---|---|---|
| Broker / upstream spy | Конечные GET и read WebSocket команды; неизвестные операции/пути, управление и redirects запрещены; локальный HTTP302 handshake проверен | Mock/source fixtures, без настоящего Supervisor |
| Архив / импорт | Multiline, boot/rotation/reconnect, Recorder overlap без слияния live repeats, type-preserving значения, quota/retention/disk gaps, миграция v1→v2, очищенный FTS | SQLite/fixtures; не 24h сбор на HA |
| Coverage | Sweep для 10 000 интервалов, худший статус, compact одинаковых zero-loss markers, loss counts не потеряны и не удвоены | Счётчик clipped gap описывает целый пересекающийся marker; точное время потерь неизвестно |
| Авторизация | Подписи RS256, iss/aud/sub/scopes/expiry, запрет Core+MCP multi-audience, revocation local policy, foreign refs/IDs/cursors и approvals | JWT/ASGI fixtures; полный login/PKCE/refresh у IdP не пройден |
| MCP SDK | Настоящий SDK HTTP: legacy 2025-11-25 initialize и modern 2026-07-28 self-contained запрос; 10 tools; все фактические outputs валидны по опубликованным schemas | Не Inspector и не вызов из ChatGPT |
| Bootstrap | Descriptor-relative O_NOFOLLOW/O_DIRECTORY, fstat/fchown/fchmod; root storage, bounded options, отказ symlink/hardlink до spawn | Mocked Linux FD contract и настоящие Windows hardlinks; Linux ownership/mount/race ещё непроверены |
| Лимиты | 64 KiB UTF-8 response, adaptive pagination без потери evidence IDs, 30 calls/min, 2 inflight до body/JWKS, 401/403/413/429/Host rejection | Локальные поведенческие проверки |
| Локальная панель | Настоящий loopback HTTP200 после перезапуска; ASGI import preview→commit→approve→revoke→delete; CSRF/Ingress spoof rejection; evidence, audit и очищенный локальный предпросмотр последних 10 записей | Локальный browser: светлая панель, ширина360px без page overflow, Tab/Enter навигация, тёмный предпросмотр synthetic fixture. HA Ingress UI ещё не проверен |
| HTTPS fallback | Single-use 256-bit code, TTL≤300s, foreign installation/replay/expiry deny, key rotation и cancellation, outgoing fixed-origin channel | Настоящий MCP SDK через ASGI gateway→relay: modern list/call, routing mismatch, OAuth/429 headers и legacy202. TLS gateway не развёрнут |
| Supply / packaging | Locks с hashes, pip check, Python/JS syntax, Tunnel SHA256/ELF/SPDX/license sidecars обеих архитектур, portable plugin schema, Python lock SBOM CycloneDX1.6 | Нет product image build/digest, Linux Tunnel execution, Sigstore signature или image vulnerability scan |

Браузерные свидетельства на synthetic data: [панель](verification/ui-desktop.jpg), [360px](verification/ui-mobile.jpg), [очищенный предпросмотр](verification/ui-preview.jpg).

Машиночитаемый отчёт и очищенный JUnit: [local-checks.json](verification/local-checks.json), [pytest-junit.xml](verification/pytest-junit.xml). Они не содержат process environment, credentials, домашние журналы или hostname компьютера. Сведения о supply-chain отдельно в [containers/VERIFICATION.json](../containers/VERIFICATION.json).

## Небольшой воспроизводимый benchmark

Четыре искусственных источника, 10 000 записей, 788 406 исходных bytes; сохранены все 10 000. Anchor `2026-10-07T08:00:00Z`, generator `deterministic_index_v1`; SHA256 fixture и параметры находятся в JSON отчёте. Замеры с tracemalloc: ingestion 22,372s, process CPU 19,5s, p95 100 archive queries 72,029ms, summary 52,017ms; SQLite+WAL+SHM 10 883 072 bytes, Python heap peak 996 190 bytes.

**Python heap не является RSS.** Эти числа не доказывают лимит RAM300MiB/CPU10%, million-record fixture, steady/burst, follow freshness или HA hardware SLO. Нагрузочный и 24h soak критерии остаются открытыми.

```powershell
.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider --basetemp .test-results\fresh-run --junitxml=.test-results\fresh-junit.xml
.\.venv\Scripts\python.exe scripts/benchmark_archive.py --output .test-results\fresh-benchmark --records 10000 --anchor 2026-10-07T08:00:00Z
```

Для pytest заранее создайте родитель `.test-results`; используйте новое имя basetemp. Benchmark отказывается перезаписывать каталог. Полный ресурсный стенд описан в LIVE_ACCEPTANCE; raw домашние данные для synthetic generator не нужны.

## Что остаётся сделать

1. На Linux собрать Import/Live образы из `dist/ha-addons`, сохраняя tag1.0.0-alpha.1; записать фактические digests, image SBOM и scan. Затем установить оба профиля на HA OS amd64 и aarch64 в Protected mode/AppArmor. Docker отсутствует, WSL не установлен в текущей среде.
2. Проверить Linux UID/credentials/IPC, `/proc`, permissions, backup exclusions и отсутствие usable HA token у query/UI/transport. Manager token даёт широкие полномочия trusted broker: его компрометация остаётся явным риском.
3. На вашем HA OS18.0/Core2026.9.4/Supervisor2026.09.3 подтвердить Ingress admin ID, фактическое чтение Core/Supervisor/девяти перечисленных владельцем addon logs, timezone Asia/Krasnoyarsk, registry, current snapshots и Recorder; сверить исходные HA данные локально. Попытка unauthenticated GET из этой среды не достигла Core; защищённое чтение не проверялось.
4. Проверить custom MCP/Tunnel в аккаунте, запустить закреплённый runtime на обоих Linux CPU и получить реальный вызов. Runtime API key — транспортный, не HA token и не требование использовать LLM API.
5. Выбрать принятый зрелый IdP и пройти полный PKCE S256/resource/audience/scopes/sub/refresh/revocation flow. Keycloak candidate template с экспериментальными MCP функциями не считается решением этого gate. Подтвердить связку HA admin + IdP owner; ручной sub и gateway code сами по себе login не доказывают.
6. Зарегистрировать настоящий MCP server, собрать plugin mapping по выданному registered ID и проверить установку/отзыв в ChatGPT, затем диалоги из GPT-01/02. Базовый ZIP сейчас содержит только skill; он не даёт самостоятельного доступа к HA.
7. Если Tunnel недоступен, развернуть подготовленный личный HTTPS gateway с TLS и IdP, выполнить single-use enrollment, живой reconnect/revoke roundtrip. Домашние входящие порты продукт не открывает.
8. Завершить Inspector, полный UI сценарий HA Ingress, million-record fixture, 15min steady/60s burst, aggregate RSS/CPU/freshness и 24h soak. Сохранить безопасные evidence по исходным ID критериев из ТЗ.

Alpha-ограничения: имена всегда псевдонимизируются; до1000 разрешённых сущностей,20MiB/50000строк bounded log backfill; polling не доказывает completeness/healthy-follow latency. MCP log pages сокращают сообщение до8KiB UTF-8; `get_log_record` возвращает более полный контекст до16000 символов и бюджета48KiB, с явным truncated. Одобрение неизвестных секретов требует локального предпросмотра; правила не гарантируют обнаружение любых credentials.

Установка, безопасный ввод секретов и отзыв: [INSTALL](INSTALL.md). Приёмка без пересмотра критериев: [LIVE_ACCEPTANCE](LIVE_ACCEPTANCE.md).

Финальный source ZIP находится в `dist/source-final`; `dist/source` — промежуточная собственная сборка до security исправлений. Для установки используйте актуальные `dist/ha-addons` или ZIP из `dist/ha-install`.
