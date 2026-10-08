# Личный gateway 1.0.0-alpha.2

Это исходники и container recipe для внешнего личного шлюза. Контейнер не собран, домен не создан, OAuth и реальный ChatGPT вызов не проверены. Покупку сервера и публикацию выполняет владелец по отдельному указанию.

Сборка с корнем репозитория в качестве context:

```sh
docker build -f deploy/gateway/Containerfile -t ha-diagnostics-gateway:1.0.0-alpha.2 .
```

Entrypoint запускает `gateway/ha_diagnostics_gateway.py --data /data`. Процесс UID/GID10004 читает `/data/policy.json`, `/data/device-channel-key` и private enrollment files. Только собственный `/data` gateway монтируется **writable** для UID10004: enrollment/rotation создаёт фиксированные key/state/lock файлы. Secrets имеют mode0600, каталог mode0700; image filesystem можно оставить read-only. Secret не передаётся в аргументах, environment, Dockerfile или compose. Внешний gateway не получает SUPERVISOR_TOKEN, архив HA или исходные журналы. Policy содержит собственный публичный resource `https://ваш-домен/mcp`, issuer/JWKS/scopes, явно привязанный owner sub и тот же случайный installation ID, что HA local policy. Используйте тот же формат PolicyStore, что в приложении; не копируйте домашний `/data` целиком. Здесь предусмотрена одна installation и отдельный уникальный channel key. Текущий verifier принимает RS256/ES256 JWT; opaque tokens не поддерживаются. Для confidential-client introspection gateway читает отдельный `/data/introspection.secret`, также mode0600 UID10004, bounded≤8192bytes и без symlink; отсутствие обязательного secret закрывает старт. Provision этой отдельной внешней копии выполняет владелец через свой secret manager, не home `/data` export. Перед live release нужна полная проверка IdP flow.

Listener намеренно фиксирован на `127.0.0.1:8080`. Обычный Docker `-p 8080:8080` не делает его достижимым. Для production TLS proxy должен разделять **сетевое пространство имён gateway**: например, compose `network_mode: service:gateway`, с публикацией HTTPS443 контейнером, которому принадлежит это пространство. Proxy upstream тогда `http://127.0.0.1:8080`. Конкретный proxy, закреплённый image digest, DNS, сертификат и deployment-конфигурацию выбирает и проверяет владелец. Host network на домашнем HA для этого не нужен. Никакой proxy не развёрнут этим репозиторием.

Proxy пропускает только `/mcp`, `/.well-known/oauth-protected-resource`, `/channel/poll`, `/channel/result`, `/channel/enroll` и нужные методы. Сохраняйте оригинальные Authorization, MCP-Protocol-Version, Origin/Host по проверенной схеме; отключите запись body, Authorization, enrollment code, query и exception fragments в access/APM logs. Нужны корректные лимиты тела, timeout до30s для MCP и до25s для long polling; enrollment request≤1024bytes. TLS должен быть публично доверенным. Не превращайте proxy в произвольную маршрутизацию до HA или других адресов.

Владелец gateway через приватную локальную консоль выпускает одноразовый 256bit код (TTL≤5min):

```sh
python /opt/ha/gateway/local_enrollment.py --data /data issue --ttl 300
```

Вывод содержит только путь `enrollment-code.private`; код нужно приватно открыть локально и ввести getpass на HA:

```sh
python -m ha_diagnostics.local_setup --data /data --enroll-relay
```

Helper требует правильный local installation ID, отправляет fixed POST `/channel/enroll`, ограничивает strict request/response и сохраняет только выданный channel key в `/data/transport/relay-device-key` и origin в `relay.json`. Raw код удаляется после потребления, в state остаётся SHA256/TTL/used; повтор, истечение и чужая installation отклоняются. `issue` отзывает прежний key до создания нового code. Для отзыва без перевыпуска:

```sh
python /opt/ha/gateway/local_enrollment.py --data /data invalidate
```

Gateway перечитывает key и отменяет pending requests; проверка настоящего timing остаётся live gate. Код выдаётся gateway CLI, не HA UI; owner sub пока сверяется вручную и полный IdP-login/HA-admin pairing flow ещё требует приёмки. Code не является OAuth token, а MCP всё равно требует login/scopes/sub и локальную политику.

Transport UID10004 запускает отдельный relay worker, без HA token. Tunnel и relay не могут одновременно иметь config; helper не удаляет существующие настройки. После изменения владелец локально перезапускает только HA-Diagnostics. Relay делает исходящие GET `/channel/poll` и POST `/channel/result`, принимает только ограниченный MCP envelope и обращается исключительно к loopback MCP8000. Key канала отличается от OAuth пользователя и HA token. Прямой ручной ввод channel key через обычный helper остаётся advanced provisioning вариантом; он не доказывает enrollment acceptance.

Перед использованием: реальная сборка/inspect/SBOM/scan, проверка отсутствия секретов во всех логах, чужого sub/resource/channel key, timeout/replay/reconnect/revocation, upstream read-only spy, Inspector и диалог ChatGPT из [LIVE_ACCEPTANCE](../../docs/LIVE_ACCEPTANCE.md). Gateway видит очищенные выборки; полностью скрыть их от владельца внешнего сервера этот канал не обещает.
