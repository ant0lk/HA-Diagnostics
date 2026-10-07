# Личный HTTPS fallback — подготовка развёртывания

Шлюз применяется только если аккаунт/архитектура/реальный вызов не позволяют Tunnel. Платные ресурсы, публикация и внешние DNS здесь не создавались. Нельзя считать source template работающим endpoint.

Внешние настройки владельца:

1. Личный домен MCP и отдельный HTTPS IdP; публично доверенный TLS, DNS, firewall. Внешний listener только /mcp + OAuth discovery + bounded outbound device-channel endpoints; admin endpoints не публикуются. Домашние входящие порты отсутствуют.
2. Выделенный небольшой server/runtime и безопасный secret manager. IdP candidate Keycloak и templates описаны в keycloak/; production DB/TLS/backup определяются владельцем. Не используйте `start-dev` или credentials из examples.
3. Соберите `deploy/gateway/Containerfile` с корнем проекта в качестве context; он запускает `gateway/ha_diagnostics_gateway.py --data /data`. TLS proxy должен разделять network namespace gateway: listener фиксирован на loopback8080 и обычный Docker port mapping недостаточен. Дополнение использует `src/ha_diagnostics/relay.py` для исходящего канала. Подробный [gateway runbook](gateway/README.md) перечисляет пути, ownership и внешние настройки. Получите реальные image digest и выполните gateway tests; готового опубликованного image нет.
4. Сверьте local installation ID и owner sub в policies HA и gateway. Выпустите одноразовый код через gateway local_enrollment.py `issue --ttl 300`, откройте его приватно локально. В HA запустите `python -m ha_diagnostics.local_setup --data /data --enroll-relay`: HTTPS origin обычным input, код через getpass, уникальный channel key сохраняется автоматически. Подробные команды в gateway/README.md. Relay и Tunnel config взаимоисключающие, bootstrap запускает relay worker UID10004 после локального перезапуска приложения. Channel key не OAuth token. Код выдаёт gateway CLI; полный HA-admin + IdP-login criterion остаётся непроверенным, owner sub пока manual.
5. Настройте server-side owner→installation, issuer/resource/audience/scopes/sub, fixed route/method allowlist, per-owner queue/concurrency, TTL≤30s, replay nonce и cancellation. Supplement повторно проверяет локальную политику; reconnect не исполняет expired запросы.
6. Ответы держатся лишь в bounded RAM buffer TTL≤60s; body/Authorization/query/log fragments исключены из proxy/APM/error logs. Не сохраняйте домашний поток в облачной DB. TLS защищает transit; gateway видит очищенные данные.
7. Проверяйте TLS/Origin/Host, code+PKCE S256, чужие ID/cursors, replay/revocation/reconnect, no HA write spy и реальный ChatGPT вызов по LIVE_ACCEPTANCE.md. Определите эксплуатационные alerts/recovery и стоимость перед запуском.

Актуальное назначение executable/config gateway сверяйте с README и CLI самих gateway исходников. Никакой неподтверждённый DNS, registered ID или callback в поставку не подставляется. Если runtime gateway не проходит необходимый flow, private transport acceptance остаётся незакрытой.
