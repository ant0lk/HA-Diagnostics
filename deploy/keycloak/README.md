# IdP-кандидат, не подтверждённая OAuth-интеграция

Keycloak 26.8.0 закреплён по OCI digest. Mature IdP используется для login/code/PKCE, но его поддержка MCP resource-indicators/CIMD официально экспериментальная. Поэтому шаблон **нельзя считать принятым full MCP flow** до живой проверки. Альтернатива — уже используемый зрелый провайдер с подтверждёнными MCP discovery/PKCE/resource, например официальный OpenAI guide указывает Auth0.

`realm.template.json` не содержит пользователей, паролей и callback. RP отключён, allowlist redirects пуст; случайная установка не создаёт доступ. Подставляйте значения только в локальную копию вне репозитория. `resource_url` должен быть точным ресурсом из metadata; для HTTPS fallback обычно `https://ваш-домен/mcp`, для Tunnel — фактический logical resource из custom MCP настройки, проверенный в discovery. Не заменяйте проверку audience клиентским ID.

1. Разверните IdP на своём HTTPS-домене с PostgreSQL, TLS, backup/recovery и безопасным secret manager; платная инфраструктура требует отдельного решения владельца.
2. Соберите Containerfile и запустите production `start --optimized`; `start-dev` не подходит. DB/admin пароли передаются secret manager, не argv, не пакет.
3. Импортируйте локальную realm-копию. Существующий RP вручную зарегистрируйте в ChatGPT, если текущий builder поддерживает pre-registered client; точный redirect скопируйте с новой страницы подключения, внесите без wildcard. Затем включите RP.
4. Если pre-registered flow недоступен, выберите CIMD/DCR и создайте ограниченную client policy по текущему официальному руководству. Не включайте открытую DCR. CIMD требует дополнительных экспериментальных настроек и SSRF/redirect/size испытаний; автоматически они не включены.
5. Отправьте `resource` в authorization **и** code exchange. Подтвердите token aud, iss, sub, exp, nbf, scope, PKCE S256, запрещённые grants и reuse code. Проверьте другой resource → invalid_target, другую установку/sub → отказ.
6. JWKS/issuer/resource и owner binding настройте локально в HA-Diagnostics. Токен не должен работать на Core. Проверьте refresh rotation, revocation, reconnect и отрицательные случаи из runbook.

Официальные источники: [Keycloak MCP](https://www.keycloak.org/securing-apps/mcp-authz-server), [containers](https://www.keycloak.org/server/containers), [OpenAI authentication](https://developers.openai.com/plugins/build/auth).
