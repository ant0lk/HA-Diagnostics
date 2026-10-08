# ADR-0002: частный Tunnel, outgoing fallback и зрелый IdP

Дата 2026-10-07; статус: условное решение, live transport/OAuth не принят.

Предпочтение владельца: Secure MCP Tunnel. Официальный runtime 0.0.16 имеет Linux amd64/arm64 artifacts с проверенными здесь checksum/ELF/SPDX. Выбран runtime-only flavor без cloudflared companion. Сам факт скачивания не доказывает работу в Linux/HA OS или права аккаунта.

Tunnel подключает только fixed loopback `/mcp`; `CONTROL_PLANE_POLL_CHANNELS=main` ограничивает канал, Harpoon callouts к HA не настраиваются, admin/health loopback, raw tracing/capture выключены. Key file owned UID10004, Supervisor token отсутствует. Runtime API key — ключ транспорта, не token HA и не требование запускать LLM через API.

Если Tunnel недоступен после проверки, личный HTTPS relay выбирается локально: outbound device channel к одному fixed TLS endpoint, OAuth пользователя независимо от channel credential, bounded requests/TTL/replay/cancellation/backoff. Шлюз видит очищенные результаты, постоянного облачного архива нет. Домашние порты автоматически не открываются, платные ресурсы не создаются.

IdP: не реализуем authorization server с нуля. Keycloak 26.8.0 закреплён как кандидат и подготовлен отключённый RP/empty redirect шаблон. Его новые resource indicators/CIMD экспериментальны, поэтому шаблон не доказывает зрелый полный MCP flow. Pre-registered code+PKCE client допустим только при подтверждении реальным builder. При недоступности выбирается зрелый IdP с готовым MCP flow; Auth0 описан официальным OpenAI guide. Требуются точный resource/aud, discovery, PKCE S256, scopes/sub, refresh rotation и отзыв, отрицательные токены. Нельзя обходить failed audience statically trusted token или принимать Core token.

Источники: [Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels), [OAuth](https://developers.openai.com/plugins/build/auth), [Keycloak MCP status](https://www.keycloak.org/securing-apps/mcp-authz-server).
