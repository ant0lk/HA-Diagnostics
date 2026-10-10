# Проверка осуществимости — 2026-10-07

Версия продукта `1.0.0-alpha.6`. Документ фиксирует обнаруженные возможности и ограничения, а не удостоверяет готовность live MVP. ТЗ/ARCHITECTURE сохранены как входные документы, их критерии не ослаблены.

| Проверка | Подтверждено | Что остаётся |
|---|---|---|
| Локальный проект | Есть Windows workspace и Python runtime; исходные некоммитированные документы сохранены | Docker/HA OS не доступны в этой среде |
| Целевой HA | Владелец сообщил HA OS 18.0, Core 2026.9.4, Supervisor 2026.09.3, amd64, timezone Asia/Krasnoyarsk | Live чтение и права на этом узле не проверены |
| HA app packaging | config.yaml + Dockerfile + repository.yaml; amd64/aarch64; local build; Ingress 8099 | Сборка/установка и AppArmor на обеих архитектурах |
| API privileges | Supervisor manager нужен кандидату live broker, не является ролью чтения; import профиль отключает обе API flags | Реальная token injection import bootstrap и границы ОС |
| Ingress trust | На pinned Supervisor2026.09.3 proxy валидирует сессию и заменяет caller remote-user headers собственным ID | Actual peer/header, выбранный admin ID и CSRF на реальном HA |
| Python/MCP | Официальный `mcp` 2.3.0 выбран отдельно от версии продукта; протокол согласуется SDK | Actual initialize/Inspector отчёт в ACCEPTANCE |
| Private plugin | Portable Agent Plugins 1.0.0 manifest, skill; зарегистрированное mapping отдельно | Реальный `plugin_asdk_app...` отсутствует, пакет подключения не выдуман |
| Secure MCP Tunnel | Официальный v0.0.16 runtime Linux amd64/arm64 скачан; SHA256/sidecar/SPDX/ELF подтверждены | Linux запуск, аккаунт/workspace права, doctor/readiness, реальный tool call |
| OAuth | Resource server должен проверить issuer/audience/expiry/scopes/sub; отдельный HA token | IdP и authorization code + PKCE S256 в реальном ChatGPT ещё не испытаны |
| Keycloak | 26.8.0 digest/realm template для IdP-кандидата | resource-indicators/CIMD экспериментальны; принятый flow пока отсутствует |
| Fallback | Подготовка личного HTTPS relay, исходящий канал и внешние настройки | Домен/TLS/IdP/VPS владелец ещё не выбрал; развёртывание не выполнялось |
| Привязка владельца | Local owner sub binding; HTTPS relay enrollment code gateway CLI, TTL≤300s, одноразовый обмен на unique channel key | Полный HA-admin + подтверждённый IdP login flow непроверен; sub остаётся manual, code не выдаётся HA UI; критерий не закрыт |

Минимальная **заявленная цель совместимости**, до живой приёмки: HA OS 18.0, Supervisor 2026.09.3, Core 2026.9.4; amd64 первым, aarch64 второй стенд. Это не утверждение о проверенной поддержке. Самостоятельный import-only контейнер вне Supervisor нужен для свойства «HA credentials не выдаются вообще». Import HA app удаляет возможный bootstrap token до рабочих процессов; наличие token injection проверяется отдельно.

Ссылки официальной проверки:

- [HA app configuration](https://developers.home-assistant.io/docs/apps/configuration/): build.yaml больше не используется; FROM/LABEL/ARG находятся в Dockerfile. API flags, roles, Ingress и минимальный Core задаются config.yaml.
- [HA publishing](https://developers.home-assistant.io/docs/apps/publishing/), [Supervisor endpoints](https://developers.home-assistant.io/docs/api/supervisor/endpoints/), [REST](https://developers.home-assistant.io/docs/api/rest/), [WebSocket](https://developers.home-assistant.io/docs/api/websocket/).
- [Pinned Supervisor Ingress](https://github.com/home-assistant/supervisor/blob/2026.09.3/supervisor/api/ingress.py): доверие UI требует настоящего proxy peer + локально закреплённого admin ID; product не выполняет POST `/ingress/validate_session`.
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk), [authorization 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization), [transports](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports). Протокол не следует версии продукта.
- [OpenAI plugin packaging](https://developers.openai.com/plugins/build/plugins): root plugin.json, skills/, optional mcp.json; OpenAI mapping только с реальным зарегистрированным ID. [Custom MCP](https://developers.openai.com/api/docs/guides/custom-mcp-server), [connection testing](https://developers.openai.com/plugins/deploy/connect-chatgpt).
- [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels): исходящий HTTPS, runtime API key, организация/workspace права; private доступ не заменяет public endpoint для публикации. [v0.0.16 release](https://github.com/openai/tunnel-client/releases/tag/v0.0.16) и [runtime source guide](https://github.com/openai/tunnel-client/blob/v0.0.16/README.md).
- [OpenAI OAuth](https://developers.openai.com/plugins/build/auth): callback и client metadata берутся из реальной страницы MCP; mature IdP рекомендован. [Keycloak MCP](https://www.keycloak.org/securing-apps/mcp-authz-server) официально называет новые resource indicators/CIMD экспериментальными.

Платформенные возможности документированы, но доступ конкретного аккаунта неизвестен. На текущем этапе можно закончить локальную alpha-поставку и воспроизводимые fixtures/contract проверки. HA-01/02, GPT-01/02, SEC-08 и OPS-01 нельзя закрыть этими данными.

В alpha имена и identifiers всегда псевдонимизируются; режим раскрытия исходных имён не реализован. Журналы собираются polling/backfill snapshots; fixture continuity/rotation не доказывает latency настоящего streaming follow. Inspector, реальный OAuth flow, HA OS и диалог ChatGPT остаются отдельными непроверенными уровнями.
