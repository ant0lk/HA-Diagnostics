# Установка HA-Diagnostics 1.0.0-alpha.6

Alpha 5 добавляет трассы автоматизаций/скриптов, Repairs, уведомления, System Health/System Log, диагностику устройств, этажи/метки, задания/репозитории Supervisor, службы хоста, диск/swap и статистику Recorder (до 64 рядов за 7 дней). В configuration входят используемые blueprints, YAML-панели и буквальные Jinja-импорты без исполнения. system/overview.json и .txt содержат паспорт хоста: ресурсы ядра отдельно от контейнерных лимитов, версии, оборудование, сеть и дополнения. comparison/ сравнивает настройки, установленные версии и реестры с предыдущим сохранённым ZIP, включая Alpha 4. Недоступные данные и пределы сбора отражаются в manifest; фоновое накопление событий/нагрузки не включено.

## Основной сценарий: ZIP

Для скачивания диагностического архива используйте дополнение `ha_diagnostics_live/` (HA-Diagnostics — ZIP diagnostics). Slug сохранён, версия — `1.0.0-alpha.6`. Укажите `ingress_admin_id` администратора в конфигурации дополнения, запустите его, откройте веб-интерфейс и нажмите «Собрать ZIP-архив», затем «Скачать ZIP». История и события — последние 24 часа, логи — весь доступный сохранённый период. Protected mode должен оставаться включённым. Автосбор включён по умолчанию в 03:00 по поясу HA; время и включение меняются в панели. Хранятся последние 7 автоархивов и 3 ручных ZIP.

Alpha 4 добавляет mount конфигурации HA в `/homeassistant` только для чтения. После обновления дополнения проверьте `configuration/index.json`: должны читаться YAML и `.storage/core.config_entries`; options/schema дополнений берутся из Supervisor info. Если файлы недоступны по правам, архив укажет `CONFIG_PERMISSION_DENIED`, остальные источники сохранятся. Установка на стенде должна подтвердить readonly mount; приложение не изменяет права или настройки HA. Подробный состав: [ZIP_EXPORT](ZIP_EXPORT.md).

MCP, OAuth, Tunnel и HTTPS relay для ZIP не настраиваются и не запускаются. Состав, очистка, пределы и отчёт о пробелах описаны в [ZIP_EXPORT.md](ZIP_EXPORT.md). На HA OS необходимо проверить обновление установленного дополнения, Ingress, доступность реальных API и скачивание.

Ниже сохранены инструкции предыдущего режима MCP; для него нужен явный `--workflow mcp` / `HAD_WORKFLOW=mcp`.


Это предварительная alpha-поставка исходников и пакетов. Реальные Linux контейнеры/HA OS/ChatGPT ещё требуют приёмки из LIVE_ACCEPTANCE.md. Не открывайте домашний HA наружу. Без завершённой локальной настройки удалённое чтение закрыто.

## 1. Проверка поставки и сборка

Нужен Python3.13 на машине сборки. Локальные тесты этой сессии могли выполняться bundled Python другого patch/minor: точный отчёт находится в ACCEPTANCE.md. Dependencies устанавливаются из hash-pinned `requirements.lock`. Не используйте реальные логи в тестовой fixture и не копируйте `/data` в репозиторий.

```powershell
python -m pip install --require-hashes -r requirements.lock
python scripts/verify_supply_chain.py
python scripts/package_release.py --with-tunnel
python scripts/package_plugin.py
```

Tunnel archives в `containers/vendor/` не включаются в Git. Если их нет, выполните `python scripts/verify_supply_chain.py --download`: он скачает три закреплённых файла для каждой архитектуры (archive, SPDX, licenses) и проверит supply-chain.lock.json, не исполняя бинарники. GitHub release CDN redirects допустимы только в этом downloader, не broker. `--with-tunnel` включает только проверенные bytes и лицензии; без флага контекст создаётся без Tunnel. Обновление binary не выполняется на старте.

Скрипты отказываются перезаписывать существующий dist package. Сначала сохраните/переместите предыдущую локальную поставку вручную, затем создайте новую; версия не повышается автоматически. ZIP плагина и файлы build context имеют SHA256SUMS. Base OCI digest зафиксирован, но готовый product image digest появляется лишь после сборки.

`python scripts/package_source.py` создаёт отдельный source ZIP с runtime, UI, schemas, tests/обезличенными fixtures, gateway, deploy, lockfiles и безопасным local verification report. Конечный allowlist исключает AGENTS.md, входные TECHNICAL_SPEC/ARCHITECTURE/CHATGPT_PROMPT, Git metadata, vendor cache, dist и runtime state. Этот архив не заменяет review исходников на неизвестные секреты. Лицензия самого продукта ещё не назначена; upstream Tunnel licenses/NOTICE входят в проверенный app payload, его runtime SBOM — отдельный artifact.

На Linux Docker builder (в этой Windows среде Docker не обнаружен):

```sh
docker buildx build --platform linux/amd64 --build-arg BUILD_ARCH=amd64 --load -t ha-diagnostics-import:1.0.0-alpha.6 dist/ha-addons/ha_diagnostics
docker buildx build --platform linux/amd64 --build-arg BUILD_ARCH=amd64 --load -t ha-diagnostics-live:1.0.0-alpha.6 dist/ha-addons/ha_diagnostics_live
```

Повторите build для linux/arm64 на соответствующем runner. Ничего не push. Перед live release сохраните `docker image inspect` digest, image SBOM, vulnerability scan и actual runtime результаты. `build.yaml` отсутствует согласно текущему HA packaging; зависимости копируются внутрь staged app context.

`python scripts/verify_supply_sbom.py` создаёт локальный inventory Python lock. Опциональный `--audit` требует заранее установленный проверенный `pip-audit2.10.1` и явно обращается к публичному advisory service; ничего не устанавливает/исправляет. Это не scan собранного image: подробности в `containers/SBOM.md`.

## 2. HA OS приложение

Первый стенд: amd64, HA OS18.0/Core2026.9.4/Supervisor2026.09.3, timezone HA Asia/Krasnoyarsk (сообщено владельцем). Это цель acceptance, пока не проверенная support матрица.

1. Владелец через свой штатный доступ размещает выбранную **staged** папку из `dist/ha-addons/` в `/addons/` HA OS, обновляет магазин локальных приложений и устанавливает её. Исходная `ha_diagnostics/` без `app/` не является самостоятельным Docker context. Не заменяйте config на чужие image references.
2. Начните с `HA-Diagnostics — Import`. Protected mode/AppArmor включены; ни Docker socket, ни host mounts, ни ports, ни host network не нужны. Приложение не удерживает HA credentials в workers; выдача token bootstrap Supervisor проверяется отдельно.
3. Для panel access в HA options задайте `ingress_admin_id` — идентификатор своего HA администратора; пока личность администратора не подтверждена, backend показывает `INGRESS_ADMIN_NOT_VERIFIED` и закрывает изменения. Пустой default оставляет панель закрытой. Сам ID не секрет; заголовок пользователя от прямого клиента не даёт админ-доступа. Не включайте demo режим на HA OS. Возможность получения этого ID и actual Ingress headers на целевой HA версии сверяется локально, без угадывания/подмены trust gate.
4. В панели импортируйте .log/.txt/.json до 20MiB, посмотрите очищенный предпросмотр. Исходник не хранится; разрешение передавать конкретный импорт задаётся отдельно. В этой alpha персональные имена/IP/MAC всегда псевдонимизируются; переключения на исходные имена пока нет.
5. `HA-Diagnostics — Live alpha` — отдельное приложение с broad manager token у broker. Установку используйте для контролируемого испытания, затем выберите конечный список реально обнаруженных источников и разрешённых диагностических сущностей. «Все допустимые» означает сохранить перечисленный локальный набор, не wildcard API-доступ. Camera/media/person/geolocation в MCP не включаются.
6. Сверьте чтение Core/Supervisor/addon/Recorder с эталоном, проверьте /proc/env/IPC негативные проверки прежде, чем разрешать удалённое чтение. При провале границы прекратите live profile; import продолжает работать.

Standalone `Dockerfile.import` вне Supervisor нужен, если HA credential не должен выдаваться даже bootstrap. Его можно собрать локально с тегом `ha-diagnostics-import:1.0.0-alpha.6`; по умолчанию он не публикует порт и не имеет сессии HA Ingress. Для панели нужен отдельный проверенный локальный admin/development доступ — это не HA Container live поддержка.

## 3. OAuth и безопасная локальная настройка

Не присылайте tokens, пароли, runtime key или client secret в чат. Они не нужны package builder. OAuth issuer/JWKS/resource, owner sub и transport secrets вводятся только владельцем в локальной настройке приложения; файлы secret имеют отдельный private UID и не включаются в exports/backup/поставку.

Для IdP используется зрелый provider. `deploy/keycloak/` содержит candidate template, без credentials и callback. Современные resource/CIMD функции Keycloak экспериментальны; до полного code+PKCE/resource испытания этот шаблон не является принятой OAuth-интеграцией. При наличии готового MCP IdP предпочтителен уже проверенный провайдер.

Нужны scopes `diagnostics:read`, `history:read`, `artifacts:read`, точный audience/resource и локальный owner binding. Callback URI/client metadata скопируйте со страницы нового custom MCP server в текущем аккаунте; никаких wildcard и старых callback примеров. В этой alpha владелец вручную вводит и сверяет собственный неизменный `sub` из проверенной учётной записи IdP в локальной панели. Для HTTPS relay реализован одноразовый gateway-issued код TTL≤300s и локальный скрытый ввод в приложении; подробности ниже. Код выдаётся private gateway CLI, а не HA UI, и один лишь введённый sub не доказывает login. Полный критерий «HA administrator + подтверждённый IdP login» остаётся открытым до live-приёмки, включая корректность этой последовательности. MCP token не работает на Core. Проверка доступа повторяется при каждом вызове; старые cursors отзываются сменой политики.

Секреты вводятся через helper **внутри установленного приложения**, в локальной интерактивной root-консоли владельца:

```sh
python -m ha_diagnostics.local_setup --data /data
```

Helper спрашивает несекретный Tunnel ID, затем скрыто через getpass — runtime API key. Если Tunnel ID пустой, он предлагает единственный HTTPS origin личного relay и скрыто спрашивает device-channel key. Затем, если IdP требует introspection authentication, вводится отдельный client secret. Enter пропускает ненужный вариант. При отсутствии безопасной интерактивной консоли helper закрывается с ошибкой; перенаправление stdin, secret в аргументе или environment не используется. Он не обращается в HA/OpenAI/IdP и не регистрирует connection. Запуск такого helper — локальная настройка приложения владельцем, не MCP tool и не HA service call.

На Linux запись атомарная, фиксированные имена имеют mode0600. После штатного перезапуска приложения bootstrap назначает transport key UID10004 и `/data/query/introspection.secret` UID10002; соответственно каталоги закрыты другими процессами. Tunnel хранит `/data/transport/tunnel.json` и `control-plane-api-key`; relay — `/data/transport/relay.json` с единственным `origin` и отдельный `relay-device-key`. Tunnel и relay взаимоисключающие: существующий другой config не перезаписывается, helper возвращает TRANSPORT_CONFLICT. Переключение требует локального удаления прежних transport config/key владельцем и отзыва старого ключа. Introspection secret нужен query-процессу для проверки MCP OAuth и не является HA credential. Проверьте `stat` без чтения содержимого файлов и затем проверки /proc/IPC по runbook. Supervisor token вручную не вводится. Helper в Windows поддерживает только development и не доказывает Linux ownership/ACL. Если безопасная локальная консоль приложения пока недоступна, не обходите её отправкой секретов в чат: transport setup остаётся незавершённым.

## Настройка туннеля через панель (alpha.2)

В HA-Diagnostics откройте «Подключение ChatGPT», введите Tunnel ID и runtime API key, нажмите «Сохранить туннель». Затем перезапустите только HA-Diagnostics на странице приложения Home Assistant. Terminal & SSH для этого не нужен. Доступ к форме защищён проверкой администратора HA Ingress и CSRF.

Пара ID/key сохраняется атомарно в `/data/transport/tunnel-settings.json`, mode0600, UID10004; UI не читает ключ обратно. Отдельный процесс transport-setup не получает HA credential; broker и MCP/query не имеют доступа к файлу или операции. На старте bootstrap подготавливает отдельный файл ключа для Tunnel runtime. При наличии настроек панели CLI helper не перезаписывает их. Существующий relay блокирует настройку туннеля. Сохранение не меняет policy remote_enabled, не создаёт OAuth и не подтверждает доступность ChatGPT. Demo позволяет проверить только форму и локальное сохранение; секреты production в demo не вводятся.

## 4. Проверка доступности Secure MCP Tunnel

Откройте [ChatGPT Plugins](https://chatgpt.com/plugins), плюс → Add custom MCP server → Connection. Если есть Tunnel, откройте [Platform tunnels](https://platform.openai.com/settings/organization/tunnels) и проверьте связь вашей Platform organization с целевым ChatGPT workspace. Runtime/использование требует Tunnels Read+Use; создание/изменение Read+Manage. Наличие меню не доказывает разрешения и рабочий вызов. [Официальный runbook](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels).

Создайте runtime key на Platform только для transport principal; это не ключ HA и не просьба запускать модель через API. Admin key в runtime не нужен. Введите его через `local_setup` выше; хранение `/data/transport/control-plane-api-key` mode0600 UID10004 после bootstrap. Tunnel ID — не credential доступа к дому. Не настраивайте HTTP callouts/Harpoon к HA.

На целевой архитектуре сначала выполните `tunnel-client-runtime --version`, `run --help` и ELF/ABI smoke. Полный отдельно установленный официальный client поддерживает `help quickstart`/`doctor`, узкий bundled runtime поддерживает только `run`/flags. Проверку readiness и реальные discovery/tool calls выполните в аккаунте. App runtime пересылает только fixed loopback `http://127.0.0.1:8000/mcp`, poll main, без public admin listener и raw logs. Внешний IdP должен быть доступен участникам login; Tunnel не публикует его автоматически.

Если Tunnel недоступен, следуйте `deploy/README.md`: личный HTTPS gateway, TLS, IdP и исходящий канал к одному домену. Покупка/публикация/развёртывание выполняются только по отдельному указанию. Сам HA наружу не публикуется.

Для initial relay binding владельцу нужно совпадающее `installation_id` в локальной HA policy и собственной gateway policy. HA создаёт случайный ID при первом старте; посмотрите его в локальной панели, не угадывайте и не подставляйте default `local`. После настройки IdP/owner/resource на обеих сторонах выпустите код на gateway:

```sh
python /opt/ha/gateway/local_enrollment.py --data /data issue --ttl 300
```

CLI печатает только путь `/data/enrollment-code.private`. Откройте файл только через приватный локальный доступ владельца; не копируйте код в чат, screenshot, command arguments или logs. На HA в интерактивной root-консоли запустите:

```sh
python -m ha_diagnostics.local_setup --data /data --enroll-relay
```

Origin вводится обычным input, код — getpass. Helper делает единственный fixed HTTPS POST `/channel/enroll`, проверяет installation ID и bounded strict response, сохраняет выданный уникальный key600. Code consumption одноразовое, raw code удаляется на gateway; повтор/expiry/foreign installation закрыты. После этого локально перезапустите только HA-Diagnostics и выполните полный OAuth/Inspector/ChatGPT runbook. Для rotation снова `issue`, для отзыва gateway `invalidate`; оба немедленно убирают прежний channel key. Прямое ручное provisioning device key остаётся advanced вариантом и не заменяет приёмку enrollment flow. TLS/domain/IdP ещё не развёрнуты.

## 5. Частный плагин

1. Подключите и протестируйте custom MCP server в ChatGPT через Tunnel или собственный HTTPS /mcp. OAuth должен работать; SDK Inspector не заменяет этот шаг.
2. Скопируйте реальный технический ID зарегистрированного сервера `plugin_asdk_app...` со страницы управления. Затем локально выполните:

```powershell
python scripts/package_plugin.py --registered-server-id ВАШ_РЕАЛЬНЫЙ_ID
```

Скрипт проверяет формат ID, но не регистрацию: убедитесь, что ID принадлежит нужному серверу/аккаунту. Он создаст `dist/plugin-registered/ha-diagnostics/` с `.app.json`, ZIP и marketplace. Без ID базовая поставка `dist/plugin-skills-only` содержит только skill и не может читать HA самостоятельно. `--mcp-url https://ваш-домен/mcp` создаёт portable endpoint package для поддерживающего клиента, не регистрацию ChatGPT.

3. Для local desktop marketplace используйте сгенерированный marketplace.json и папку ha-diagnostics в одном marketplace root. Зарегистрируйте этот root штатным способом клиента (`codex plugin marketplace add <путь>` при наличии поддерживаемого CLI) либо перенесите catalog в личный/репозиторный `.agents/plugins/marketplace.json`, сохранив относительный `source.path` от marketplace root. Не перезаписывайте существующий personal catalog. Перезапустите desktop, установите пакет из его local source и начните новый чат.
4. Проверяйте весь установленный пакет: skill + тот же реальный mapping + OAuth + status/incident/evidence. Если аккаунт не поддерживает package installation surface, сохраните bundle и отдельно созданное MCP подключение, отметив package acceptance непроверенной. [Формат и установка](https://developers.openai.com/plugins/build/plugins).

## 6. Отзыв, обновление, откат

В локальной панели выключите удалённый доступ/owner binding и выбранные источники или imports. Следующий вызов должен быть запрещён, active выдача отменена по критерию ≤5s. Это kill switch; удаление плагина в ChatGPT не заменяет его. Затем отзовите refresh/session в IdP и runtime transport key в Platform/личном gateway, остановите транспорт. История сборщика может продолжаться при паузе удалённого доступа; остановка сбора отдельна.

При обновлении сохраняйте версию `1.0.0-alpha.6` до отдельного указания. Повторяйте lock/hash/negative tests и runbook; source package не содержит state. Для отката используйте предыдущий проверенный image digest и совместимую копию своего очищенного архива/политики. Backup defaults исключают архив и secrets; автоматическое восстановление credentials не обещается. Локальное удаление не удаляет уже переданные ответы в ChatGPT или резервные копии других систем.
