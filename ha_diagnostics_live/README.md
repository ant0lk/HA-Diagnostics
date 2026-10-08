# HA-Diagnostics — Live alpha 1.0.0-alpha.1

Приложение для чтения разрешённых журналов, каталога и истории HA. Этот каталог содержит полный Docker build context для HA OS amd64/aarch64, включая закреплённый Tunnel runtime.

Protected mode оставить включённым. В options требуется проверенный ingress_admin_id владельца. Сбор и удалённое чтение отключены до локальной настройки. Broker использует широкий Supervisor manager credential; это не роль только чтения.

Сборка контейнера, фактическая Linux изоляция, HA OS и ChatGPT ещё требуют live-приёмки. См. ../docs/INSTALL.md, ../docs/ACCEPTANCE.md, ../docs/LIVE_ACCEPTANCE.md.
