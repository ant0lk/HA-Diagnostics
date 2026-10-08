# HA-Diagnostics 1.0.0-alpha.3

Основной Live-профиль собирает и скачивает диагностический ZIP без MCP/OAuth/Tunnel: доступные журналы и сведения об установке, история и события за последние 24 часа. См. `docs/ZIP_EXPORT.md`.

Предварительный частный alpha-пакет. Import-профиль не удерживает credentials HA и работает с локально импортированными очищенными файлами. Live-профиль поставляется отдельно; у его broker широкий токен Supervisor manager, и реальные HA OS/ChatGPT проверки ещё нужны.

Сначала выполните `python scripts/package_release.py`: он создаст самостоятельный build context в `dist/ha-addons/`. Исходная папка приложения без staged `app/` не является готовым контекстом Docker.

Полная установка, настройка, отзыв и ограничения: `docs/INSTALL.md`, `docs/LIVE_ACCEPTANCE.md`, `docs/SECURITY.md` в исходной поставке. Не отключайте Protected mode. Домашние порты открывать не требуется.
