# HA-Diagnostics 1.0.0-alpha.1

Предварительный частный alpha-пакет. Import-профиль не удерживает credentials HA и работает с локально импортированными очищенными файлами. Live-профиль поставляется отдельно; у его broker широкий токен Supervisor manager, и реальные HA OS/ChatGPT проверки ещё нужны.

Сначала выполните `python scripts/package_release.py`: он создаст самостоятельный build context в `dist/ha-addons/`. Исходная папка приложения без staged `app/` не является готовым контекстом Docker.

Полная установка, настройка, отзыв и ограничения: `docs/INSTALL.md`, `docs/LIVE_ACCEPTANCE.md`, `docs/SECURITY.md` в исходной поставке. Не отключайте Protected mode. Домашние порты открывать не требуется.
