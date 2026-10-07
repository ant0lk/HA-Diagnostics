# Установка Live alpha

1. Добавьте репозиторий https://github.com/ant0lk/HA-Diagnostics#alpha в магазин приложений HA и выберите HA-Diagnostics — Live alpha.
2. Установите приложение, сохраняя Protected mode. Укажите ingress_admin_id своего администратора. Пока ID не подтверждён, панель закрыта.
3. После проверки Linux credentials/IPC выберите источники и допустимые сущности локально, проверьте очищенный предпросмотр.
4. Настройте зрелый OAuth IdP и Tunnel либо личный HTTPS relay по docs/INSTALL.md. Секреты вводятся только локально. Установка приложения сама по себе не подключает ChatGPT.
5. Проведите live-приёмку; отзывайте удалённый доступ в локальной панели, затем IdP и transport credentials.

Полный MVP ещё не принят. Управляющих MCP tools нет, manager credential у broker остаётся широким.
