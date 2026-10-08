# ADR-0001: конечный диагностический контракт и credential broker

Дата 2026-10-07; статус: принято для alpha, Linux/HA OS isolation acceptance ожидается.

Контекст: у Supervisor нет подтверждённой роли «читать все необходимые журналы». Live broker получает manager ради Core/Supervisor/разрешённых addon logs. Manager позволяет больше чтения, поэтому компрометация broker отличается от злонамеренного MCP-запроса.

Решение: конечный allowlist tools и typed broker operations; проверка метода, канонического маршрута, params, scope, local owner binding и источников в handler. Нет service calls, generic proxy/URL/path/shell/SQL; нет способов редактировать свою политику из MCP. Broker UID10001 единственный получает token. Query UID10002 читает очищенный archive; UI UID10003 управляет только своими данными; transport UID10004 имеет только transport credential. Root bootstrap минимален и удаляет inherited credentials при exec остальных процессов. OS dumpable/no_new_privs, permissions и IPC peer credentials должны быть проверены реальным образом.

Import HA app: hassio_api/homeassistant_api false, default роль, рабочие процессы не удерживают HA token. Не обещаем отсутствие выдачи Supervisor token на bootstrap. Для этого поставляется отдельный import-only образ вне Supervisor. Live profile отдельно и требует локального выбора.

Последствия: readOnlyHint объясняет намерение клиенту, защита лежит в server/broker/ОС. Выполнение произвольного кода в доверенном live broker может использовать широкое credential — явный остаточный риск. Protected mode/AppArmor остаются включёнными, host/Docker mounts отсутствуют. Изоляция UID без SEC-08 на HA OS недостаточна для live release.

Источники: [HA configuration](https://developers.home-assistant.io/docs/apps/configuration/), [Supervisor security middleware](https://github.com/home-assistant/supervisor/blob/2026.09.3/supervisor/api/middleware/security.py).
