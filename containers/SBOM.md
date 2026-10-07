# Supply-chain inventory and audit

`python scripts/verify_supply_sbom.py` создаёт `dist/sbom/python-lock.cdx.json`: CycloneDX1.6 inventory всех закреплённых Python requirements, разрешённые distribution SHA256 и совпадение версии в текущем interpreter. Это не полный image SBOM: OS packages, реальный установленный wheel, Tunnel и граф зависимостей здесь не реконструируются. Tunnel имеет отдельный закреплённый upstream SPDX в supply-chain.lock.json.

Опциональный `--audit` использует только уже установленный и отдельно проверенный/hash-pinned `pip-audit2.10.1`, не устанавливает инструменты и не применяет исправления. Он обращается к публичной advisory service PyPI с названиями/версиями публичных зависимостей; реальные данные HA не читаются. При отсутствии инструмента audit отмечается unavailable. [Официальные flags/security model](https://github.com/pypa/pip-audit) определяют `--require-hashes`, `--disable-pip` и `--no-deps`. Версия инструмента не обновляется автоматически.

После реальной Linux сборки нужен отдельный image SBOM по actual digest, scan OS/Python/Tunnel и проверка provenance. Hash/inventory не доказывает отсутствие уязвимостей. Ненулевой audit не скрывается, подавление advisory требует отдельного документированного решения. Эти результаты и принятые исключения фиксируются до live-приёмки.
