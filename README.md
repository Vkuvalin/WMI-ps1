# WMI-ps1
Создание юзеров с минимальными необходимыми полномочиями для WMI

Задача: нужно было создать учетную запись пользователя домена, которая могла бы получить доступ к WMI на всех серверах.
Необходимо (как в моём случае) для создание процесса обнаружения инвентаризации, который будет запрашивать в Active Directory серверы и собирать данные об их оборудовании.

Данный скрипт предназначен для windows (powershell). Создает юзера и на серверах и потенциально на рабочих станциях добавляет для доменной группы безопасности следующие права (минимально необходимые полномочия):
WMI (wmimgmt.msc) -> "WMI Control (Local) -> Properties -> Security -> Root\CIMv2 -> Security": Remote Enable
