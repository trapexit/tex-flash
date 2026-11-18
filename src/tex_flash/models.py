# SPDX-License-Identifier: GPL-2.0-or-later
"""Keyboard models with independently qualified updater profiles."""

from enum import Enum


class Model(str, Enum):
    def __new__(cls, name: str, app_pid: str, iap_pid: str, slot_size: int, version: str):
        model = str.__new__(cls, name)
        model._value_ = name
        model.app_pid = app_pid
        model.iap_pid = iap_pid
        model.slot_size = slot_size
        model.version = version
        return model

    SHURA = ("shura", "0532", "1532", 27964, "0.18")
    SHINOBI = ("shinobi", "0407", "1407", 28076, "4.04")

    @property
    def title(self) -> str:
        return self.value.capitalize()
