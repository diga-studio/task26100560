"""进程内设备模型：原子应用高版本完整配置，忽略旧版/重复配置。"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, FrozenSet, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes


def _config_hash(config: "DeviceConfig") -> str:
    """同一版本唯一对应一份内容：内容哈希由全部配置内容决定。"""
    digest = hashlib.sha256()
    digest.update(config.site.encode())
    digest.update(config.version.to_bytes(8, "big"))
    digest.update(config.identity.fingerprint(hashes.SHA256()))
    for neighbor in sorted(config.trust):
        digest.update(neighbor.encode())
        fps = sorted(c.fingerprint(hashes.SHA256()) for c in config.trust[neighbor])
        for fp in fps:
            digest.update(fp)
    return digest.hexdigest()


@dataclass(frozen=True)
class DeviceConfig:
    """某站点的完整设备配置：本站身份证书 + 针对各邻站的信任集合。"""
    site: str
    version: int
    identity: x509.Certificate
    trust: Dict[str, FrozenSet[x509.Certificate]]


@dataclass(frozen=True)
class Receipt:
    """应用回执：证明某版本曾成功应用，不代表设备当前仍停留在该版本。"""
    site: str
    version: int
    config_hash: str


class Device:
    """进程内设备。只原子应用版本号严格高于当前版本的完整配置。"""

    def __init__(self, initial_config: DeviceConfig) -> None:
        if initial_config.version < 1:
            raise ValueError("初始配置版本必须 >= 1")
        self._state = initial_config

    @property
    def current_version(self) -> int:
        return self._state.version

    @property
    def state(self) -> DeviceConfig:
        """设备当前实际生效的配置。"""
        return self._state

    def apply(self, config: DeviceConfig) -> Optional[Receipt]:
        """原子应用配置；版本不高于当前版本时不改变状态并返回 None。"""
        if config.site != self._state.site:
            raise ValueError(f"配置站点 {config.site} 与设备 {self._state.site} 不符")
        if config.version <= self._state.version:
            return None
        self._state = config
        return Receipt(
            site=config.site,
            version=config.version,
            config_hash=_config_hash(config),
        )
