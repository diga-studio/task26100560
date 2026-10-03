"""进程内设备模型：原子应用版本递增的完整配置。"""
from __future__ import annotations

from dataclasses import dataclass

from .certs import Certificate


@dataclass(frozen=True)
class SiteConfig:
    """某站点的完整设备配置：本站身份证书 + 针对各邻站的信任集合。

    trust[neighbor] 为本站信任的、该邻站可用作身份的证书指纹集合。
    应用配置会整体替换身份证书与全部信任集合。
    """

    identity: Certificate
    trust: dict[str, frozenset[str]]


@dataclass(frozen=True)
class VersionedConfig:
    """带站点内递增版本号的完整配置。同一版本唯一对应一份内容。"""

    site: str
    version: int
    config: SiteConfig


@dataclass(frozen=True)
class Receipt:
    """应用回执：证明某站点的某版本配置曾成功应用。

    不代表设备当前仍停留在该版本。
    """

    site: str
    version: int


class Device:
    """进程内设备：只原子应用高于当前版本的完整配置。

    旧版或重复版本的配置不改变设备状态。
    """

    def __init__(self, site: str, initial: VersionedConfig) -> None:
        if initial.site != site:
            raise ValueError("初始配置站点与设备站点不一致")
        self._site = site
        self._current = initial

    @property
    def site(self) -> str:
        return self._site

    @property
    def current(self) -> VersionedConfig:
        return self._current

    def apply(self, vc: VersionedConfig) -> Receipt | None:
        """版本更高则原子应用并返回回执；旧版/重复版本返回 None。"""
        if vc.site != self._site:
            raise ValueError("配置站点与设备站点不一致")
        if vc.version <= self._current.version:
            return None
        self._current = vc
        return Receipt(site=self._site, version=vc.version)
