"""分阶段证书轮换库：发起轮换、人工确认、待下发配置、应用回执。"""
from __future__ import annotations

from dataclasses import dataclass, replace

from .certs import Certificate
from .device import Receipt, SiteConfig, VersionedConfig


class RotationError(Exception):
    """非法操作（如重复发起轮换、确认不匹配的候选证书）。"""


# 轮换阶段：分发信任 -> 等待人工确认 -> 切换本站身份 -> 清除旧信任 -> 完成
_DISTRIBUTE_TRUST = "distribute_trust"
_AWAIT_CONFIRM = "await_confirm"
_SWITCH_IDENTITY = "switch_identity"
_REMOVE_OLD = "remove_old"


@dataclass
class _Rotation:
    candidate: Certificate
    phase: str
    confirmed: bool = False
    # 当前阶段已下发、等待回执的版本号：{站点: 版本}
    awaiting: dict[str, int] | None = None


class RotationLibrary:
    """站点证书分阶段轮换库。状态全部保存在内存。

    不变式：每条隧道任一端实际身份证书，始终在对端针对该站点的
    实际信任集合中。阶段顺序保证每一次设备应用之后该不变式成立。
    """

    def __init__(
        self,
        topology: dict[str, list[str]],
        initial_certs: dict[str, Certificate],
    ) -> None:
        for site, neighbors in topology.items():
            for n in neighbors:
                if site not in topology.get(n, []):
                    raise ValueError(f"拓扑不对称: {site} -> {n}")
        if set(topology) != set(initial_certs):
            raise ValueError("拓扑站点与初始证书站点不一致")

        self._neighbors = {s: list(ns) for s, ns in topology.items()}
        # 各站点期望配置内容（下一次发版以此为准）
        self._desired: dict[str, SiteConfig] = {
            s: SiteConfig(
                identity=cert,
                trust={
                    n: frozenset({initial_certs[n].fingerprint})
                    for n in self._neighbors[s]
                },
            )
            for s, cert in initial_certs.items()
        }
        self._version = {s: 0 for s in topology}  # 已发版本（初始配置为 0）
        self._applied = {s: 0 for s in topology}  # 回执证实的最高已应用版本
        self._outstanding: dict[str, VersionedConfig] = {}  # 已下发未回执
        self._rotation: dict[str, _Rotation | None] = {s: None for s in topology}

    # ---- 内部工具 ----

    def _issue(self, site: str) -> VersionedConfig:
        """以当前期望内容为站点发出下一版本配置。"""
        self._version[site] += 1
        vc = VersionedConfig(site, self._version[site], self._desired[site])
        self._outstanding[site] = vc
        return vc

    def _acked(self, site: str, version: int) -> bool:
        return self._applied[site] >= version

    # ---- 四类操作 ----

    def start_rotation(self, site: str) -> Certificate:
        """为站点发起轮换：生成候选证书并提前让各邻站信任它。

        本站在人工确认前不使用候选证书作为身份。
        """
        if site not in self._neighbors:
            raise RotationError(f"未知站点: {site}")
        if self._rotation[site] is not None:
            raise RotationError(f"站点 {site} 存在未完成轮换")

        from .certs import generate_self_signed

        candidate = generate_self_signed(f"{site}-candidate")
        rot = _Rotation(candidate=candidate, phase=_DISTRIBUTE_TRUST, awaiting={})
        self._rotation[site] = rot

        fp = candidate.fingerprint
        for n in self._neighbors[site]:
            desired = self._desired[n]
            new_trust = dict(desired.trust)
            new_trust[site] = frozenset(set(new_trust[site]) | {fp})
            self._desired[n] = replace(desired, trust=new_trust)
            vc = self._issue(n)
            rot.awaiting[n] = vc.version
        if not rot.awaiting:  # 无邻站：直接进入待确认
            rot.phase = _AWAIT_CONFIRM
        return candidate

    def confirm(self, site: str, candidate: Certificate) -> None:
        """人工确认：仅授权当前轮换的指定候选证书。

        迟到的旧确认（指纹不匹配或阶段不符）不能授权轮换。
        """
        rot = self._rotation.get(site)
        if rot is None:
            raise RotationError(f"站点 {site} 没有进行中的轮换")
        if rot.phase != _AWAIT_CONFIRM:
            raise RotationError(f"站点 {site} 当前不在待确认阶段")
        if candidate.fingerprint != rot.candidate.fingerprint:
            raise RotationError("确认的候选证书与本次轮换不匹配")
        rot.confirmed = True
        self._advance(site)

    def pending_configs(self) -> list[VersionedConfig]:
        """当前已下发但尚未被回执证实的配置（取出不代表应用成功）。"""
        return list(self._outstanding.values())

    def submit_receipt(self, receipt: Receipt) -> None:
        """提交应用回执。乱序、重复、迟到的回执均安全。"""
        site = receipt.site
        if site not in self._applied:
            raise RotationError(f"未知站点: {site}")
        if receipt.version <= self._applied[site]:
            return  # 旧版/重复回执：不改变状态
        self._applied[site] = receipt.version
        out = self._outstanding.get(site)
        if out is not None and receipt.version >= out.version:
            del self._outstanding[site]
        # 推进所有可能因此满足的轮换阶段
        for s, rot in self._rotation.items():
            if rot is not None:
                self._advance(s)

    def is_complete(self, site: str) -> bool:
        """站点当前没有未完成轮换即为完成（初始状态视为已完成）。"""
        return self._rotation.get(site) is None

    # ---- 阶段推进 ----

    def _advance(self, site: str) -> None:
        rot = self._rotation[site]
        if rot is None:
            return
        if rot.awaiting and not all(
            self._acked(s, v) for s, v in rot.awaiting.items()
        ):
            return  # 当前阶段尚有未证实的应用

        if rot.phase == _DISTRIBUTE_TRUST:
            rot.phase = _AWAIT_CONFIRM
            rot.awaiting = {}
        elif rot.phase == _AWAIT_CONFIRM:
            if not rot.confirmed:
                return
            # 切换本站身份为候选证书
            desired = self._desired[site]
            self._desired[site] = replace(desired, identity=rot.candidate)
            vc = self._issue(site)
            rot.phase = _SWITCH_IDENTITY
            rot.awaiting = {site: vc.version}
        elif rot.phase == _SWITCH_IDENTITY:
            # 各邻站针对本站只保留候选证书，清除旧证书信任
            fp = rot.candidate.fingerprint
            awaiting = {}
            for n in self._neighbors[site]:
                desired = self._desired[n]
                new_trust = dict(desired.trust)
                new_trust[site] = frozenset({fp})
                self._desired[n] = replace(desired, trust=new_trust)
                vc = self._issue(n)
                awaiting[n] = vc.version
            rot.phase = _REMOVE_OLD
            rot.awaiting = awaiting
        elif rot.phase == _REMOVE_OLD:
            self._rotation[site] = None  # 完成；允许再次轮换
