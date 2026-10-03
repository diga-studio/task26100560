"""站点证书分阶段轮换库：状态保存在内存，由上层直接调用。"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from cryptography import x509

from .certs import cert_fingerprint, generate_self_signed_cert
from .device import DeviceConfig, Receipt
from .device import _config_hash


class Phase(enum.Enum):
    """单站点轮换阶段。"""
    IDLE = "idle"                          # 无未完成轮换
    DISTRIBUTING_TRUST = "distributing"    # 已发起：让邻站追加信任候选证书
    AWAITING_CONFIRM = "awaiting_confirm"  # 邻站已信任，等待人工确认
    SWITCHING_IDENTITY = "switching"       # 已确认：等待本站切换身份证书
    REVOKING_OLD = "revoking_old"          # 已切换：等待邻站清除旧证书信任


@dataclass(frozen=True)
class RotationStatus:
    site: str
    phase: Phase
    candidate_fingerprint: Optional[str]
    complete: bool


@dataclass
class _Rotation:
    """单站点一次未完成轮换的内部状态。"""
    candidate: x509.Certificate
    old_cert: x509.Certificate
    phase: Phase = Phase.DISTRIBUTING_TRUST
    trust_add_versions: Dict[str, int] = field(default_factory=dict)
    switch_version: Optional[int] = None
    revoke_versions: Dict[str, int] = field(default_factory=dict)


class RotationLibrary:
    """分阶段证书轮换库。初始化接收固定拓扑与各站点初始证书，约定初始互信成立。"""

    def __init__(
        self,
        topology: Dict[str, List[str]],
        initial_certs: Dict[str, x509.Certificate],
    ) -> None:
        for site, neighbors in topology.items():
            for neighbor in neighbors:
                if neighbor not in topology or site not in topology[neighbor]:
                    raise ValueError(f"拓扑不对称: {site} -> {neighbor}")
        if set(initial_certs) != set(topology):
            raise ValueError("初始证书必须覆盖拓扑中的全部站点")
        self._topology = {s: list(ns) for s, ns in topology.items()}
        self._identity = dict(initial_certs)
        self._version: Dict[str, int] = {}
        self._acked: Dict[str, int] = {}
        self._desired: Dict[str, DeviceConfig] = {}
        self._issued_hashes: Dict[str, Dict[int, str]] = {}
        self._rotation: Dict[str, Optional[_Rotation]] = {}
        self._completed: Dict[str, bool] = {}
        self._initial_configs: Dict[str, DeviceConfig] = {}
        for site, neighbors in self._topology.items():
            self._version[site] = 1
            self._acked[site] = 1
            self._rotation[site] = None
            self._completed[site] = False
            config = DeviceConfig(
                site=site,
                version=1,
                identity=initial_certs[site],
                trust={
                    n: frozenset({initial_certs[n]}) for n in neighbors
                },
            )
            self._desired[site] = config
            self._issued_hashes[site] = {1: _config_hash(config)}
            self._initial_configs[site] = config

    def get_initial_config(self, site: str) -> DeviceConfig:
        """站点初始完整配置（版本 1），可用于构造进程内设备。"""
        self._require_site(site)
        return self._initial_configs[site]

    def _require_site(self, site: str) -> None:
        if site not in self._topology:
            raise KeyError(f"未知站点: {site}")

    def _bump(self, site: str, *, identity=None, trust=None) -> DeviceConfig:
        """以递增版本生成某站点新的完整期望配置。"""
        current = self._desired[site]
        self._version[site] += 1
        config = DeviceConfig(
            site=site,
            version=self._version[site],
            identity=identity if identity is not None else current.identity,
            trust=trust if trust is not None else current.trust,
        )
        self._desired[site] = config
        self._issued_hashes[site][config.version] = _config_hash(config)
        return config

    def _set_neighbor_trust(self, neighbor: str, site: str, certs) -> int:
        """更新 neighbor 针对 site 的信任集合并生成新版本配置，返回新版本号。"""
        current = self._desired[neighbor]
        trust = dict(current.trust)
        trust[site] = frozenset(certs)
        return self._bump(neighbor, trust=trust).version

    def start_rotation(self, site: str) -> str:
        """发起轮换：生成新候选证书，返回候选证书指纹。同一站点同时只能有一次未完成轮换。"""
        self._require_site(site)
        if self._rotation[site] is not None:
            raise ValueError(f"站点 {site} 存在未完成轮换")
        candidate = generate_self_signed_cert(f"{site}-candidate")
        rotation = _Rotation(candidate=candidate, old_cert=self._identity[site])
        self._rotation[site] = rotation
        self._completed[site] = False
        for neighbor in self._topology[site]:
            trusted = set(self._desired[neighbor].trust[site])
            trusted.add(candidate)
            rotation.trust_add_versions[neighbor] = self._set_neighbor_trust(
                neighbor, site, trusted
            )
        return cert_fingerprint(candidate)

    def confirm_rotation(self, site: str, candidate_fingerprint: str) -> None:
        """人工确认：仅授权指定候选证书；迟到的旧确认不能授权下一次轮换。"""
        self._require_site(site)
        rotation = self._rotation[site]
        if rotation is None:
            raise ValueError(f"站点 {site} 无未完成轮换，确认无效")
        if cert_fingerprint(rotation.candidate) != candidate_fingerprint:
            raise ValueError("确认与当前候选证书不符，不能授权本次轮换")
        if rotation.phase in (
            Phase.SWITCHING_IDENTITY,
            Phase.REVOKING_OLD,
        ):
            return  # 重复确认，幂等忽略
        if rotation.phase is not Phase.AWAITING_CONFIRM:
            raise ValueError("邻站尚未信任候选证书，暂不能确认")
        rotation.switch_version = self._bump(site, identity=rotation.candidate).version
        rotation.phase = Phase.SWITCHING_IDENTITY

    def get_pending_configs(self, site: str) -> List[DeviceConfig]:
        """获取该站点当前待下发的完整配置（取出不等于应用成功）。"""
        self._require_site(site)
        desired = self._desired[site]
        if desired.version > self._acked[site]:
            return [desired]
        return []

    def submit_receipt(self, site: str, receipt: Receipt) -> None:
        """提交应用回执。回执可乱序、重复、延迟。"""
        self._require_site(site)
        if receipt.site != site:
            raise ValueError(f"回执站点 {receipt.site} 与提交站点 {site} 不符")
        known = self._issued_hashes[site].get(receipt.version)
        if known is None or known != receipt.config_hash:
            raise ValueError(f"站点 {site} 版本 {receipt.version} 的回执无效")
        if receipt.version > self._acked[site]:
            self._acked[site] = receipt.version
        for other in self._topology:
            self._advance(other)

    def get_status(self, site: str) -> RotationStatus:
        """查询轮换状态；只有实际达到完成态才报告 complete。"""
        self._require_site(site)
        self._advance(site)
        rotation = self._rotation[site]
        if rotation is None:
            return RotationStatus(
                site=site,
                phase=Phase.IDLE,
                candidate_fingerprint=None,
                complete=self._completed[site],
            )
        return RotationStatus(
            site=site,
            phase=rotation.phase,
            candidate_fingerprint=cert_fingerprint(rotation.candidate),
            complete=False,
        )

    def _advance(self, site: str) -> None:
        """依据已确认应用的版本推进轮换阶段；阶段只前进不后退。"""
        rotation = self._rotation[site]
        if rotation is None:
            return
        if rotation.phase is Phase.DISTRIBUTING_TRUST:
            if all(
                self._acked[n] >= v
                for n, v in rotation.trust_add_versions.items()
            ):
                rotation.phase = Phase.AWAITING_CONFIRM
        if rotation.phase is Phase.SWITCHING_IDENTITY:
            if self._acked[site] >= rotation.switch_version:
                for neighbor in self._topology[site]:
                    rotation.revoke_versions[neighbor] = self._set_neighbor_trust(
                        neighbor, site, {rotation.candidate}
                    )
                rotation.phase = Phase.REVOKING_OLD
        if rotation.phase is Phase.REVOKING_OLD:
            if all(
                self._acked[n] >= v
                for n, v in rotation.revoke_versions.items()
            ):
                self._identity[site] = rotation.candidate
                self._rotation[site] = None
                self._completed[site] = True
