"""站点证书分阶段轮换库的自动化测试。

测试依据设备实际身份证书与对端实际信任集合独立核对结果，
而不是只检查库报告的阶段。
"""
from __future__ import annotations

import random

import pytest

from cert_rotation.certs import generate_self_signed
from cert_rotation.device import Device, SiteConfig, VersionedConfig
from cert_rotation.library import RotationError, RotationLibrary

TOPO = {"a": ["b", "c"], "b": ["a", "c"], "c": ["a", "b"]}


def make_world(topo=TOPO):
    certs = {s: generate_self_signed(s) for s in topo}
    lib = RotationLibrary(topo, certs)
    devices = {}
    for s in topo:
        cfg = SiteConfig(
            identity=certs[s],
            trust={n: frozenset({certs[n].fingerprint}) for n in topo[s]},
        )
        devices[s] = Device(s, VersionedConfig(s, 0, cfg))
    return lib, devices, certs


def check_all_tunnels(topo, devices):
    """每条隧道两端：任一端实际身份证书必须在对端针对该端的实际信任集合中。"""
    for s, neighbors in topo.items():
        id_fp = devices[s].current.config.identity.fingerprint
        for n in neighbors:
            trust = devices[n].current.config.trust[s]
            assert id_fp in trust, f"隧道 {s}-{n}: {n} 不信任 {s} 的实际身份"


class Harness:
    """模拟乱序、重复、延迟的配置投递与回执提交。"""

    def __init__(self, lib, devices, topo, seed=0):
        self.lib = lib
        self.devices = devices
        self.topo = topo
        self.rng = random.Random(seed)
        self.in_flight = []      # 已取出未投递的配置
        self.receipts = []       # 已产生未提交的回执
        self.delivered = []      # 所有投递过的配置副本（含旧版）
        self.submitted = []      # 所有提交过的回执副本（含旧版）

    def collect(self, dup=False):
        cfgs = self.lib.pending_configs()
        self.in_flight.extend(cfgs)
        if dup:
            self.in_flight.extend(cfgs)  # 重复取出

    def deliver_all(self):
        self.rng.shuffle(self.in_flight)
        while self.in_flight:
            vc = self.in_flight.pop()
            self.delivered.append(vc)
            r = self.devices[vc.site].apply(vc)
            # 每一次实际应用之后，所有隧道必须双向互信
            check_all_tunnels(self.topo, self.devices)
            if r is not None:
                self.receipts.append(r)

    def submit_all(self, dup=False):
        self.rng.shuffle(self.receipts)
        while self.receipts:
            r = self.receipts.pop()
            self.lib.submit_receipt(r)
            self.submitted.append(r)
            if dup:
                self.lib.submit_receipt(r)  # 重复回执

    def run_until_quiet(self, max_rounds=50):
        for _ in range(max_rounds):
            self.collect(dup=True)
            if not self.in_flight and not self.receipts:
                return
            self.deliver_all()
            self.submit_all(dup=True)
        raise AssertionError("轮换未在限定轮次内收敛")


# ---- 场景一：乱序、重复投递与回执 ----

def test_rotation_out_of_order_and_duplicate():
    lib, devices, certs = make_world()
    h = Harness(lib, devices, TOPO, seed=1)
    old_fp = certs["a"].fingerprint

    cand = lib.start_rotation("a")
    assert not lib.is_complete("a")

    # 邻站信任分发阶段（乱序+重复）
    h.run_until_quiet()
    # 未确认前：本站不得启用候选身份
    assert devices["a"].current.config.identity.fingerprint == old_fp
    # 邻站已同时信任新旧证书
    for n in TOPO["a"]:
        trust = devices[n].current.config.trust["a"]
        assert {old_fp, cand.fingerprint} <= trust

    # 确认不匹配的候选证书被拒绝
    with pytest.raises(RotationError):
        lib.confirm("a", generate_self_signed("impostor"))
    # 确认指定候选证书
    lib.confirm("a", cand)
    # 确认不代表设备已应用：身份仍未切换
    assert devices["a"].current.config.identity.fingerprint == old_fp

    h.run_until_quiet()
    assert lib.is_complete("a")
    # 本站实际使用新证书
    assert devices["a"].current.config.identity.fingerprint == cand.fingerprint
    # 所有邻站针对本站只信任新证书，旧证书信任已清除
    for n in TOPO["a"]:
        trust = devices[n].current.config.trust["a"]
        assert trust == frozenset({cand.fingerprint})
        assert old_fp not in trust
    check_all_tunnels(TOPO, devices)


def test_pending_configs_not_applied_until_receipt():
    lib, devices, certs = make_world()
    cand = lib.start_rotation("a")
    # 取出待下发配置不等于应用成功
    pending = lib.pending_configs()
    assert pending
    for n in TOPO["a"]:
        assert cand.fingerprint not in devices[n].current.config.trust["a"]
    # 投递并提交回执后，待下发清空
    for vc in pending:
        r = devices[vc.site].apply(vc)
        lib.submit_receipt(r)
    assert lib.pending_configs() == []


def test_one_rotation_at_a_time():
    lib, devices, certs = make_world()
    lib.start_rotation("a")
    with pytest.raises(RotationError):
        lib.start_rotation("a")
    # 不同站点可独立轮换
    lib.start_rotation("b")


def test_confirm_wrong_phase_rejected():
    lib, devices, certs = make_world()
    cand = lib.start_rotation("a")
    # 信任分发尚未完成（无回执），不在待确认阶段
    with pytest.raises(RotationError):
        lib.confirm("a", cand)


# ---- 场景二：上一轮的旧配置/旧回执延迟到下一轮 ----

def test_stale_receipts_and_configs_from_previous_rotation():
    lib, devices, certs = make_world()
    h = Harness(lib, devices, TOPO, seed=2)

    # 第一轮轮换完整完成
    cand1 = lib.start_rotation("a")
    h.run_until_quiet()
    lib.confirm("a", cand1)
    h.run_until_quiet()
    assert lib.is_complete("a")
    assert devices["a"].current.config.identity.fingerprint == cand1.fingerprint

    stale_configs = list(h.delivered)    # 第一轮投递过的全部配置
    stale_receipts = list(h.submitted)   # 第一轮提交过的全部回执

    # 第二轮轮换开始
    cand2 = lib.start_rotation("a")
    assert not lib.is_complete("a")

    # 第一轮的旧配置迟到重投：设备版本不更高，应拒绝
    for vc in stale_configs:
        assert devices[vc.site].apply(vc) is None
    check_all_tunnels(TOPO, devices)

    # 第一轮的旧回执迟到重提：库应忽略，不得推进第二轮
    for r in stale_receipts:
        lib.submit_receipt(r)
    assert not lib.is_complete("a")
    # 本站身份不得被旧回执提前切换
    assert devices["a"].current.config.identity.fingerprint == cand1.fingerprint
    # 邻站对 cand1 的信任不得被错误清除
    for n in TOPO["a"]:
        assert cand1.fingerprint in devices[n].current.config.trust["a"]

    # 第一轮的旧确认迟到：不能授权第二轮
    with pytest.raises(RotationError):
        lib.confirm("a", cand1)
    assert devices["a"].current.config.identity.fingerprint == cand1.fingerprint

    # 正常完成第二轮
    h.run_until_quiet()
    lib.confirm("a", cand2)
    h.run_until_quiet()
    assert lib.is_complete("a")
    assert devices["a"].current.config.identity.fingerprint == cand2.fingerprint
    for n in TOPO["a"]:
        trust = devices[n].current.config.trust["a"]
        assert trust == frozenset({cand2.fingerprint})
        assert cand1.fingerprint not in trust
    check_all_tunnels(TOPO, devices)


def test_delayed_duplicate_receipt_mid_rotation():
    """同一轮内：回执延迟重复到达，不导致状态倒退或提前推进。"""
    lib, devices, certs = make_world()
    old_fp = certs["a"].fingerprint
    cand = lib.start_rotation("a")

    # 只投递并回执部分邻站
    pending = {vc.site: vc for vc in lib.pending_configs()}
    r_b = devices["b"].apply(pending["b"])
    lib.submit_receipt(r_b)
    lib.submit_receipt(r_b)  # 重复回执
    # c 尚未应用，不得进入待确认阶段
    with pytest.raises(RotationError):
        lib.confirm("a", cand)
    # 旧版本配置重复投递给 b：设备拒绝
    assert devices["b"].apply(pending["b"]) is None
    check_all_tunnels(TOPO, devices)

    r_c = devices["c"].apply(pending["c"])
    lib.submit_receipt(r_c)
    lib.confirm("a", cand)
    # 切换身份配置下发前，身份仍是旧证书
    assert devices["a"].current.config.identity.fingerprint == old_fp
    # 完成剩余流程
    h = Harness(lib, devices, TOPO, seed=3)
    h.run_until_quiet()
    assert lib.is_complete("a")
    for n in TOPO["a"]:
        assert devices[n].current.config.trust["a"] == frozenset({cand.fingerprint})
