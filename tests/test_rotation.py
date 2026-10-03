"""站点证书分阶段轮换库的自动化测试。

测试依据设备实际身份证书与对端实际信任集合独立核对结果，
而不是只检查库报告的阶段。
"""
from __future__ import annotations

import random

import pytest

from cert_rotation import (
    Device,
    Phase,
    RotationLibrary,
    cert_fingerprint,
    generate_self_signed_cert,
)

TOPOLOGY = {
    "a": ["b", "c"],
    "b": ["a", "c"],
    "c": ["a", "b"],
}


def make_env():
    certs = {s: generate_self_signed_cert(s) for s in TOPOLOGY}
    lib = RotationLibrary(TOPOLOGY, certs)
    devices = {s: Device(lib.get_initial_config(s)) for s in TOPOLOGY}
    return lib, devices, certs


def assert_all_tunnels_mutual_trust(devices):
    """每条隧道任一端实际身份证书，必须在对端针对该站点的实际信任集合中。"""
    for site, neighbors in TOPOLOGY.items():
        identity = devices[site].state.identity
        for neighbor in neighbors:
            trust = devices[neighbor].state.trust[site]
            assert identity in trust, (
                f"隧道 {site}-{neighbor}: {site} 的身份证书不在 {neighbor} 的信任集合中"
            )


def pump_one_round(lib, devices, rng, duplicates=2):
    """收集一轮待下发配置，乱序、重复投递；回执也乱序、重复提交。

    每次设备实际应用后都独立核对全部隧道双向互信。
    返回本轮产生的全部回执（按提交前保存）。
    """
    configs = []
    for site in TOPOLOGY:
        configs.extend(lib.get_pending_configs(site))
    rng.shuffle(configs)
    receipts = []
    for config in configs:
        for _ in range(rng.randint(1, duplicates)):
            receipt = devices[config.site].apply(config)
            assert_all_tunnels_mutual_trust(devices)
            if receipt is not None:
                receipts.append(receipt)
    rng.shuffle(receipts)
    for receipt in receipts:
        for _ in range(rng.randint(1, duplicates)):
            lib.submit_receipt(receipt.site, receipt)
    return receipts


def pump_until_idle(lib, devices, rng, max_rounds=50):
    all_receipts = []
    for _ in range(max_rounds):
        receipts = pump_one_round(lib, devices, rng)
        all_receipts.extend(receipts)
        if not any(lib.get_pending_configs(s) for s in TOPOLOGY):
            return all_receipts
    raise AssertionError("配置投递未收敛")


def test_out_of_order_and_duplicate_delivery_full_rotation():
    """配置与回执乱序、重复时：全程双向互信，未确认身份不被启用，
    轮换完成后旧证书信任确实消失。"""
    rng = random.Random(20261005)
    lib, devices, certs = make_env()
    old_cert = certs["a"]

    candidate_fp = lib.start_rotation("a")

    # 第一阶段：邻站追加信任候选证书。乱序、重复投递与回执。
    pump_until_idle(lib, devices, rng)
    assert lib.get_status("a").phase is Phase.AWAITING_CONFIRM

    # 独立核对：候选证书已被邻站信任，但本站尚未启用（人工确认前）。
    assert devices["a"].state.identity == old_cert
    for neighbor in ("b", "c"):
        trust = devices[neighbor].state.trust["a"]
        assert old_cert in trust
        assert any(cert_fingerprint(c) == candidate_fp for c in trust)

    # 确认前再泵一轮：候选身份不得被启用。
    pump_until_idle(lib, devices, rng)
    assert devices["a"].state.identity == old_cert

    # 人工确认后完成轮换。
    lib.confirm_rotation("a", candidate_fp)
    pump_until_idle(lib, devices, rng)

    status = lib.get_status("a")
    assert status.complete
    assert status.phase is Phase.IDLE

    # 独立核对：本站实际使用新证书，邻站只信任新证书，旧证书信任已清除。
    new_identity = devices["a"].state.identity
    assert cert_fingerprint(new_identity) == candidate_fp
    assert new_identity != old_cert
    for neighbor in ("b", "c"):
        assert devices[neighbor].state.trust["a"] == frozenset({new_identity})
    assert_all_tunnels_mutual_trust(devices)


def test_unconfirmed_identity_never_activated():
    """未做人工确认时，无论配置/回执如何乱序重复，候选身份都不会被启用。"""
    rng = random.Random(7)
    lib, devices, certs = make_env()
    old_cert = certs["a"]
    lib.start_rotation("a")
    for _ in range(5):
        pump_one_round(lib, devices, rng)
        assert devices["a"].state.identity == old_cert
    assert_all_tunnels_mutual_trust(devices)


def test_pending_config_is_not_applied_proof():
    """取出待下发配置不等于应用成功：不投递则阶段不前进。"""
    lib, devices, certs = make_env()
    lib.start_rotation("a")
    for site in TOPOLOGY:
        lib.get_pending_configs(site)  # 只取出，不投递
    assert lib.get_status("a").phase is Phase.DISTRIBUTING_TRUST
    assert devices["a"].state.identity == certs["a"]


def test_stale_receipts_from_previous_rotation_do_not_leak():
    """上一轮回执延迟（重复）到下一轮才到达：不能提前切换或错误清除信任。"""
    rng = random.Random(99)
    lib, devices, certs = make_env()

    # 第一轮轮换完整完成，保存全部回执模拟传输中的延迟副本。
    fp1 = lib.start_rotation("a")
    pump_until_idle(lib, devices, rng)
    lib.confirm_rotation("a", fp1)
    round1_receipts = pump_until_idle(lib, devices, rng)
    assert lib.get_status("a").complete
    cert_after_round1 = devices["a"].state.identity
    assert cert_fingerprint(cert_after_round1) == fp1

    # 第二轮轮换发起。
    fp2 = lib.start_rotation("a")
    assert fp2 != fp1
    assert lib.get_status("a").phase is Phase.DISTRIBUTING_TRUST

    # 第一轮延迟的旧回执此刻才到达：不得推进第二轮的任何阶段。
    for receipt in round1_receipts:
        lib.submit_receipt(receipt.site, receipt)
    assert lib.get_status("a").phase is Phase.DISTRIBUTING_TRUST
    assert devices["a"].state.identity == cert_after_round1
    for neighbor in ("b", "c"):
        # 信任未被错误清除：仍信任第一轮的新证书。
        assert cert_after_round1 in devices[neighbor].state.trust["a"]

    # 第二轮正常推进：旧回执不影响最终正确完成。
    pump_until_idle(lib, devices, rng)
    for receipt in round1_receipts:  # 确认前再次混入旧回执
        lib.submit_receipt(receipt.site, receipt)
    lib.confirm_rotation("a", fp2)
    pump_until_idle(lib, devices, rng)
    for receipt in round1_receipts:  # 完成后再混入旧回执
        lib.submit_receipt(receipt.site, receipt)

    assert lib.get_status("a").complete
    final_identity = devices["a"].state.identity
    assert cert_fingerprint(final_identity) == fp2
    for neighbor in ("b", "c"):
        assert devices[neighbor].state.trust["a"] == frozenset({final_identity})
    assert_all_tunnels_mutual_trust(devices)


def test_stale_confirmation_cannot_authorize_next_rotation():
    """迟到的旧确认不能授权下一次轮换。"""
    rng = random.Random(3)
    lib, devices, certs = make_env()

    fp1 = lib.start_rotation("a")
    pump_until_idle(lib, devices, rng)
    lib.confirm_rotation("a", fp1)
    pump_until_idle(lib, devices, rng)
    assert lib.get_status("a").complete

    # 第二轮：旧确认迟到，必须被拒绝且不授权本轮。
    fp2 = lib.start_rotation("a")
    pump_until_idle(lib, devices, rng)
    assert lib.get_status("a").phase is Phase.AWAITING_CONFIRM
    with pytest.raises(ValueError):
        lib.confirm_rotation("a", fp1)
    assert lib.get_status("a").phase is Phase.AWAITING_CONFIRM
    assert cert_fingerprint(devices["a"].state.identity) == fp1

    # 无轮换时的确认同样无效。
    lib.confirm_rotation("a", fp2)
    pump_until_idle(lib, devices, rng)
    assert lib.get_status("a").complete
    with pytest.raises(ValueError):
        lib.confirm_rotation("a", fp2)


def test_concurrent_rotation_rejected_and_rerotation_allowed():
    """同一站点同时只能有一次未完成轮换，完成后允许再次轮换。"""
    rng = random.Random(11)
    lib, devices, certs = make_env()
    lib.start_rotation("a")
    with pytest.raises(ValueError):
        lib.start_rotation("a")
    # 不同站点可独立轮换。
    lib.start_rotation("b")
    status_b = lib.get_status("b")
    assert status_b.phase is Phase.DISTRIBUTING_TRUST


def test_completion_state_does_not_regress():
    """完成后迟到的旧配置、旧回执不能让状态倒退。"""
    rng = random.Random(42)
    lib, devices, certs = make_env()
    fp = lib.start_rotation("a")
    pump_until_idle(lib, devices, rng)
    lib.confirm_rotation("a", fp)
    receipts = pump_until_idle(lib, devices, rng)
    assert lib.get_status("a").complete

    snapshot = {s: devices[s].state for s in TOPOLOGY}
    # 旧回执重复提交。
    for receipt in receipts:
        lib.submit_receipt(receipt.site, receipt)
    # 旧配置重新投递（设备版本不高于当前，忽略）。
    for site in TOPOLOGY:
        stale = lib.get_initial_config(site)
        assert devices[site].apply(stale) is None
    assert lib.get_status("a").complete
    for site in TOPOLOGY:
        assert devices[site].state == snapshot[site]
    assert_all_tunnels_mutual_trust(devices)
