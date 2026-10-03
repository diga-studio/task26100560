"""本地生成真实自签 X.509 证书的工具。"""
from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_self_signed_cert(common_name: str) -> x509.Certificate:
    """生成一张真实自签 X.509 证书（私钥在函数内生成并随即丢弃）。"""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )


def cert_fingerprint(cert: x509.Certificate) -> str:
    """返回证书 SHA-256 指纹（hex 字符串），用作证书的唯一标识。"""
    return cert.fingerprint(hashes.SHA256()).hex()
