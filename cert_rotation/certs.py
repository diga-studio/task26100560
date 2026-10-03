"""本地生成真实自签名 X.509 证书。"""
from __future__ import annotations

import datetime
import hashlib
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


@dataclass(frozen=True)
class Certificate:
    """一张自签名 X.509 身份证书（含私钥，仅进程内使用）。"""

    cert_pem: bytes
    key_pem: bytes

    @property
    def fingerprint(self) -> str:
        """证书 DER 的 SHA-256 指纹（十六进制），作为证书唯一标识。"""
        cert = x509.load_pem_x509_certificate(self.cert_pem)
        return cert.fingerprint(hashes.SHA256()).hex()


def generate_self_signed(common_name: str) -> Certificate:
    """生成一张真实自签名 X.509 证书（RSA-2048，有效期 10 年）。"""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return Certificate(
        cert_pem=cert.public_bytes(serialization.Encoding.PEM),
        key_pem=key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
