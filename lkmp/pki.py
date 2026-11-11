"""Turnkey X.509 mTLS Public Key Infrastructure (PKI) generator for LKMP clusters."""

from __future__ import annotations

import ipaddress
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence


@dataclass(frozen=True)
class PkiBundlePaths:
    """Filesystem paths of generated Root CA and leaf mTLS certificates."""

    out_dir: Path
    ca_cert: Path
    ca_key: Path
    node_cert: Path
    node_key: Path
    named_nodes: Dict[str, tuple[Path, Path]]

    def to_dict(self) -> Dict[str, object]:
        return {
            "out_dir": str(self.out_dir),
            "ca_cert": str(self.ca_cert),
            "ca_key": str(self.ca_key),
            "node_cert": str(self.node_cert),
            "node_key": str(self.node_key),
            "named_nodes": {
                name: {"cert": str(cert_p), "key": str(key_p)}
                for name, (cert_p, key_p) in self.named_nodes.items()
            },
        }


def _build_san_entries(hosts: Iterable[str]) -> List[str]:
    dns_entries: List[str] = []
    ip_entries: List[str] = []
    seen: set[str] = set()

    for raw in hosts:
        item = raw.strip().strip("[]")
        if not item or item in seen:
            continue
        seen.add(item)
        try:
            addr = ipaddress.ip_address(item)
            ip_entries.append(f"IP:{addr}")
        except ValueError:
            dns_entries.append(f"DNS:{item}")

    if "IP:127.0.0.1" not in ip_entries:
        ip_entries.insert(0, "IP:127.0.0.1")
    if "IP:::1" not in ip_entries:
        ip_entries.append("IP:::1")
    if "DNS:localhost" not in dns_entries:
        dns_entries.insert(0, "DNS:localhost")

    return dns_entries + ip_entries


def _generate_signed_leaf(
    *,
    openssl_bin: str,
    ca_cert: Path,
    ca_key: Path,
    cert_path: Path,
    key_path: Path,
    common_name: str,
    san_entries: Sequence[str],
    validity_days: int,
) -> None:
    san_line = ",".join(san_entries)
    with tempfile.TemporaryDirectory() as tmp:
        tmp_p = Path(tmp)
        csr_path = tmp_p / "leaf.csr"
        ext_path = tmp_p / "leaf_ext.cnf"
        srl_path = tmp_p / "ca.srl"

        subprocess.run(
            [
                openssl_bin,
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(key_path),
                "-out",
                str(csr_path),
                "-subj",
                f"/O=LKMP/CN={common_name}",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        os.chmod(key_path, 0o600)

        ext_path.write_text(
            "\n".join(
                [
                    "basicConstraints = critical, CA:FALSE",
                    "keyUsage = critical, digitalSignature, keyEncipherment",
                    "extendedKeyUsage = serverAuth, clientAuth",
                    f"subjectAltName = {san_line}",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        subprocess.run(
            [
                openssl_bin,
                "x509",
                "-req",
                "-in",
                str(csr_path),
                "-CA",
                str(ca_cert),
                "-CAkey",
                str(ca_key),
                "-CAserial",
                str(srl_path),
                "-CAcreateserial",
                "-out",
                str(cert_path),
                "-days",
                str(validity_days),
                "-sha256",
                "-extfile",
                str(ext_path),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        os.chmod(cert_path, 0o644)


def generate_mtls_pki(
    out_dir: str | Path,
    *,
    hosts: Sequence[str] = ("127.0.0.1", "localhost"),
    node_names: Optional[Sequence[str]] = None,
    validity_days: int = 365,
    ca_common_name: str = "LKMP Cluster Root CA",
    node_common_name: str = "lkmp-node",
    openssl_bin: str = "openssl",
    overwrite: bool = False,
) -> PkiBundlePaths:
    """
    Generate a Root CA (`ca.crt`, `ca.key`) and mutual-TLS leaf certificate(s) (`node.crt`, `node.key`)
    suitable for `lkmp agent`, `lkmp migrate`, and `criu page-server --tls` (GnuTLS & OpenSSL compatible).
    """
    target = Path(out_dir).resolve()
    target.mkdir(parents=True, exist_ok=True)

    ca_cert = target / "ca.crt"
    ca_key = target / "ca.key"
    node_cert = target / "node.crt"
    node_key = target / "node.key"

    if not overwrite and ca_cert.exists() and ca_key.exists() and node_cert.exists() and node_key.exists():
        named_existing: Dict[str, tuple[Path, Path]] = {}
        for n_name in node_names or ():
            nc = target / f"{n_name}.crt"
            nk = target / f"{n_name}.key"
            if nc.exists() and nk.exists():
                named_existing[n_name] = (nc, nk)
        if not node_names or len(named_existing) == len(node_names):
            return PkiBundlePaths(
                out_dir=target,
                ca_cert=ca_cert,
                ca_key=ca_key,
                node_cert=node_cert,
                node_key=node_key,
                named_nodes=named_existing,
            )

    with tempfile.TemporaryDirectory() as tmp:
        ca_cnf = Path(tmp) / "ca.cnf"
        ca_cnf.write_text(
            "\n".join(
                [
                    "[req]",
                    "distinguished_name = dn",
                    "x509_extensions = v3_ca",
                    "prompt = no",
                    "[dn]",
                    "O = LKMP",
                    f"CN = {ca_common_name}",
                    "[v3_ca]",
                    "subjectKeyIdentifier = hash",
                    "authorityKeyIdentifier = keyid:always,issuer",
                    "basicConstraints = critical, CA:TRUE",
                    "keyUsage = critical, digitalSignature, cRLSign, keyCertSign",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        subprocess.run(
            [
                openssl_bin,
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(ca_key),
                "-out",
                str(ca_cert),
                "-days",
                str(max(validity_days, 365)),
                "-sha256",
                "-config",
                str(ca_cnf),
                "-extensions",
                "v3_ca",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        os.chmod(ca_key, 0o600)
        os.chmod(ca_cert, 0o644)

    all_hosts = list(hosts) + list(node_names or ())
    san_entries = _build_san_entries(all_hosts)

    _generate_signed_leaf(
        openssl_bin=openssl_bin,
        ca_cert=ca_cert,
        ca_key=ca_key,
        cert_path=node_cert,
        key_path=node_key,
        common_name=node_common_name,
        san_entries=san_entries,
        validity_days=validity_days,
    )

    named_nodes: Dict[str, tuple[Path, Path]] = {}
    for n_name in node_names or ():
        n_cert = target / f"{n_name}.crt"
        n_key = target / f"{n_name}.key"
        n_san = _build_san_entries([n_name, *hosts])
        _generate_signed_leaf(
            openssl_bin=openssl_bin,
            ca_cert=ca_cert,
            ca_key=ca_key,
            cert_path=n_cert,
            key_path=n_key,
            common_name=n_name,
            san_entries=n_san,
            validity_days=validity_days,
        )
        named_nodes[n_name] = (n_cert, n_key)

    return PkiBundlePaths(
        out_dir=target,
        ca_cert=ca_cert,
        ca_key=ca_key,
        node_cert=node_cert,
        node_key=node_key,
        named_nodes=named_nodes,
    )
