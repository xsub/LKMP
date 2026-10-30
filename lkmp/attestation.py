"""Cryptographic Merkle-tree checkpoint attestation and tamper detection (`manifest.sig.json`)."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ImageFileDigest:
    """Cryptographic digest of a single CRIU `.img` file."""

    filename: str
    size_bytes: int
    sha256: str


@dataclass
class CheckpointAttestationManifest:
    """Merkle-tree manifest & HMAC-SHA256 attestation over a CRIU checkpoint directory."""

    migration_id: str
    pid: int
    created_at_unix: float
    merkle_root: str
    hmac_signature: str
    files: List[ImageFileDigest] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CheckpointAttestationManifest:
        files = [ImageFileDigest(**f) for f in data.get("files", [])]
        return cls(
            migration_id=data["migration_id"],
            pid=int(data["pid"]),
            created_at_unix=float(data["created_at_unix"]),
            merkle_root=data["merkle_root"],
            hmac_signature=data["hmac_signature"],
            files=files,
        )


def compute_merkle_root(leaf_hashes: List[str]) -> str:
    """Compute a binary SHA-256 Merkle root from an ordered list of hex leaf hashes."""
    if not leaf_hashes:
        return hashlib.sha256(b"EMPTY_CHECKPOINT").hexdigest()

    current_level = [bytes.fromhex(h) for h in leaf_hashes]
    while len(current_level) > 1:
        next_level: List[bytes] = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            combined = hashlib.sha256(b"\x01" + left + right).digest()
            next_level.append(combined)
        current_level = next_level

    return current_level[0].hex()


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _compute_manifest_hmac(
    migration_id: str,
    pid: int,
    merkle_root: str,
    secret_key: bytes,
) -> str:
    msg = f"{migration_id}:{pid}:{merkle_root}".encode("utf-8")
    return hmac.new(secret_key, msg, hashlib.sha256).hexdigest()


class CheckpointAttestor:
    """Signs CRIU image directories on Source A and verifies integrity on Destination B."""

    MANIFEST_FILENAME = "manifest.sig.json"

    def __init__(self, secret_key: Optional[bytes] = None) -> None:
        self.secret_key = secret_key or b"lkmp-default-cluster-attestation-key-v1"

    def generate_manifest(
        self,
        images_dir: str | Path,
        migration_id: str,
        pid: int,
    ) -> CheckpointAttestationManifest:
        """Scan all `.img` files in `images_dir`, build a Merkle root, and write `manifest.sig.json`."""
        root = Path(images_dir)
        img_files = sorted(
            p for p in root.iterdir() if p.is_file() and p.name.endswith(".img")
        )

        digests: List[ImageFileDigest] = []
        leaf_hashes: List[str] = []

        for img in img_files:
            sha = _hash_file(img)
            size = img.stat().st_size
            digests.append(ImageFileDigest(filename=img.name, size_bytes=size, sha256=sha))
            leaf = hashlib.sha256(f"{img.name}:{size}:{sha}".encode("utf-8")).hexdigest()
            leaf_hashes.append(leaf)

        merkle_root = compute_merkle_root(leaf_hashes)
        signature = _compute_manifest_hmac(migration_id, pid, merkle_root, self.secret_key)

        manifest = CheckpointAttestationManifest(
            migration_id=migration_id,
            pid=pid,
            created_at_unix=time.time(),
            merkle_root=merkle_root,
            hmac_signature=signature,
            files=digests,
        )
        manifest_path = root / self.MANIFEST_FILENAME
        manifest_path.write_text(json.dumps(manifest.to_dict(), indent=2), encoding="utf-8")
        return manifest

    def verify_directory(
        self,
        images_dir: str | Path,
        expected_migration_id: Optional[str] = None,
    ) -> CheckpointAttestationManifest:
        """
        Verify `manifest.sig.json`, HMAC signature, Merkle root, and every `.img` file on Destination B.
        Raises `ValueError` if any image file is missing, modified, or corrupted in transit.
        """
        root = Path(images_dir)
        manifest_path = root / self.MANIFEST_FILENAME
        if not manifest_path.exists():
            raise ValueError(f"Checkpoint attestation manifest missing: {manifest_path}")

        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest = CheckpointAttestationManifest.from_dict(raw)

        if expected_migration_id and manifest.migration_id != expected_migration_id:
            raise ValueError(
                f"Manifest migration_id mismatch: expected {expected_migration_id}, "
                f"got {manifest.migration_id}"
            )

        expected_sig = _compute_manifest_hmac(
            manifest.migration_id,
            manifest.pid,
            manifest.merkle_root,
            self.secret_key,
        )
        if not hmac.compare_digest(manifest.hmac_signature, expected_sig):
            raise ValueError("Invalid HMAC signature on checkpoint attestation manifest")

        leaf_hashes: List[str] = []
        for entry in manifest.files:
            img_path = root / entry.filename
            if not img_path.exists():
                raise ValueError(f"Attested checkpoint image missing on destination: {entry.filename}")
            actual_size = img_path.stat().st_size
            if actual_size != entry.size_bytes:
                raise ValueError(
                    f"Checkpoint image size mismatch for {entry.filename}: "
                    f"expected {entry.size_bytes}, got {actual_size}"
                )
            actual_sha = _hash_file(img_path)
            if actual_sha != entry.sha256:
                raise ValueError(
                    f"Checkpoint image SHA-256 integrity failure for {entry.filename}: "
                    f"expected {entry.sha256[:12]}..., got {actual_sha[:12]}..."
                )
            leaf = hashlib.sha256(
                f"{entry.filename}:{actual_size}:{actual_sha}".encode("utf-8")
            ).hexdigest()
            leaf_hashes.append(leaf)

        recomputed_root = compute_merkle_root(leaf_hashes)
        if recomputed_root != manifest.merkle_root:
            raise ValueError(
                f"Checkpoint Merkle root mismatch: expected {manifest.merkle_root}, "
                f"recomputed {recomputed_root}"
            )

        return manifest
