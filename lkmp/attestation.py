"""Cryptographic Merkle-tree checkpoint attestation and tamper detection (`manifest.sig.json`)."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
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
    dest_pages_merkle_root: Optional[str] = None
    expected_pages_bytes: Optional[int] = None

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
            dest_pages_merkle_root=data.get("dest_pages_merkle_root"),
            expected_pages_bytes=data.get("expected_pages_bytes"),
        )


CheckpointManifest = CheckpointAttestationManifest


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


def compute_directory_img_digests(
    images_dir: str | Path,
    prefix_filter: Optional[str] = None,
) -> Tuple[List[ImageFileDigest], str]:
    """Compute `(digests, merkle_root)` for `.img` files in `images_dir`."""
    root = Path(images_dir)
    if not root.exists():
        return [], compute_merkle_root([])

    img_files = sorted(
        p
        for p in root.iterdir()
        if p.is_file()
        and p.name.endswith(".img")
        and (prefix_filter is None or p.name.startswith(prefix_filter))
    )
    digests: List[ImageFileDigest] = []
    leaf_hashes: List[str] = []
    for img in img_files:
        sha = _hash_file(img)
        size = img.stat().st_size
        digests.append(ImageFileDigest(filename=img.name, size_bytes=size, sha256=sha))
        leaf = hashlib.sha256(f"{img.name}:{size}:{sha}".encode("utf-8")).hexdigest()
        leaf_hashes.append(leaf)

    return digests, compute_merkle_root(leaf_hashes)


def _compute_manifest_hmac(
    migration_id: str,
    pid: int,
    merkle_root: str,
    dest_pages_merkle_root: Optional[str],
    secret_key: bytes,
    expected_pages_bytes: Optional[int] = None,
) -> str:
    pages_part = dest_pages_merkle_root or ""
    exp_pages_part = str(expected_pages_bytes) if expected_pages_bytes is not None else ""
    msg = f"{migration_id}:{pid}:{merkle_root}:{pages_part}:{exp_pages_part}".encode("utf-8")
    return hmac.new(secret_key, msg, hashlib.sha256).hexdigest()


def resolve_attestation_key(
    explicit_key: Optional[bytes] = None,
    key_hex: Optional[str] = None,
) -> bytes:
    """
    Resolve the HMAC attestation key from explicit bytes, hex config, or `LKMP_ATTESTATION_KEY`.
    If none is provided, raises ValueError unless generating an ephemeral per-session key.
    """
    if explicit_key is not None:
        return explicit_key
    if key_hex:
        return bytes.fromhex(key_hex)
    env_key = os.environ.get("LKMP_ATTESTATION_KEY")
    if env_key:
        try:
            return bytes.fromhex(env_key)
        except ValueError:
            return env_key.encode("utf-8")
    raise ValueError(
        "Attestation key not configured: set LKMP_ATTESTATION_KEY or MigrationConfig.attestation_key_hex"
    )


def generate_ephemeral_key_hex() -> str:
    """Generate a cryptographically random 256-bit ephemeral attestation key."""
    return secrets.token_hex(32)


class CheckpointAttestor:
    """Signs CRIU image directories on Source A and verifies integrity on Destination B."""

    MANIFEST_FILENAME = "manifest.sig.json"

    def __init__(self, secret_key: Optional[bytes] = None) -> None:
        self._secret_key = secret_key

    def _get_key(self, key_hex: Optional[str] = None) -> bytes:
        return resolve_attestation_key(explicit_key=self._secret_key, key_hex=key_hex)

    def generate_manifest(
        self,
        images_dir: str | Path,
        migration_id: str,
        pid: int,
        dest_pages_merkle_root: Optional[str] = None,
        key_hex: Optional[str] = None,
        expected_pages_bytes: Optional[int] = None,
    ) -> CheckpointAttestationManifest:
        """Scan `.img` files in `images_dir`, build a Merkle root, and write `manifest.sig.json`."""
        secret_key = self._get_key(key_hex)
        root = Path(images_dir)
        digests, merkle_root = compute_directory_img_digests(root)
        signature = _compute_manifest_hmac(
            migration_id=migration_id,
            pid=pid,
            merkle_root=merkle_root,
            dest_pages_merkle_root=dest_pages_merkle_root,
            secret_key=secret_key,
            expected_pages_bytes=expected_pages_bytes,
        )

        manifest = CheckpointAttestationManifest(
            migration_id=migration_id,
            pid=pid,
            created_at_unix=time.time(),
            merkle_root=merkle_root,
            hmac_signature=signature,
            files=digests,
            dest_pages_merkle_root=dest_pages_merkle_root,
            expected_pages_bytes=expected_pages_bytes,
        )
        manifest_path = root / self.MANIFEST_FILENAME
        manifest_path.write_text(json.dumps(manifest.to_dict(), indent=2), encoding="utf-8")
        return manifest

    def verify_directory(
        self,
        images_dir: str | Path,
        expected_migration_id: Optional[str] = None,
        key_hex: Optional[str] = None,
    ) -> CheckpointAttestationManifest:
        """
        Verify `manifest.sig.json`, HMAC signature, Merkle root, and every `.img` file on Destination B.
        Raises `ValueError` if the manifest or any image file is missing, modified, or corrupted.
        """
        secret_key = self._get_key(key_hex)
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
            migration_id=manifest.migration_id,
            pid=manifest.pid,
            merkle_root=manifest.merkle_root,
            dest_pages_merkle_root=manifest.dest_pages_merkle_root,
            secret_key=secret_key,
            expected_pages_bytes=manifest.expected_pages_bytes,
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

        # Also verify page-server received pages-*.img on Destination B if attested
        if manifest.dest_pages_merkle_root is not None:
            _page_digests, actual_pages_root = compute_directory_img_digests(
                root, prefix_filter="pages-"
            )
            if actual_pages_root != manifest.dest_pages_merkle_root:
                raise ValueError(
                    "Destination page-server pages-*.img Merkle root mismatch: "
                    f"expected {manifest.dest_pages_merkle_root}, got {actual_pages_root}"
                )

        # Verify total pages-*.img byte size if expected_pages_bytes is set > 0
        if manifest.expected_pages_bytes is not None and manifest.expected_pages_bytes > 0:
            actual_pages_bytes = sum(
                p.stat().st_size
                for p in root.iterdir()
                if p.is_file() and p.name.startswith("pages-") and p.name.endswith(".img")
            )
            if actual_pages_bytes != manifest.expected_pages_bytes:
                raise ValueError(
                    f"Destination pages-*.img total byte size mismatch: "
                    f"expected {manifest.expected_pages_bytes}, got {actual_pages_bytes}"
                )

        return manifest
