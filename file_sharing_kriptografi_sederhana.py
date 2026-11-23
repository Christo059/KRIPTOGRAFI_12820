"""
DEMO FILE SHARING TERENKRIPSI DENGAN PERLINDUNGAN MITM
Berdasarkan laporan: File Sharing Terenkripsi dengan Perlindungan MITM.

Algoritma:
- AES-256-GCM : enkripsi isi file, metadata, dan pembungkusan FK
- X25519      : pertukaran shared secret Alice-Bob
- HKDF-SHA256 : derivasi KEK, K_content, dan K_meta
- Ed25519     : tanda tangan digital manifest
- SHA-256     : fingerprint dan hash tag

PERINGATAN:
Ini implementasi demonstrasi/pembelajaran, bukan protokol produksi yang diaudit.
Fingerprint HARUS dicocokkan melalui kanal independen (misalnya tatap muka/telepon).
Demo ini meminta pengguna mengetik fingerprint yang disampaikan melalui kanal tersebut.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


CHUNK_SIZE = 64 * 1024
PROTOCOL_VERSION = "fs-v1"
TAG_SIZE = 16
EXPIRY_SECONDS = 24 * 60 * 60


# ---------------------------------------------------------------------------
# Fungsi bantu tampilan (hanya untuk print, tidak memengaruhi logika kripto)
# ---------------------------------------------------------------------------
LINE = "=" * 56


def print_title(text: str) -> None:
    """Judul besar program."""
    print(LINE)
    print(f"  {text}")
    print(LINE)


def print_section(text: str) -> None:
    """Judul tiap tahap."""
    print(f"\n--- {text} ---")


def print_ok(text: str) -> None:
    print(f"  [OK] {text}")


def print_info(text: str) -> None:
    print(f"  [..] {text}")


def format_size(size: int) -> str:
    """Ukuran byte -> teks yang mudah dibaca."""
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.2f} MB"


def format_fingerprint(fp: str) -> str:
    """Fingerprint 64 hex dipecah per 8 karakter agar mudah dibandingkan."""
    return "    " + " ".join(fp[i:i + 8] for i in range(0, len(fp), 8))


# ---------------------------------------------------------------------------
# Fungsi kriptografi
# ---------------------------------------------------------------------------
def canonical_encode(data: Any) -> bytes:
    """Mengubah data menjadi JSON bytes yang konsisten untuk tanda tangan/AAD."""
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def b64e(data: bytes) -> str:
    """Bytes menjadi teks Base64 agar dapat disimpan sebagai JSON."""
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    """Teks Base64 dikembalikan menjadi bytes."""
    return base64.b64decode(data.encode("ascii"))


def raw_public_key(public_key) -> bytes:
    """Mengambil representasi raw dari public key X25519/Ed25519."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def fingerprint(identity_public: ed25519.Ed25519PublicKey,
                dh_public: x25519.X25519PublicKey) -> str:
    """
    Fingerprint SHA-256 dari gabungan public key identitas (Ed25519)
    dan public key pertukaran kunci (X25519), sesuai rancangan laporan.
    """
    combined = raw_public_key(identity_public) + raw_public_key(dh_public)
    return hashlib.sha256(combined).hexdigest()


def derive_key(secret: bytes, salt: bytes, info: bytes) -> bytes:
    """HKDF-SHA256 menghasilkan kunci 32 byte (256 bit)."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    ).derive(secret)


def chunk_nonce(index: int) -> bytes:
    """
    AES-GCM memerlukan nonce 12 byte.
    Nomor chunk diubah menjadi 12 byte big-endian.
    Aman dalam demo ini karena K_content unik untuk setiap file.
    """
    if index < 0 or index >= 2**96:
        raise ValueError("Nomor chunk di luar batas nonce.")
    return index.to_bytes(12, byteorder="big")


def make_wrap_context(file_id: str, ephemeral_public: bytes,
                      bob_dh_public: bytes) -> bytes:
    """Konteks yang sama harus dibentuk Alice dan Bob."""
    return canonical_encode({
        "protocol": PROTOCOL_VERSION + "/wrap",
        "sender": "Alice",
        "receiver": "Bob",
        "file_id": file_id,
        "ephemeral_public": b64e(ephemeral_public),
        "bob_dh_public": b64e(bob_dh_public),
    })


class Alice:
    def __init__(self):
        # Kunci identitas untuk tanda tangan Ed25519.
        self.identity_private = ed25519.Ed25519PrivateKey.generate()
        self.identity_public = self.identity_private.public_key()

        # Kunci X25519 jangka panjang untuk menerima/menyetujui pertukaran kunci.
        self.dh_private = x25519.X25519PrivateKey.generate()
        self.dh_public = self.dh_private.public_key()

    def send_file(self, file_path: Path, bob_dh_public: x25519.X25519PublicKey,
                  server: "UntrustedServer") -> str:
        if not file_path.is_file():
            raise FileNotFoundError(f"File tidak ditemukan: {file_path}")

        file_bytes = file_path.read_bytes()
        file_id = os.urandom(16).hex()
        file_key = os.urandom(32)  # FK baru untuk setiap file

        print_info(f"Membaca file: {file_path.name} "
                   f"({format_size(len(file_bytes))})")
        print_ok("File Key (FK) acak dibuat")

        # Kunci terpisah untuk isi file dan metadata.
        k_content = derive_key(
            file_key, bytes.fromhex(file_id), b"fs-v1/content"
        )
        k_meta = derive_key(
            file_key, bytes.fromhex(file_id), b"fs-v1/meta"
        )

        # Enkripsi metadata memakai kunci berbeda dari isi file.
        metadata = canonical_encode({
            "filename": file_path.name,
            "size": len(file_bytes),
        })
        meta_nonce = b"\x00" * 12
        meta_ciphertext = AESGCM(k_meta).encrypt(
            meta_nonce, metadata, file_id.encode("ascii")
        )
        print_ok("Metadata (nama & ukuran file) dienkripsi")

        # Enkripsi isi file per chunk, masing-masing dengan AAD yang mengikat
        # versi protokol, file_id, nomor chunk, dan penanda chunk terakhir.
        chunks = [
            file_bytes[i:i + CHUNK_SIZE]
            for i in range(0, len(file_bytes), CHUNK_SIZE)
        ]
        if not chunks:  # file kosong tetap direpresentasikan satu chunk kosong
            chunks = [b""]

        encrypted_chunks = []
        tags = []

        for index, chunk in enumerate(chunks):
            is_last = index == len(chunks) - 1
            aad = canonical_encode({
                "protocol": PROTOCOL_VERSION,
                "file_id": file_id,
                "index": index,
                "last": is_last,
            })
            encrypted = AESGCM(k_content).encrypt(
                chunk_nonce(index), chunk, aad
            )
            ciphertext, tag = encrypted[:-TAG_SIZE], encrypted[-TAG_SIZE:]
            encrypted_chunks.append({
                "ciphertext": b64e(ciphertext),
                "tag": b64e(tag),
            })
            tags.append(tag)
        print_ok(f"Isi file dienkripsi ({len(encrypted_chunks)} chunk)")

        tags_hash = hashlib.sha256(canonical_encode(
            [b64e(tag) for tag in tags]
        )).hexdigest()

        # X25519 ephemeral: pasangan sementara Alice dibuat untuk file ini.
        ephemeral_private = x25519.X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key()
        ephemeral_public_raw = raw_public_key(ephemeral_public)
        bob_dh_raw = raw_public_key(bob_dh_public)

        shared_secret = ephemeral_private.exchange(bob_dh_public)
        context = make_wrap_context(
            file_id, ephemeral_public_raw, bob_dh_raw
        )
        kek = derive_key(
            shared_secret,
            hashlib.sha256(context).digest(),
            b"fs-v1/kek",
        )

        wrap_nonce = os.urandom(12)
        wrapped_file_key = AESGCM(kek).encrypt(
            wrap_nonce, file_key, context
        )
        print_ok("FK dibungkus dengan kunci bersama Alice-Bob (X25519)")

        # Manifest memuat parameter penting dan ditandatangani Alice.
        manifest = {
            "version": PROTOCOL_VERSION,
            "file_id": file_id,
            "sender": "Alice",
            "receiver": "Bob",
            "ephemeral_public": b64e(ephemeral_public_raw),
            "wrap_nonce": b64e(wrap_nonce),
            "wrapped_file_key": b64e(wrapped_file_key),
            "meta_nonce": b64e(meta_nonce),
            "meta_ciphertext": b64e(meta_ciphertext),
            "chunk_count": len(encrypted_chunks),
            "tags_hash": tags_hash,
            "expires_at": int(time.time()) + EXPIRY_SECONDS,
        }
        manifest_bytes = canonical_encode(manifest)
        signature = self.identity_private.sign(manifest_bytes)
        print_ok("Manifest ditandatangani Alice (Ed25519)")

        package = {
            "manifest": manifest,
            "signature": b64e(signature),
            "chunks": encrypted_chunks,
        }
        server.upload(file_id, package)
        print_ok("Paket terenkripsi diunggah ke server")

        # Catatan: Python tidak menjamin penghapusan aman bytes/kunci dari RAM.
        del ephemeral_private, shared_secret, kek, file_key
        return file_id


class UntrustedServer:
    """
    Server hanya menyimpan dan meneruskan paket.
    Server tidak menerima FK maupun kunci privat Alice/Bob.
    Penyimpanan JSON ini hanya simulasi server lokal.
    """
    def __init__(self, storage_dir: Path):
        self.storage_dir = storage_dir
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def upload(self, file_id: str, package: dict) -> None:
        path = self.storage_dir / f"{file_id}.json"
        path.write_text(
            json.dumps(package, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def download(self, file_id: str) -> dict:
        path = self.storage_dir / f"{file_id}.json"
        if not path.is_file():
            raise FileNotFoundError("File tidak ditemukan di server.")
        return json.loads(path.read_text(encoding="utf-8"))


class Bob:
    def __init__(self):
        self.identity_private = ed25519.Ed25519PrivateKey.generate()
        self.identity_public = self.identity_private.public_key()

        self.dh_private = x25519.X25519PrivateKey.generate()
        self.dh_public = self.dh_private.public_key()

        # Untuk demo, daftar replay disimpan selama program berjalan.
        self.seen_file_ids: set[str] = set()

    def receive_file(self, file_id: str, alice_identity_public,
                     server: UntrustedServer, output_dir: Path) -> Path:
        package = server.download(file_id)
        manifest = package["manifest"]
        signature = b64d(package["signature"])
        chunks = package["chunks"]
        print_ok("Paket diunduh dari server")

        # 1. Verifikasi tanda tangan sebelum mempercayai isi manifest.
        manifest_bytes = canonical_encode(manifest)
        try:
            alice_identity_public.verify(signature, manifest_bytes)
        except InvalidSignature as exc:
            raise ValueError(
                "Tanda tangan Alice tidak valid. File ditolak."
            ) from exc
        print_ok("Tanda tangan Alice valid")

        # 2. Pemeriksaan versi, pengirim/penerima, kedaluwarsa, dan replay.
        if manifest["version"] != PROTOCOL_VERSION:
            raise ValueError("Versi protokol tidak dikenal.")
        if manifest["sender"] != "Alice" or manifest["receiver"] != "Bob":
            raise ValueError("Identitas pengirim/penerima tidak sesuai.")
        if int(time.time()) >= int(manifest["expires_at"]):
            raise ValueError("File sudah kedaluwarsa.")

        if file_id in self.seen_file_ids:
            raise ValueError("File ID sudah pernah diterima (replay).")
        if manifest["file_id"] != file_id:
            raise ValueError("File ID tidak cocok.")

        expected_count = int(manifest["chunk_count"])
        if len(chunks) != expected_count:
            raise ValueError("Jumlah chunk tidak sesuai.")

        tags = [b64d(item["tag"]) for item in chunks]
        actual_tags_hash = hashlib.sha256(canonical_encode(
            [b64e(tag) for tag in tags]
        )).hexdigest()
        if actual_tags_hash != manifest["tags_hash"]:
            raise ValueError("Hash tag tidak cocok.")
        print_ok("Versi, identitas, masa berlaku, replay, dan hash tag aman")

        # 3. Bob membentuk shared secret yang sama menggunakan private X25519.
        ephemeral_public_raw = b64d(manifest["ephemeral_public"])
        ephemeral_public = x25519.X25519PublicKey.from_public_bytes(
            ephemeral_public_raw
        )
        bob_dh_raw = raw_public_key(self.dh_public)

        shared_secret = self.dh_private.exchange(ephemeral_public)
        context = make_wrap_context(
            file_id, ephemeral_public_raw, bob_dh_raw
        )
        kek = derive_key(
            shared_secret,
            hashlib.sha256(context).digest(),
            b"fs-v1/kek",
        )

        # 4. Buka FK menggunakan KEK. Tag GCM juga diverifikasi di sini.
        try:
            file_key = AESGCM(kek).decrypt(
                b64d(manifest["wrap_nonce"]),
                b64d(manifest["wrapped_file_key"]),
                context,
            )
        except InvalidTag as exc:
            raise ValueError("FK tidak dapat dibuka; paket ditolak.") from exc
        print_ok("FK berhasil dibuka")

        # 5. Turunkan kembali kunci isi dan metadata.
        file_id_bytes = bytes.fromhex(file_id)
        k_content = derive_key(
            file_key, file_id_bytes, b"fs-v1/content"
        )
        k_meta = derive_key(
            file_key, file_id_bytes, b"fs-v1/meta"
        )

        try:
            metadata_bytes = AESGCM(k_meta).decrypt(
                b64d(manifest["meta_nonce"]),
                b64d(manifest["meta_ciphertext"]),
                file_id.encode("ascii"),
            )
            metadata = json.loads(metadata_bytes.decode("utf-8"))
        except (InvalidTag, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Metadata gagal diverifikasi.") from exc
        print_ok(f"Metadata terbaca: {metadata['filename']} "
                 f"({format_size(int(metadata['size']))})")

        # 6. Dekripsi semua chunk. Jika satu gagal, tidak ada file yang disimpan.
        plaintext_chunks = []
        for index, item in enumerate(chunks):
            aad = canonical_encode({
                "protocol": PROTOCOL_VERSION,
                "file_id": file_id,
                "index": index,
                "last": index == expected_count - 1,
            })
            ciphertext_and_tag = (
                b64d(item["ciphertext"]) + b64d(item["tag"])
            )
            try:
                plaintext = AESGCM(k_content).decrypt(
                    chunk_nonce(index), ciphertext_and_tag, aad
                )
            except InvalidTag as exc:
                raise ValueError(
                    f"Chunk {index} gagal autentikasi. Seluruh file ditolak."
                ) from exc
            plaintext_chunks.append(plaintext)

        complete_file = b"".join(plaintext_chunks)
        if len(complete_file) != int(metadata["size"]):
            raise ValueError("Ukuran file hasil dekripsi tidak sesuai.")
        print_ok(f"Semua chunk ({expected_count}) berhasil didekripsi "
                 "& terautentikasi")

        # Hindari nama path dari metadata; hanya gunakan nama dasar.
        safe_name = Path(metadata["filename"]).name
        if not safe_name:
            safe_name = "file_diterima.bin"

        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / safe_name
        output_path.write_bytes(complete_file)

        # Tandai seen setelah seluruh verifikasi dan penyimpanan berhasil.
        self.seen_file_ids.add(file_id)

        del shared_secret, kek, file_key
        return output_path


def verify_fingerprint_interactively(label: str, expected: str) -> None:
    """
    Pengguna harus membandingkan fingerprint melalui kanal independen.
    Jangan mengambil nilai pembanding dari server yang sama.
    """
    print(f"\nFingerprint {label}:")
    print(format_fingerprint(expected))
    typed = ""
    prompt = "  Tempel/ketik fingerprint lengkap (64 karakter): "
    # Jika fingerprint ditempel dua baris, baris berikutnya tetap dibaca
    # sampai 64 karakter terkumpul (atau baris kosong dimasukkan).
    while True:
        line = input(prompt).strip().lower().replace(":", "").replace(" ", "")
        typed += line
        if len(typed) >= len(expected) or not line:
            break
        prompt = "  (lanjutan) "
    if typed != expected:
        raise ValueError(
            f"Fingerprint {label} tidak cocok. Proses dihentikan."
        )
    print_ok(f"Fingerprint {label} cocok")


def main() -> None:
    print_title("FILE SHARING TERENKRIPSI (Alice -> Bob)")

    alice = Alice()
    bob = Bob()
    server = UntrustedServer(Path("server_storage"))

    try:
        # Fingerprint tetap diperiksa untuk menunjukkan verifikasi identitas.
        print_section("TAHAP 1: Verifikasi Identitas (anti-MITM)")
        print("Bandingkan fingerprint lewat kanal lain (tatap muka/telepon).")

        bob_fp = fingerprint(bob.identity_public, bob.dh_public)
        verify_fingerprint_interactively("Bob", bob_fp)

        alice_fp = fingerprint(alice.identity_public, alice.dh_public)
        verify_fingerprint_interactively("Alice", alice_fp)

        print_section("TAHAP 2: Pilih File")
        file_input = input("  Masukkan lokasi file: ").strip()
        file_path = Path(file_input).expanduser()

        print_section("TAHAP 3: Alice Mengenkripsi & Mengirim")
        file_id = alice.send_file(file_path, bob.dh_public, server)

        print_section("TAHAP 4: Bob Menerima & Mendekripsi")
        output_dir = Path("hasil_dekripsi")
        saved_path = bob.receive_file(
            file_id, alice.identity_public, server, output_dir
        )

        print(f"\n{LINE}")
        print("  SELESAI: File berhasil dikirim dan diterima dengan aman")
        print(f"  Lokasi hasil: {saved_path.resolve()}")
        print(LINE)

    except (OSError, ValueError, KeyError, InvalidTag) as error:
        print(f"\n{LINE}")
        print(f"  [GAGAL] {error}")
        print(LINE)
        sys.exit(1)


if __name__ == "__main__":
    main()
