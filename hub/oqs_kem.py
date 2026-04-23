import os
import ctypes
from ctypes import c_char_p, c_int, c_size_t, c_uint8, c_void_p, POINTER, Structure

LIB_CANDIDATES = [
    "liboqs.so",
    "/usr/local/lib/liboqs.so",
    "/usr/local/lib64/liboqs.so",
    "/usr/lib/liboqs.so",
    "/usr/lib/x86_64-linux-gnu/liboqs.so",
]

lib = None
last_error = None

for candidate in LIB_CANDIDATES:
    try:
        lib = ctypes.CDLL(candidate)
        break
    except OSError as exc:
        last_error = exc

if lib is None:
    raise OSError(f"Could not load liboqs.so from known paths: {LIB_CANDIDATES}. Last error: {last_error}")


class OQS_KEM(Structure):
    _fields_ = [
        ("method_name", c_char_p),
        ("alg_version", c_char_p),
        ("claimed_nist_level", c_int),
        ("ind_cca", c_int),
        ("length_public_key", c_size_t),
        ("length_secret_key", c_size_t),
        ("length_ciphertext", c_size_t),
        ("length_shared_secret", c_size_t),
        ("keypair", c_void_p),
        ("encaps", c_void_p),
        ("decaps", c_void_p),
    ]


lib.OQS_KEM_new.argtypes = [c_char_p]
lib.OQS_KEM_new.restype = POINTER(OQS_KEM)

lib.OQS_KEM_free.argtypes = [POINTER(OQS_KEM)]
lib.OQS_KEM_free.restype = None

lib.OQS_KEM_keypair.argtypes = [POINTER(OQS_KEM), POINTER(c_uint8), POINTER(c_uint8)]
lib.OQS_KEM_keypair.restype = c_int

lib.OQS_KEM_encaps.argtypes = [POINTER(OQS_KEM), POINTER(c_uint8), POINTER(c_uint8), POINTER(c_uint8)]
lib.OQS_KEM_encaps.restype = c_int

lib.OQS_KEM_decaps.argtypes = [POINTER(OQS_KEM), POINTER(c_uint8), POINTER(c_uint8), POINTER(c_uint8)]
lib.OQS_KEM_decaps.restype = c_int


class KemError(Exception):
    pass


class Kem:
    def __init__(self, alg_candidates: list[bytes] | None = None):
        if alg_candidates is None:
            alg_candidates = [
                b"ML-KEM-768",
                b"Kyber768",
                b"OQS_KEM_alg_ml_kem_768",
                b"OQS_KEM_alg_kyber_768",
                b"ML-KEM-512",
                b"Kyber512",
                b"OQS_KEM_alg_ml_kem_512",
                b"OQS_KEM_alg_kyber_512",
            ]

        self.kem = None
        self.alg = None

        for alg in alg_candidates:
            kem = lib.OQS_KEM_new(alg)
            if kem:
                self.kem = kem
                self.alg = alg.decode(errors="ignore")
                break

        if not self.kem:
            raise KemError("No supported ML-KEM/Kyber algorithm found in liboqs")

        self.pk_len = int(self.kem.contents.length_public_key)
        self.sk_len = int(self.kem.contents.length_secret_key)
        self.ct_len = int(self.kem.contents.length_ciphertext)
        self.ss_len = int(self.kem.contents.length_shared_secret)

    def __del__(self):
        if getattr(self, "kem", None):
            try:
                lib.OQS_KEM_free(self.kem)
            except Exception:
                pass

    def keypair(self) -> tuple[bytes, bytes]:
        pk = (c_uint8 * self.pk_len)()
        sk = (c_uint8 * self.sk_len)()
        rc = lib.OQS_KEM_keypair(self.kem, pk, sk)
        if rc != 0:
            raise KemError("OQS_KEM_keypair failed")
        return bytes(pk), bytes(sk)

    def encaps(self, pk_bytes: bytes) -> tuple[bytes, bytes]:
        if len(pk_bytes) != self.pk_len:
            raise ValueError(f"pk length mismatch: expected {self.pk_len}, got {len(pk_bytes)}")

        ct = (c_uint8 * self.ct_len)()
        ss = (c_uint8 * self.ss_len)()
        pk = (c_uint8 * self.pk_len).from_buffer_copy(pk_bytes)

        rc = lib.OQS_KEM_encaps(self.kem, ct, ss, pk)
        if rc != 0:
            raise KemError("OQS_KEM_encaps failed")

        return bytes(ct), bytes(ss)

    def decaps(self, ct_bytes: bytes, sk_bytes: bytes) -> bytes:
        if len(ct_bytes) != self.ct_len:
            raise ValueError(f"ct length mismatch: expected {self.ct_len}, got {len(ct_bytes)}")
        if len(sk_bytes) != self.sk_len:
            raise ValueError(f"sk length mismatch: expected {self.sk_len}, got {len(sk_bytes)}")

        ss = (c_uint8 * self.ss_len)()
        ct = (c_uint8 * self.ct_len).from_buffer_copy(ct_bytes)
        sk = (c_uint8 * self.sk_len).from_buffer_copy(sk_bytes)

        rc = lib.OQS_KEM_decaps(self.kem, ss, ct, sk)
        if rc != 0:
            raise KemError("OQS_KEM_decaps failed")

        return bytes(ss)
