import oqs


DEFAULT_SIG_ALG = "Dilithium2"


def generate_keypair(algorithm: str = DEFAULT_SIG_ALG):
    with oqs.Signature(algorithm) as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()
    return public_key, secret_key


def sign_message(message: bytes, secret_key: bytes, algorithm: str = DEFAULT_SIG_ALG) -> bytes:
    with oqs.Signature(algorithm, secret_key) as signer:
        return signer.sign(message)


def verify_message(message: bytes, signature: bytes, public_key: bytes, algorithm: str = DEFAULT_SIG_ALG) -> bool:
    with oqs.Signature(algorithm) as verifier:
        return verifier.verify(message, signature, public_key)
