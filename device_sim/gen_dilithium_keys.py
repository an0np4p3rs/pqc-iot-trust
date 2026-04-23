import base64
from oqs_sig import generate_keypair

#pk, sk = generate_keypair("Dilithium2")
pk, sk = generate_keypair("ML-DSA-44") #New name for Dilithium2 according to NIST

print("MANUFACTURER_PUBLIC_KEY_B64=" + base64.b64encode(pk).decode())
print("MANUFACTURER_SECRET_KEY_B64=" + base64.b64encode(sk).decode())
