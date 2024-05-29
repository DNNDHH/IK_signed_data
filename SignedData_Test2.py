from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import base64

def sign_by_private_key(input_text, private_key):
    input_bytes = input_text.encode('utf-8')
    signature = private_key.sign(
        input_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def verify_by_public_key(input_text, signature, public_key):
    input_bytes = input_text.encode('utf-8')
    signature_bytes = base64.b64decode(signature)
    try:
        public_key.verify(
            signature_bytes,
            input_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except:
        return False

# RSA 1024 bits private key
pem_private_key = b"""
-----BEGIN RSA PRIVATE KEY-----
MIICWAIBAAKBgLkG1MbGaKzsCnfEz/v5Pv0mSffavUujhNKjmAAUdlBuE6v+uxMH
ezdep9kH1FZRZHtYRjN1M6oeqckKVMhK82DMkoRxjCjwyknnM6VKO8uMbI3jbZwE
jEv7yyNjxNIF7jVq5ifJujc13uainCQw2Y2UyJD3pmSgZp7xkt9vM9lVAgMBAAEC
gYAdGhn1edeU+ztaQzaDZ1yk7JTNyzXi48FMcDbELHO/itDFSLeb8p1KxDSaSkT3
nq2zSNsh1NlfdJs358wWBNPqrSBOEQGrcwUqob59mLQysxddE8HKN0kN7ZfLiebp
y1xHxTqV1VEBmTlon9sMyYa5wbjJ8teSBQnvXP5JCnw2sQJAytZc/rIxKSazx2is
os89qJFkzIEK4QhopCvSiDWarsYRi79KIxizrL0PCK0qAu6OXFsy5F2Ei+YXw++I
Hhgx2wJA6YVwCKnGybW5hDKy7+XdFPpy0mhLxcGMWo9LQKCCSTKXqj6IOH3HOvnc
iXN7NUf/TwN6mFzrsBHzyKrXJhAAjwJAnNIhMfW41nUKt9hw6KtLo4FNqmL2c0da
B9utuQugnRGbzSzG992IRLwi3HVtLrkbrcIA1diLutHZe+48ke/o0wJANVdPogr1
53llKPdTvEyrVXFn7Pv54vA1GTKGI/sGB6ZQ0oh6IT1J1wTgBV2llSQfA3Nt+4Ou
KofPQdUUVBNvrQJAeFeVPpvWJTiMWCN2NMmJXqqdva8J1XIT047x5fdg72LcPOU+
xCGlz9vV3+AAQ31C2phoyd/QhvpL85p39n6Ibg==
-----END RSA PRIVATE KEY-----
"""

# RSA 1024 bits public key
pem_public_key = b"""
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCQq5094oTTQbD601MQNWkgQjHX
bfuIWSqYxpWZgzpIxl1gUNi4n6LMKZUW7JT1Wpp/9s4WaAhmdGAmHjCo8cRNvWo/
B2XkwsXveH2XYnhbWDOv7zGyycjVl+aN01JN3XszbPrw5edhygXdJz2MiGeRBahm
9kd04XjdiTS+mnDHbwIDAQAB
-----END PUBLIC KEY-----
"""

# Load private key
private_key = serialization.load_pem_private_key(
    pem_private_key,
    password=None,
    backend=default_backend()
)

# Load public key
public_key = serialization.load_pem_public_key(
    pem_public_key,
    backend=default_backend()
)

# Main code
userId = "142821649"
idempotencyKey = "b5b08324-62c1-48c4-b0a2-72976c05894b"
input_text = f"{userId}{idempotencyKey}"

signature = sign_by_private_key(input_text, private_key)
print(f"idempotencyKeySignature: {signature}")

is_verified = verify_by_public_key(input_text, signature, public_key)
print(f"SignatureVerified: {is_verified}")
