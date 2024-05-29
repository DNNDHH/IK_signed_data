import base64
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def make_signed_data(private_key, hash_algorithm, idempotency_key):

    if not hash_algorithm:
        return "NO HASH"

    key_bytes = idempotency_key.encode('utf-8')

    hash_obj = hashlib.new(hash_algorithm)
    hash_obj.update(key_bytes)
    hash_bytes = hash_obj.digest()

    signature = private_key.sign(
        hash_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PKCS1v15()
        ),
        hashes.SHA256()
    )

    base64_signature = base64.b64encode(signature).decode('utf-8')
    return base64_signature

def main():

    hash_algorithm = "SHA256"
    idempotency_key = "b5b08324-62c1-48c4-b0a2-72976c05894b"

    sample_private_key = b"""
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

    private_key = serialization.load_pem_private_key(
        sample_private_key,
        password=None,
        backend=default_backend()
    )

    signed_data = make_signed_data(private_key, hash_algorithm, idempotency_key)

    print("idempotencyKeySignature:", signed_data)

if __name__ == "__main__":
    main()
