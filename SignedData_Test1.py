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
            salt_length=padding.PSS.MAX_LENGTH
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
MIICWwIBAAKBgQCQq5094oTTQbD601MQNWkgQjHXbfuIWSqYxpWZgzpIxl1gUNi4
n6LMKZUW7JT1Wpp/9s4WaAhmdGAmHjCo8cRNvWo/B2XkwsXveH2XYnhbWDOv7zGy
ycjVl+aN01JN3XszbPrw5edhygXdJz2MiGeRBahm9kd04XjdiTS+mnDHbwIDAQAB
AoGASrEP4d+NjDSiVx28COZKfGkwqnUSJHdE0tPUcQmbke84Tn3vJoLk3lupqchD
r9kzY1XdWRwlGiCDc6qqnM8V9fW5v4GmKP6mGGOHwxocw8KIOnh53nptu6q/OoZm
5PK4n5qhISiA53wdYjkqe5jfrQBhqNLWb0YQqqtOdalD9IECQQDQTsgWjPHhQB30
ADl+3LVVOxie9EgJRHfAtSibedabNaMkThj8I1QJma2AdzCGfPk/tpL9lB25ymNI
8CXwdlu/AkEAscr0PJ1uMvgSJfmreIlLaFqyuhl4wwb/r9QNgHewDS1tCEyEEg+2
fnD6+TUmFSOn5z6oglhaHfemQSrVrXJAUQJAAwuDxUCeMIq9ZVmzfXVAeVR50akE
fI4xqfF7/HnVd0NbdSZnGxhxHArRDHWxkeW1xwamM2q83IBm3yQTieZRBQJAYGjf
vCbaZQUkQjd7BifdHj9gf43kcE1RRTVGBQ3iB6NEZqWnUGv41+PIFG7/saLeH4VY
tyXV6D4sh1YE/MLhoQJAZMNe4nEk+0+ajh1eUcw1F7POqY4tx4XYInNlLbe8f64l
ZKZ9NYJFINlZpo3wrUCoSoove37f0fPLZ1mkoU3yOw==
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
