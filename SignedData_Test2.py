from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import base64

def sign_by_private_key(input_text, private_key):
    input_bytes = input_text.encode('utf-16-le')
    signature = private_key.sign(
        input_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def verify_by_public_key(input_text, signature, public_key):
    input_bytes = input_text.encode('utf-16-le')
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
input_text = f"{userId}-{idempotencyKey}"

signature = sign_by_private_key(input_text, private_key)
print(f"idempotencyKeySignature: {signature}")

is_verified = verify_by_public_key(input_text, signature, public_key)
print(f"SignatureVerified: {is_verified}")
