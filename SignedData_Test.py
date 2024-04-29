import hashlib

def calculate_idempotency_key_signature(io, ks):
    exist_key = bytes.fromhex('6F8D9F2C')
    result = bytearray()
    
    for io_item in io:
        current_iter = io_item
        for j in range(current_iter):
            a = ks[current_iter][j]
            tmp_mod = j % len(exist_key)
            result.append(exist_key[tmp_mod] ^ exist_key[j])
    
    return hashlib.sha256(result).hexdigest()

io = [1, 2, 3]  
ks = [[b'abc', b'def'], [b'ghi', b'jkl'], [b'mno', b'pqr']]  

idempotency_key_signature = calculate_idempotency_key_signature(io, ks)
print("IdempotencyKeySignature:", idempotency_key_signature)
