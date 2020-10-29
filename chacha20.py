BLOCK_CONSTANTS = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

def main():
    runtests()

def chacha20_decrypt(key, counter, nonce, ciphertext):
    return chacha20_encrypt(key, counter, nonce, ciphertext)

def chacha20_encrypt(key, counter, nonce, plaintext):
    byte_length = len(plaintext)
    full_blocks = byte_length//64
    encrypted_message = b''

    for i in range(full_blocks):
        key_stream = serialize(chacha20_block(key, [counter[0] + i], nonce))
        plaintext_block = plaintext[i*64:i*64+64]
        encrypted_block = [plaintext_block[j] ^ key_stream[j] for j in range(64)]
        encrypted_message += bytes(encrypted_block)
    if byte_length % 64 != 0:
        key_stream = serialize(chacha20_block(key, [counter[0] + full_blocks], nonce))
        plaintext_block = plaintext[full_blocks*64:byte_length]
        encrypted_block = [plaintext_block[j] ^ key_stream[j] for j in range(byte_length % 64)]
        encrypted_message += bytes(encrypted_block)

    return encrypted_message

# returns a list of 16 32-bit unsigned integers
def chacha20_block(key, counter, nonce):
    init_state = BLOCK_CONSTANTS + key + counter + nonce
    current_state = init_state[:]
    for i in range(10):
        inner_block(current_state)
    for i in range(16):
        current_state[i] = add_32(current_state[i], init_state[i])

    return current_state

def inner_block(state):
    # columns
    quarterround(state, 0, 4, 8, 12)
    quarterround(state, 1, 5, 9, 13)
    quarterround(state, 2, 6, 10, 14)
    quarterround(state, 3, 7, 11, 15)
    # diagonals
    quarterround(state, 0, 5, 10, 15)
    quarterround(state, 1, 6, 11, 12)
    quarterround(state, 2, 7, 8, 13)
    quarterround(state, 3, 4, 9, 14)

def xor_32(x, y):
    return (x ^ y) & 0xffffffff

def add_32(x, y):
    return (x + y) & 0xffffffff

def rot_l32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

def quarterround(state, i1, i2, i3, i4):
    a = state[i1]
    b = state[i2]
    c = state[i3]
    d = state[i4]

    a = add_32(a, b); d = xor_32(d, a); d = rot_l32(d, 16)
    c = add_32(c, d); b = xor_32(b, c); b = rot_l32(b, 12)
    a = add_32(a, b); d = xor_32(d, a); d = rot_l32(d, 8)
    c = add_32(c, d); b = xor_32(b, c); b = rot_l32(b, 7)

    state[i1] = a
    state[i2] = b
    state[i3] = c
    state[i4] = d

def serialize(block):
    return b''.join([(word).to_bytes(4, 'little') for word in block])

def runtests():
    KEY = "03020100070605040b0a09080f0e0d0c13121110171615141b1a19181f1e1d1c13121110171615141b1a19181f1e1d1c"
    NONCE_1 = "090000004a00000000000000"
    NONCE_2 = "000000004a00000000000000"

    a = 0x11111111
    b = 0x01020304
    c = 0x77777777
    d = 0x01234567

    c = add_32(c, d)
    assert(c == 0x789abcde)

    b = xor_32(b, c)
    assert(b == 0x7998bfda)

    a = 0x11111111
    b = 0x01020304
    c = 0x9b8d6f43
    d = 0x01234567

    state = [a, b, c, d]
    expected_state = [0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb]

    quarterround(state, 0, 1, 2, 3)
    assert(state == expected_state)

    state = [
        0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
        0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
        0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
        0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320
    ]
    expected_state = [
        0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a,
        0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2,
        0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963,
        0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320
    ]

    quarterround(state, 2, 7, 8, 13)
    assert(state == expected_state)

    key_bytes = bytes.fromhex(KEY)
    key = [int.from_bytes(key_bytes[i*4:i*4+4], byteorder='big') for i in range(8)]
    counter = [0x00000001]
    nonce_bytes = bytes.fromhex(NONCE)
    nonce = [int.from_bytes(nonce_bytes[i*4:i*4+4], byteorder='big') for i in range(3)]
    block = chacha20_block(key, counter, nonce)
    expected_block = [
        0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
        0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
        0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
        0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2
    ]
    assert(block == expected_block)

    serialized_block = serialize(block)
    print(serialized_block)
    f = open('/Users/jesse/src/chacha20/output', 'wb')
    f.write(serialized_block)
    f.close()

    print("All tests passed!")

main();
