def main():
    runtests()

def chacha20_decrypt(key, counter, nonce, ciphertext):
    return chacha20_encrypt(key, counter, nonce, ciphertext)

def chacha20_encrypt(key, counter, nonce, plaintext):
    byte_length = len(plaintext)
    full_blocks = byte_length//64
    remainder_bytes = byte_length % 64
    encrypted_message = b''

    for i in range(full_blocks):
        key_stream = serialize(chacha20_block(key, counter + i, nonce))
        plaintext_block = plaintext[i*64:i*64+64]
        encrypted_block = [plaintext_block[j] ^ key_stream[j] for j in range(64)]
        encrypted_message += bytes(encrypted_block)
    if remainder_bytes != 0:
        key_stream = serialize(chacha20_block(key, counter + full_blocks, nonce))
        plaintext_block = plaintext[full_blocks*64:byte_length]
        encrypted_block = [plaintext_block[j] ^ key_stream[j] for j in range(remainder_bytes)]
        encrypted_message += bytes(encrypted_block)

    return encrypted_message

# returns a list of 16 32-bit unsigned integers
def chacha20_block(key, counter, nonce):
    BLOCK_CONSTANTS = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    init_state = BLOCK_CONSTANTS + key + [counter] + nonce
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

# Test Vectors from RFC 8439
def runtests():
    # section 2.1
    a = 0x11111111
    b = 0x01020304
    c = 0x77777777
    d = 0x01234567

    c = add_32(c, d)
    assert(c == 0x789abcde)

    b = xor_32(b, c)
    assert(b == 0x7998bfda)

    # section 2.1.1
    state = [0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567]
    expected_state = [0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb]

    quarterround(state, 0, 1, 2, 3)
    assert(state == expected_state)

    # section 2.2.1
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

    # section 2.3.2
    KEY = "03020100070605040b0a09080f0e0d0c13121110171615141b1a19181f1e1d1c13121110171615141b1a19181f1e1d1c"
    NONCE_1 = "090000004a00000000000000"
    key_bytes = bytes.fromhex(KEY)
    # split 256-bit key into list of 8 unsigned 32-bit integers
    key = [int.from_bytes(key_bytes[i*4:i*4+4], byteorder='big') for i in range(8)]
    init_counter = 0x00000001
    nonce_bytes = bytes.fromhex(NONCE_1)
    # split 96-bit nonce into list of 3 unsigned 32-bit integers
    nonce = [int.from_bytes(nonce_bytes[i*4:i*4+4], byteorder='big') for i in range(3)]
    block = chacha20_block(key, init_counter, nonce)
    expected_block = [
        0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
        0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
        0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
        0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2
    ]
    assert(block == expected_block)

    serialized_block = serialize(block)
    expected_bytes = [
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0xf, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x3, 0x4, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
        0xd2, 0x82, 0x64, 0x46, 0x7, 0x9f, 0xaa, 0x9, 0x14, 0xc2, 0xd7, 0x5, 0xd9, 0x8b, 0x2, 0xa2,
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e
    ]
    assert(serialized_block == bytes(expected_bytes))

    # section 2.4.2
    NONCE_2 = "000000004a00000000000000"
    nonce_bytes = bytes.fromhex(NONCE_2)
    nonce = [int.from_bytes(nonce_bytes[i*4:i*4+4], byteorder='big') for i in range(3)]
    plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

    first_block = chacha20_block(key, init_counter, nonce)
    expected_first_block = [
        0xf3514f22, 0xe1d91b40, 0x6f27de2f, 0xed1d63b8,
        0x821f138c, 0xe2062c3d, 0xecca4f7e, 0x78cff39e,
        0xa30a3b8a, 0x920a6072, 0xcd7479b5, 0x34932bed,
        0x40ba4c79, 0xcd343ec6, 0x4c2c21ea, 0xb7417df0
    ]
    assert(first_block == expected_first_block)
    second_block = chacha20_block(key, init_counter + 1, nonce)
    expected_second_block = [
        0x9f74a669, 0x410f633f, 0x28feca22, 0x7ec44dec,
        0x6d34d426, 0x738cb970, 0x3ac5e9f3, 0x45590cc4,
        0xda6e8b39, 0x892c831a, 0xcdea67c1, 0x2b7e1d90,
        0x037463f3, 0xa11a2073, 0xe8bcfb88, 0xedc49139
    ]
    assert(second_block == expected_second_block)

    expected_key_stream = [
        0x22, 0x4f, 0x51, 0xf3, 0x40, 0x1b, 0xd9, 0xe1, 0x2f, 0xde, 0x27, 0x6f, 0xb8, 0x63, 0x1d, 0xed, 0x8c, 0x13, 0x1f, 0x82, 0x3d, 0x2c, 0x06,
        0xe2, 0x7e, 0x4f, 0xca, 0xec, 0x9e, 0xf3, 0xcf, 0x78, 0x8a, 0x3b, 0x0a, 0xa3, 0x72, 0x60, 0x0a, 0x92, 0xb5, 0x79, 0x74, 0xcd, 0xed, 0x2b,
        0x93, 0x34, 0x79, 0x4c, 0xba, 0x40, 0xc6, 0x3e, 0x34, 0xcd, 0xea, 0x21, 0x2c, 0x4c, 0xf0, 0x7d, 0x41, 0xb7, 0x69, 0xa6, 0x74, 0x9f, 0x3f,
        0x63, 0x0f, 0x41, 0x22, 0xca, 0xfe, 0x28, 0xec, 0x4d, 0xc4, 0x7e, 0x26, 0xd4, 0x34, 0x6d, 0x70, 0xb9, 0x8c, 0x73, 0xf3, 0xe9, 0xc5, 0x3a,
        0xc4, 0x0c, 0x59, 0x45, 0x39, 0x8b, 0x6e, 0xda, 0x1a, 0x83, 0x2c, 0x89, 0xc1, 0x67, 0xea, 0xcd, 0x90, 0x1d, 0x7e, 0x2b, 0xf3, 0x63
    ]
    assert((serialize(first_block) + serialize(second_block))[:len(plaintext)] == bytes(expected_key_stream))

    ciphertext = chacha20_encrypt(key, init_counter, nonce, plaintext)
    expected_ciphertext = [
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
        0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
        0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
        0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
        0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
        0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
        0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
        0x87, 0x4d
    ]
    assert(ciphertext == bytes(expected_ciphertext))
    assert(chacha20_decrypt(key, init_counter, nonce, ciphertext) == plaintext)

    print("All tests passed!")

main();
