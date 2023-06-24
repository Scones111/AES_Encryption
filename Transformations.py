import numpy as np
import math

s_box = np.array([
    [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
    [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
    [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
    [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
    [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
    [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
    [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
    [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
    [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
    [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
    [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
    [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
    [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
    [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
    [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
    [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
], dtype=np.uint8)

inv_s_box = np.array([
    [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
    [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
    [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
    [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
    [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
    [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
    [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
    [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
    [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
    [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
    [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
    [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
    [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
    [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
    [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
    [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]
], dtype=np.uint8)


# Polynomial multiplication
def g_mul(a, b):
    bin_poly = 0b100011011  # Irreducible polynomial in binary
    product = 0  # Product of multiplication
    for i in range(8):
        product = product << 1
        if product & 0b100000000:
            product = product ^ bin_poly
        if b & 0b010000000:
            product = product ^ a
        b = b << 1
    return product


########################################################################################################################
# ENCRYPTION

# Padding function
def Pad(message):
    last_block_len = len(message)%16
    i = len(message)-last_block_len
    temp = message[i:]
    pad_no = 16-len(temp)
    if pad_no != 16:
        padding = bytearray([pad_no for i in range(pad_no)])
        message.extend(padding)
    return message

# DePadding function
def unPad(message):
    pad_no = int(message[-1])
    if pad_no < 16 and int(message[-pad_no]) == pad_no:
        return message[0:len(message)-pad_no]
    else:
        return message

def generate_IV():
    IV = np.random.randint(0, high=255, size=16, dtype=np.uint8)
    np.savetxt("IV.txt", IV, fmt='%u')  # Saves randomly generated key to the file 'Key.txt'
    return IV

def read_IV():
    IV = np.loadtxt("IV.txt", dtype=np.uint8)
    return IV

# Substitute state using s_box
def sub_bytes(state):
    for col in range(4):
        for row in range(4):
            sub_row = int(hex(state[row][col])[2:].zfill(2)[0], 16)
            sub_col = int(hex(state[row][col])[2:].zfill(2)[1], 16)
            state[row][col] = s_box[sub_row][sub_col]
    return state


# Add round key to state using simple bitwise XOR operation
def add_round_key(state, key_schedule):
    return state ^ key_schedule


# Cyclically shift each state row from 0 to 3 offsets (to the left)
def shift_row(state):
    for row in range(4):
        state[row] = np.roll(state[row], -row)
    return state


# works for now, with a function found online, seems to be more hardcoded, need to find a more flexible method
def mix_columns(state):
    # create 2d array with zeros, to store values in
    b = np.zeros(state.shape, dtype=np.uint8)
    # initialize the polynomial used for the matrix multiplication
    a = np.array([[2, 3, 1, 1],
                  [1, 2, 3, 1],
                  [1, 1, 2, 3],
                  [3, 1, 1, 2]], dtype=np.uint8)
    for i in range(4):
        for j in range(4):
            for k in range(4):
                # g_mul, does bitwise operations, as we cannot have values with more than 8 bits.
                b[i, j] = b[i, j] ^ g_mul(state[k, j], a[i, k])
    state = b
    return state


########################################################################################################################
# DECRYPTION

# Cyclically shift each state row from 0 to 3 offsets (to the right)
def inv_shift_rows(state):
    for row in range(4):
        state[row] = np.roll(state[row], row)
    return state


# Substitute state using inv_s_box
def inv_sub_bytes(state):
    for col in range(4):
        for row in range(4):
            sub_row = int(hex(state[row][col])[2:].zfill(2)[0], 16)
            sub_col = int(hex(state[row][col])[2:].zfill(2)[1], 16)
            state[row][col] = inv_s_box[sub_row][sub_col]
    return state


def inv_mix_columns(state):
    # create 2d array with zeros, to store values in
    b = np.zeros(state.shape, dtype=np.uint8)
    # initialize the polynomial used for the matrix multiplication
    a = np.array([[0x0E, 0x0B, 0x0D, 0x09],
                  [0x09, 0x0E, 0x0B, 0x0D],
                  [0x0D, 0x09, 0x0E, 0x0B],
                  [0x0B, 0x0D, 0x09, 0x0E]], dtype=np.uint8)
    for i in range(4):
        for j in range(4):
            for k in range(4):
                # g_mul, does bitwise operations, as we cannot have values with more than 8 bits.
                b[i, j] = b[i, j] ^ g_mul(state[k, j], a[i, k])
    state = b
    return state


def sub_word(word):
    for i in range(4):
        sub_row = int(hex(word[i])[2:].zfill(2)[0], 16)
        sub_col = int(hex(word[i])[2:].zfill(2)[1], 16)
        word[i] = s_box[sub_row][sub_col]
    return word


########################################################################################################################
# KEYS

# class Key:
#
#     def __init__(self, key_length):
#         self.key = np.random.randint(0, high=255, size=int(key_length / 8), dtype=np.uint8)
#
#     def get_key(self):
#         return self.key


def generate_key(key_length):
    key = np.random.randint(0, high=255, size=int(key_length / 8), dtype=np.uint8)
    np.savetxt("Key.txt", key, fmt='%u')  # Saves randomly generated key to the file 'Key.txt'
    return key

def set_key(key):
    np.savetxt("Key.txt", key, fmt='%u')  #Saves the key to the file 'Key.txt'
    return key

def read_key():
    key = np.loadtxt("Key.txt", dtype=np.uint8)
    return key


def key_expansion(key, rounds, block_size):
    nk = int(len(key) * 8 / 32)  # Number of 32-bit words comprising the cypher key
    rconCount = int((rounds + 1) * block_size / nk)
    rcon = np.zeros((rconCount, 4), dtype=np.uint8)
    for i in range(rconCount):
        if i == 0:
            rcon[i] = np.array([1, 0, 0, 0], dtype=np.uint8)
        else:
            rcon[i] = np.array([int(g_mul(rcon[i - 1, 0], 2)), 0, 0, 0], dtype=np.uint8)
    word = np.empty([block_size * (rounds + 1), block_size], dtype=np.uint8)
    for i in range(nk):
        word[i] = np.array([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]])

    for i in range(nk, block_size * (rounds + 1)):
        temp = np.copy(word[i - 1])
        if i % nk == 0:
            temp = np.bitwise_xor(sub_word(np.roll(temp, -1)), rcon[int(i / nk) - 1])
        elif nk > 6 and i % nk == 4:
            temp = sub_word(temp)
        word[i] = np.bitwise_xor(word[i - nk], temp)
    return word
