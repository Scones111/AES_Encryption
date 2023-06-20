import numpy as np
import Transformations
import random

def load_state(plaintext):
    state = np.array_split(plaintext, 4)
    state = np.concatenate(([state[0]], [state[1]], [state[2]], [state[3]]))
    return state


def load_output(state):
    output = np.array_split(state, 4)
    output = np.concatenate((output[0], output[1], output[2], output[3])).tobytes('C')
    return output


def cypher(plaintext, key):
    if len(key)*8 == 128:
        rounds = 10
    elif len(key)*8 == 192:
        rounds = 12
    elif len(key)*8 == 256:
        rounds = 14

    w = Transformations.key_expansion(key, rounds, 4)
    state = load_state(plaintext).T

    #print("round: 0")
    #print(state)

    #print("add_round_key:")
    #print(w[0:4].T)
    state = Transformations.add_round_key(state, w[0:4].T)
    #print("\n")
    for i in range(1, rounds):
        #print("round: " + str(i))
        #print(state)
        state = Transformations.sub_bytes(state)
        #print(state)
        state = Transformations.shift_row(state)
        #print(state)
        state = Transformations.mix_columns(state)
        #print(state)
        #print("add_round_key:")
        #print(w[i * 4:(i + 1) * 4].T)
        state = Transformations.add_round_key(state, w[i * 4:(i + 1) * 4].T)
        #print(state)
        #print("\n")

    #print("round: " + str(i + 1))
    #print(state)
    state = Transformations.sub_bytes(state)
    #print(state)
    state = Transformations.shift_row(state)
    #print(state)
    #print("add_round_key:")
    #print(w[(i + 1) * 4:(i + 2) * 4].T)
    state = Transformations.add_round_key(state, w[(i + 1) * 4:(i + 2) * 4].T)
    #print(state)

    return load_output(state.T)


def inv_cypher(ciphertext, key):
    if len(key)*8 == 128:
        rounds = 10
    elif len(key)*8 == 192:
        rounds = 12
    elif len(key)*8 == 256:
        rounds = 14

    #print("round: " + str(rounds))
    w = Transformations.key_expansion(key, rounds, 4)
    state = load_state(bytearray(ciphertext)).T
    #print(w[rounds * 4:(rounds + 1) * 4].T)
    state = Transformations.add_round_key(state, w[rounds * 4:(rounds + 1) * 4].T)
    #print(state)
    #print("\n")

    for i in range(rounds-1, 0, -1):
        #print("round: " + str(i))
        #print(state)
        state = Transformations.inv_shift_rows(state)
        #print(state)
        state = Transformations.inv_sub_bytes(state)
        #print(state)
        #print("add_round_key:")
        #print(w[i * 4:(i + 1) * 4].T)
        state = Transformations.add_round_key(state, w[i * 4:(i + 1) * 4].T)
        #print(state)
        state = Transformations.inv_mix_columns(state)
        #print(state)
        #print("\n")

    #print("round: " + str(i - 1))
    #print(state)
    state = Transformations.inv_shift_rows(state)
    #print(state)
    state = Transformations.inv_sub_bytes(state)
    #print(state)
    #print("add_round_key:")
    #print(w[(i - 1) * 4: i * 4].T)
    state = Transformations.add_round_key(state, w[0: 4].T)
    #print(state)

    return load_output(state.T)


# Encrypts string to array of bytes using AES
def encrypt(plain_text):
    if type(plain_text) == str:
        plain_text = bytearray(plain_text,'utf-8')
    else:
        plain_text = bytearray(plain_text)
    
    arrayified_message = Transformations.Pad(plain_text)
    cypher_text = bytearray()
    for i in range(int(len(arrayified_message)/16)):
        cypher_text.extend(cypher(arrayified_message[i*16:(i+1)*16], Transformations.read_key()))
    return bytes(cypher_text)


# Decrypts array of bytes to string using AES
def decrypt(cypher_text):
    plain_text = bytearray()
    cypher_text = bytearray(cypher_text)
    for i in range(int(len(cypher_text)/16)):
        plain_text.extend(inv_cypher(cypher_text[i*16:(i+1)*16], Transformations.read_key()))
    plain_text = Transformations.unPad(plain_text)
    return bytes(plain_text)

def CBC_encrypt(plain_text):
    if type(plain_text) == str:
        plain_text = bytearray(plain_text,'utf-8')
    else:
        plain_text = bytearray(plain_text)
    cypher_text = bytearray()
    arrayified_message = Transformations.Pad(plain_text)
    IV = bytearray(Transformations.generate_IV())
    for i in range(int(len(arrayified_message)/16)):
        message_block = arrayified_message[i*16:(i+1)*16]
        message_xored = bytearray([message_block[j] ^ IV[j] for j in range(16)])
        cipher_block = cypher(message_xored, Transformations.read_key())
        IV = bytearray(cipher_block)
        cypher_text.extend(cipher_block)
    
    return bytes(cypher_text)
    
def CBC_decrypt(cypher_text):
    plain_text = bytearray()
    cypher_text = bytearray(cypher_text)
    IV = bytearray(Transformations.read_IV())
    for i in range(int(len(cypher_text)/16)):
        cypher_block = cypher_text[i*16:(i+1)*16]
        message_block = inv_cypher(cypher_block, Transformations.read_key())
        message_xored = bytearray([message_block[j] ^ IV[j] for j in range(16)])
        plain_text.extend(message_xored)
        IV = bytearray(cypher_block)
    plain_text = Transformations.unPad(plain_text)
    return bytes(plain_text)