import set1


def pkcs7_padding(s, length):
    l = len(s)
    if l > length:
        l = l % length
    pad_len = length - l

    pad_char = chr(pad_len)
    return s + pad_char * pad_len


def split_into_blocks_and_pad(string, block_length):
    blocks = []
    for i in range(len(string) / block_length):
        blocks.append(string[0:block_length])
        string = string[block_length:]
        if len(string) < block_length:
            break

    blocks.append(pkcs7_padding(string, block_length))

    # print blocks
    for b in blocks:
        if len(b) != 16:
            print len(b), b
    return blocks


def cbc_encrypt(string, iv, key, block_length):
    encrypt = set1.encrypt_AES_ECB
    xor = set1.fixed_XOR

    blocks = split_into_blocks_and_pad(string, block_length)

    output = ''
    xored = xor(blocks[0], iv)
    e = encrypt(xored, key)
    output += e
    for b in blocks[1:]:
        xored = xor(b, e)
        e = encrypt(xored, key)
        output += e

    return output


def cbc_decrypt(ciphertext, iv, key, block_length):
    decrypt = set1.decrypt_AES_ECB
    xor = set1.fixed_XOR

    cipherblocks = split_into_blocks_and_pad(ciphertext, block_length)[:-1]

    output = ''
    d = decrypt(cipherblocks[0], key)
    xored = xor(d, iv)
    output += xored
    for b in cipherblocks[1:]:
        d = decrypt(b, key)
        xored = xor(d, iv)
        output += xored

    return output


if __name__ == '__main__':
    if pkcs7_padding('YELLOW SUBMARINE', 10) == "YELLOW SUBMARINE ":
        print 'Success on set 2, challenge 9'
    else:
        print 'Fails: ', pkcs7_padding('YELLOW SUBMARINE', 10)

    block_size = 16
    iv = chr(0) * block_size

    inp = "Hello World"
    enc = cbc_encrypt(inp, iv, 'YELLOW SUBMARINE', block_size)
    dec = cbc_decrypt(enc, iv, 'YELLOW SUBMARINE', block_size)
    if dec == pkcs7_padding(inp, block_size):
        print 'Inverse is true'
    else:
        print dec, pkcs7_padding(inp, block_size)

    # This is a separation comment for no reason other than reasons
    f = open("set210 CBC encrypted.txt", 'r')
    cbc_encrypted = f.read()
    cbc_encrypted = cbc_encrypted.replace('\n', '')

    print cbc_decrypt(cbc_encrypted, iv, 'YELLOW SUBMARINE', block_size).encode('base64')