import set1


def pkcs7_padding(s, length):
    l = len(s)
    if l > length:
        l = l % length
    pad_len = length - l

    pad_char = chr(pad_len)
    return s + pad_char * pad_len


def validate_pkcs7_padding(string, length):
    pad = string[-1]
    if pad == chr(0):
        raise Exception("Invalid padding")
    for i in range(ord(pad)):
        if string[-(i+1)] == pad:
            continue
        else:
            raise Exception("Invalid padding")

    return string[:-ord(pad)]


def split_into_blocks_and_pad(string, block_length):
    blocks = []
    for i in range(len(string) / block_length):
        blocks.append(string[0:block_length])
        string = string[block_length:]

    blocks.append(pkcs7_padding(string, block_length))

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

    # don't include end block because don't want a full-pad block at the end. Expect input ciphertext to be correctly
    # padded
    cipherblocks = split_into_blocks_and_pad(ciphertext, block_length)[:-1]

    output = ''
    de = decrypt(cipherblocks[0], key)
    plain = xor(de, iv)
    output += plain
    prev_c = cipherblocks[0]
    for c in cipherblocks[1:]:
        de = decrypt(c, key)
        plain = xor(de, prev_c)
        output += plain
        prev_c = c

    return output


if __name__ == '__main__':
    if pkcs7_padding('YELLOW SUBMARINE', 10) == "YELLOW SUBMARINE":
        print 'Success on set 2, challenge 9'
    else:
        print 'Fails: ', pkcs7_padding('YELLOW SUBMARINE', 10)

    block_size = 16
    iv = chr(0) * block_size

    inp = "Hello World".encode('base64')

    enc = cbc_encrypt(inp, iv, 'YELLOW SUBMARINE', block_size)
    dec = cbc_decrypt(enc, iv, 'YELLOW SUBMARINE', block_size)
    if dec == pkcs7_padding(inp, block_size):
        print 'Inverse is true'
    else:
        print dec, pkcs7_padding(inp, block_size)

    # This is a separation comment for no reason other than reasons
    f = open("set210 CBC encrypted.txt", 'r')
    cbc_encrypted = f.read()
    cbc_encrypted = cbc_encrypted.replace('\n', '').decode('base64')

    res = cbc_decrypt(cbc_encrypted, iv, 'YELLOW SUBMARINE', block_size)
    if res[:33] == "I'm back and I'm ringin' the bell":
        print 'CBC decrypt success'
    else:
        print res

    # PKCS padding validation
    t1 = "ICE ICE BABY" + chr(4) * 4
    t2 = "ICE ICE BABY" + chr(5) * 4
    t3 = "ICE ICE BABY" + chr(1) + chr(2) + chr(3) + chr(4)
    t4 = "ICE ICE BABY"
    if validate_pkcs7_padding(t1, 16) == "ICE ICE BABY":
        print "padding1 success"
        try:
            validate_pkcs7_padding(t2, 16)
        except Exception as e:
            if str(e) == "Invalid padding":
                print "padding2 success"

        try:
            validate_pkcs7_padding(t3, 16)
        except Exception as e:
            if str(e) == "Invalid padding":
                print "padding3 success"

        try:
            validate_pkcs7_padding(t4, 16)
        except Exception as e:
            if str(e) == "Bad padding length":
                print "padding4 success"
    else:
        print "Padding failure"