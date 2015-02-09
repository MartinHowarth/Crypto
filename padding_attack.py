import set1
import set2


def create_check_request(_key, _length):
    def check_request(_ciphertext):
        _iv = _ciphertext[:_length]
        _ciphertext = _ciphertext[_length:]
        dec = set2.cbc_decrypt(_ciphertext, _iv, _key, _length)
        try:
            _res = set2.validate_pkcs7_padding(dec[-_length:], _length)
            if debug: print _res
            _res = dec[:-_length] + _res
            if debug: print "HIDDEN:", _res, '#####', dec
            if _res == message:
                return 200
        except Exception as e:
            if debug: print "HIDDEN", dec
            if str(e) == "Invalid padding":
                return 500
        return 404
    return check_request


def change_bytes(string, guess):
    index = len(guess)
    c = chr(index)
    xor = set1.fixed_XOR

    new_string = string
    for i in range(1, index+1):
        new_char = xor(xor(string[-i], guess[-i]), c)
        temp_string = new_string[:-i] + new_char

        if i != 1:  # if i == 1 then do not append new_string[-0:]
            temp_string += new_string[-i + 1:]

        new_string = temp_string
    return new_string


def padding_attack(ciphertext, check_function):
    c_blocks = set2.split_into_blocks_and_pad(ciphertext, 16)[:-1]
    iv = c_blocks[0]
    c_blocks = c_blocks[1:]
    _plaintext = ''
    _completed_cipher = ''
    for b_i in range(len(c_blocks)):
        _guess = ''
        if b_i == 0:
            c1 = iv
        else:
            c1 = c_blocks[b_i - 1]
        c2 = c_blocks[b_i]
        for _j in range(16):
            found_answer = False
            for _i in range(0, 256):
                temp_guess = chr(_i) + _guess
                new_c1 = change_bytes(c1, temp_guess)

                to_send = _completed_cipher + new_c1 + c2

                try:
                    result = check_function(to_send)
                except Exception as e:
                    result = 500
                    continue

                if result == 404 or result == 200:
                    _guess = temp_guess
                    print chr(_i),
                    found_answer = True
                    break
                elif result != 500:
                    print result
                    if result != 403:
                        raw_input("Waiting:")
                elif result == 500:
                    print _i, result
                    raw_input("waiting on 500:")

            if not found_answer:
                print "Expand search", _i

        print b_i, 'current:', _guess
        _plaintext += _guess
        _completed_cipher += c1
    return _plaintext


def hex_padding_attack(ciphertext, check_function):
    cipher = set1.hex_to_base64(ciphertext)

    def check(string):
        print string
        stri = set1.base64_to_hex(string)
        return check_function(stri)

    ret = padding_attack(cipher, check)
    return ret

if __name__ == "__main__":
    debug = 0

    if chr(1) == change_bytes(chr(0), chr(0)):
        print "success1"
    else:
        print ord(change_bytes(chr(0), chr(0)))
    if chr(0) == change_bytes(chr(1), chr(0)):
        print "success2"
    else:
        print ord(change_bytes(chr(1), chr(0)))

    res = change_bytes(chr(2) * 5, chr(3))
    if res[-1] == chr(0):
        print "success partial"
    else:
        for c in res: print ord(c),
        print

    res = change_bytes(chr(2) + chr(0) + chr(4), chr(1) + chr(0) + chr(2))
    if chr(0) + chr(3) + chr(5) == res:
        print "success triple"
    else:
        print ord(res[0]), ord(res[1])

    # end check change_bytes function
    iv = chr(0) * 16
    key = "YELLOW SUBMARINE"
    message = "Super Secret Message made longer because testing alll the things"
    # print set2.split_into_blocks_and_pad(message, 16)

    encrypted = set2.cbc_encrypt(message, iv, key, 16)

    # print encrypted.encode('base64')

    check = create_check_request(key, 16)
    # Start hack

    c_blocks = set2.split_into_blocks_and_pad(encrypted, 16)[:-1]
    # print c_blocks

    if check(iv + encrypted) == 200 and check(iv + chr(0) + encrypted[1:]) == 404 and check(iv + encrypted[:-1] + chr(0)) == 500:
        print "single check works"
    else:
        print "FAIL on single check"

    print
    print "##########################################################"
    print

    print padding_attack(iv + encrypted, check)

    print
    print "##########################################################"
    print

    # hexy = iv + encrypted
    # hexy = hexy.encode('base64').encode('hex')
    # print hexy
    # print hex_padding_attack(hexy, check)


    # plaintext = ''
    # completed_cipher = ''
    # for b_i in range(len(c_blocks)):
    #     guess = ''
    #     if b_i == 0:
    #         c1 = iv
    #     else:
    #         c1 = c_blocks[b_i - 1]
    #     c2 = c_blocks[b_i]
    #     for j in range(16):
    #         for i in range(32, 127):
    #             temp_guess = chr(i) + guess
    #             new_c1 = change_bytes(c1, temp_guess)
    #
    #             to_send = completed_cipher + new_c1 + c2
    #             if debug: print chr(i),
    #             result = check(to_send)
    #             if result == 404 or result == 200:
    #                 guess = temp_guess
    #                 break
    #             elif result != 500:
    #                 print result
    #
    #     print b_i, 'current:', guess
    #     plaintext += guess
    #     completed_cipher += c1
    #
    # print plaintext