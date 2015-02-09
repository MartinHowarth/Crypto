from Crypto.Util import strxor
from Crypto.Cipher import AES


def hex_to_base64(string):
    return string.decode('hex').encode('base64').rstrip()


def base64_to_hex(string):
    return string.decode('base64').encode('hex').rstrip()


def fixed_XOR(s1, s2):
    return strxor.strxor(s1, s2)


def decrypt_AES_ECB(encryptedd, key):
    cipher = AES.AESCipher(key)
    return cipher.decrypt(encryptedd)


def encrypt_AES_ECB(decryptedd, key):
    cipher = AES.AESCipher(key)
    return cipher.encrypt(decryptedd)


if __name__ == '__main__':
    hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    string_64 = hex_to_base64(hex_string)
    if string_64 == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t":
        print 'Success on set 1, challenge 1.'
    else:
        print string_64

    if base64_to_hex(string_64) == hex_string:
        print "Success 64 to hex"

    x1 = "1c0111001f010100061a024b53535009181c"
    x2 = "686974207468652062756c6c277320657965"
    x_result = fixed_XOR(x1.decode('hex'), x2.decode('hex')).encode('hex')
    if x_result == "746865206b696420646f6e277420706c6179":
        print 'Success on set 2, challenge 2.'
    else:
        print x_result

    f = open("set1-7 encrypted.txt", 'r')
    encrypted = f.read()
    encrypted = encrypted.replace('\n', '')
    decrypted = decrypt_AES_ECB(encrypted.decode('base64'), 'YELLOW SUBMARINE')
    print 'Success on set 1, challenge 7.'

    reencrypt = encrypt_AES_ECB(decrypted, 'YELLOW SUBMARINE').encode('base64')
    reencrypt = reencrypt.replace('\n', '')
    if reencrypt == encrypted:
        print 'Success'
    else:
        print reencrypt