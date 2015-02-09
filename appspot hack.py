import requests
import urllib
import set1
import padding_attack


r = requests.get('http://crypto-class.appspot.com/po?er=f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4')
if r.status_code == 200:
    print "Success"
elif r.status_code == 404:
    print "Not found"
elif r.status_code == 500:
    print "bad padding"

ciphertext = "f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4"
# ciphertext = set1.hex_to_base64(ciphertext)
print len(ciphertext)


def check(test):
    url = "http://crypto-class.appspot.com/po?er=" + test
    print url
    return requests.get(url).status_code

plaintext = padding_attack.hex_padding_attack(ciphertext, check)
print plaintext