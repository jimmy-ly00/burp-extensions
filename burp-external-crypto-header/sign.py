import sys
import base64

from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

def encrypt_text(StringToSign):
    key = RSA.importKey(open('./private-key.pem').read())
    h = SHA256.new(StringToSign.encode("utf-8"))
    signature = pkcs1_15.new(key).sign(h)
    return base64.b64encode(signature).decode("utf-8")

def main():
    result = encrypt_text(sys.argv[1])
    print(result)

if __name__ == "__main__":
    main()