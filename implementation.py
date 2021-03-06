
import time
import bcrypt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad,unpad


def hash_password(plaintextPassword):
  hash = bcrypt.hashpw(plaintextPassword, bcrypt.gensalt(rounds=15))
  return hash

def generateKey(msgKey):
    salt = get_random_bytes(32)
    key = PBKDF2(msgKey, salt, dkLen=32)
    return key

def encryption_machine(msg,key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(msg, AES.block_size))
    return cipher,ciphertext



def save_to_database(user, pwd , cipher ):
    with open('encrypted.bin', 'wb') as f:
        f.write(cipher.iv)
        f.write(b"\n" + pwd)
        f.write(b"\n" + user)

def check_password(user, pwd,key):
    lines=[]
    with open('encrypted.bin', 'rb') as f:
        lines = f.readlines()
    print(lines)
    iv = lines[0].rstrip(b"\n")
    decrypt_data = lines[1].rstrip(b"\n")
    userdb = lines[2].rstrip(b"\n")
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    original = unpad(cipher.decrypt(decrypt_data), AES.block_size)
    return pwd == original,user == userdb




user = input("enter your username").encode()
pwd = input("enter your password please").encode()

key = generateKey("hehehe")
#key =b'qx\xf3\xf8]\x9c \xabd\xd9\r\xe0\xea\xd8\xf4\xb0\x93/\xaa\x88\xac`y\x8b\xc2A\xfbs\x08p\xf7\x0e'
cipher,ciphertext = encryption_machine(pwd,key)
save_to_database(user, ciphertext, cipher, )
if check_password( b"user" , b"thisIsMyPassword",key) :
    print("good authentication")
else:
    print("ERROR , false username or password")
