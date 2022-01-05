import bcrypt
import time


password = b"SecretPasswor55"
print(password)

start = time.time()
hashed= bcrypt.hashpw(password, bcrypt.gensalt(rounds=10))
print(hashed)
end = time.time()

f = end - start
print(f)

if bcrypt.checkpw(password,hashed):
  print("yes")

def hash_password(plaintextPassword):
  hashed = bcrypt.hashpw(plaintextPassword, bcrypt.gensalt)
  return hashed

def encryption_machine(msg):
  pass