import hashlib, hmac, binascii
f=open("hi.txt","r")
contents=f.read()
print(contents)

mac = hmac.new(b'key_ma', contents, hashlib.sha256).digest()
#print(mac)
print(binascii.hexlify(mac))

#mac2 = hmac.new(b'key_mac', b'hello, how are you doing today?', hashlib.sha256).digest()
#print(binascii.hexlify(mac2))