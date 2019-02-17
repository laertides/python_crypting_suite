#!/usr/bin/python
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from cryptosteganography import CryptoSteganography

flag = ''
def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)
def file_select():
    file = str(input("Enter file name: "))
    if flag == 'e':
        fcrypt(file)
    elif flag == 'd':
        fdcrypt(file)

def main():
    opts = {1: crypt, 2: dcrypt, 3: misc}
    print("1.) Encryption\n")
    print("2.) Decryption \n")
    print("3.) Misc.\n")

    choice = int(input("Make youre choice: "))
    opts[choice]()

def dir_crypt():
    print("crypt dir\n")
"""
def text_crypt():
    print("crypt text\n")

    text = str(input("gimme sum text to encrypt: \n")) 
    message = pad(text.encode('utf-8')) #reading and padding text
    key = str(input("enter a password: \n"))
    key = pad(key.encode("utf-8")) #reading and padding password

    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv) #creation of iv and cipher obj

    out = iv + cipher.encrypt(message) #do the sh!t
    f = open("enc_text.bin",'wb')
    f.write(out)  #because CBC mode ciphers bytes we need to write it into a file (copy paste does not work)
    print("done\nPls check 'output/enc_text.bin' for the file ", )
"""
def text_crypt():
    text = str(input("Enter a text to encrypt: "))
    text = text.encode("utf-8")
    key = str(input("ennter a password: "))
    key = pad(key.encode("utf-8"))
    cipher = AES.new(key, AES.MODE_EAX) #we use AEX to detect modifications
    ciphertext,tag = cipher.encrypt_and_digest(text)
    file_out = open("encrypted.bin", "wb")
    [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]

def fcrypt(path):
    print("a")
    

#==================================================================================================================================================

def crypt():
    flag = 'e'
    opts = {1: fcrypt, 2: dir_crypt, 3: text_crypt}
    print("1.) Ecrypt a file\n")
    print("2.) Ecrypt a folder\n")
    print("3.) Ecrypt text\n")
    choice = int(input("Make youre choice: "))
    opts[choice]()

#==================================================================================================================================================
#==================================================================================================================================================

def dir_dcrypt():
    print("dcrypt dir\n")

"""
def text_dcrypt():
    print("crypt text\n")

    key = str(input("Pls enter ur password: \n"))
    key = pad(key.encode("utf-8")) #read and pad the password
    path = str(input("enter the path of the file containing the encrypted text :\n"))
    
    f = open(path,'rb')
    entext = f.read() #open and read the file 
    iv = entext[:AES.block_size] #grab the iv

    cipher = AES.new(key, AES.MODE_CBC, iv) #create decipher obj
    plaintext = cipher.decrypt(entext[AES.block_size:])

    text = plaintext.rstrip(b"\0")
    text = text.decode("utf-8") #strip and decode text

    print("Done\n")
    print("resaulting text: \n")
    print(text)
"""
def text_dcrypt():
    key = str(input("Enter your password: "))
    key = pad(key.encode("utf-8"))
    file_in = open("encrypted.bin", "rb")
    nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    print(data.decode("utf-8"))

def fdcrypt(path):
    print("crypt file\n")

#==================================================================================================================================================

def dcrypt():
    flag = 'd'
    opts = {1: fdcrypt, 2: dir_dcrypt, 3: text_dcrypt}
    print("1.) Decrypt a file\n")
    print("2.) Decrypt a folder\n")
    print("3.) Decrypt text\n")
    choice = int(input("Make youre choice: "))
    opts[choice]()

def misc():
    print("misc")

if __name__ == "__main__":
    main()

