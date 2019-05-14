#!/usr/bin/python
import os
import time
import getpass
import tkinter as tk
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from tkinter.filedialog import askopenfilename

root = tk.Tk()
root.withdraw()

def exit1():
    exit()

def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

def gen_rsa():
    #password = str(input("Enter a password to encrypt the key pair: "))
    password = getpass.getpass(prompt="Enter password to encrypt key pair: ")
    while password == '':
        print("Enter a password")
        password = getpass.getpass(prompt="Enter password to encrypt key pair: ")
    
    key = RSA.generate(4096)
    enc_rsa = key.export_key(passphrase=password, pkcs=8, protection="scryptAndAES128-CBC")
    #get pass and generate keys
    f_out = open("privkey.pem", "wb")
    f_out.write(enc_rsa)
    f_out.close()
    print("\n",enc_rsa.decode("utf-8"),"\n")
    f_out = open("pubkey.pem", "wb")
    f_out.write(key.publickey().export_key())
    f_out.close()
    print("\n",key.publickey().export_key().decode("utf-8"),"\n")
    #write the keys to files
    print("EXPORTED KEYS SUCCESSFULLY\n")

def encrypt_rsa():
    print("TRYING ENCRYPTION")
    print("import your public key")
    time.sleep(1)
    pub_key = RSA.import_key(open(askopenfilename()).read())
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(pub_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    print("Chose file to encrypt")
    time.sleep(1)
    name = askopenfilename()
    file = open(name,"rb")
    data = file.read()

    f_out = open(name + ".lck", "wb")
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    [f_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
    file.close()
    os.remove(name)

    print("DONE")

def dcrypt_rsa():
    print("TRYING DECRYPTION\n")
    password = str(input("Enter the password to decrypt the RSA key: "))
    print("choose priv key")
    time.sleep(1)
    priv_key = RSA.import_key(open(askopenfilename()).read(), passphrase=password)
    print("choose crypted file")
    time.sleep(1)
    name = askopenfilename()
    file_in = open(name,'rb')
    enc_session_key, nonce, tag, ciphertext = \
    [ file_in.read(x) for x in (priv_key.size_in_bytes(), 16, 16, -1) ]


    cipher_rsa = PKCS1_OAEP.new(priv_key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    file_in.close()
    name2 = name.replace(".lck", "")
    fout = open(name2, "wb")
    fout.write(data)
    os.remove(name)


def rsa():
    opts = {1: gen_rsa, 2: encrypt_rsa, 3: dcrypt_rsa}
    print("1.) Generate RSA key pair \n")
    print("2.) Encrypt a file with RSA \n")
    print("3.) Dcrypt a file with RSA encryption \n")
    choice = int(input("Make youre choice: "))
    opts[choice]()

def file_crypt():
    print("Choose a file to encrypt!\n")
    time.sleep(2)
    file = askopenfilename()
    fcrypt(file)

def file_dcrypt():
    print("Choose a file to decrypt!\n")
    time.sleep(2)
    file = askopenfilename()
    fdcrypt(file)
    
def main():
    opts = {1: crypt, 2: dcrypt, 3: misc, 4:rsa, 5:exit1}
    print("1.) Encryption\n")
    print("2.) Decryption \n")
    print("3.) Misc.\n")
    print("4.) RSA tools")
    print("5.) Exit\n")

    choice = int(input("Make youre choice: "))
    opts[choice]()

def text_dcrypt_opts():
    opts = {1: text_crypt_eax, 2: text_crypt_cbc}
    print("1.) EAX\n2.) CBC")
    choice = int(input("Select Mode: "))
    opts[choice]()

def text_crypt_opts():
    opts = {1: text_crypt_eax, 2: text_crypt_cbc}
    print("1.) EAX\n2.)CBC")
    choice = int(input("Select Mode: "))
    opts[choice]()

def dir_crypt():
    dirr = str(input("Enter a directory you want to encrypt: "))
    for path, subdirs, files in os.walk(dirr):
        for name in files:
            fcrypt(os.path.join(path, name))

def text_crypt_cbc():
    print("ENCRYPTING TEXT USING CBC MODE\n")
    text = str(input("gimme sum text to encrypt: \n")) 
    message = pad(text.encode('utf-8')) #reading and padding text
    key = str(input("enter a password: \n"))
    key = pad(key.encode("utf-8")) #reading and padding password

    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv) #creation of iv and cipher obj

    out = iv + cipher.encrypt(message) #do the sh!t
    f = open("crypted_text",'wb')
    f.write(out)  #copy paste does not work needs to be written to a file
    print("done\nPls check 'crypted_text.lck' for the file ")

def text_crypt_eax():
    print("ENCRYPTING TEXT USING EAX MODE\n")
    text = str(input("Enter a text to encrypt: "))
    text = text.encode("utf-8")
    key = str(input("ennter a password: "))
    key = pad(key.encode("utf-8"))
    cipher = AES.new(key, AES.MODE_EAX) #we use EAX to detect modifications
    ciphertext,tag = cipher.encrypt_and_digest(text)
    file_out = open("crypted_text.lck", "wb")
    [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]

def fcrypt(path):
    ext = ".lck"
    key = str(input("Enter a password: "))
    key = pad(key.encode("utf-8"))
    #file = str(input("Enter file name to open: "))
    f = open(path, "rb")
    data = f.read()
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    f_name = path + ext
    file_out = open(f_name, "wb")
    [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
    file_out.close()
    f.close()
    os.remove(path)
    
#==================================================================================================================================================

def crypt():
    opts = {1: file_crypt, 2: dir_crypt, 3: text_crypt_opts}
    print("1.) Ecrypt a file\n")
    print("2.) Ecrypt a folder\n")
    print("3.) Ecrypt text\n")
    choice = int(input("Make youre choice: "))
    opts[choice]()

#==================================================================================================================================================
#==================================================================================================================================================

def dir_dcrypt():
    dirr = str(input("Enter a directory you want to decrypt: "))
    for path, subdirs, files in os.walk(dirr):
        for name in files:
            fcrypt(os.path.join(path, name))

def text_dcrypt_cbc():
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

def text_dcrypt_aes():
    print("DECRYPTING TEXT USING EAX MODE\n")
    key = str(input("Enter your password: "))
    key = pad(key.encode("utf-8"))
    file = str(input("Enter name of the file containing encrypted TEXT: "))
    file_in = open(file, "rb")
    nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    print(data.decode("utf-8"))

def fdcrypt(path):
    #file = str(input("Enter file Name: "))
    key = str(input("Enter your password: "))
    key = pad(key.encode("utf-8"))
    file_in = open(path, "rb")
    nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    f_name = path.replace(".lck","")
    fout = open(f_name, "wb")
    fout.write(data)
    fout.close()
    #os.remove(file_in)
#==================================================================================================================================================

def dcrypt():
    opts = {1: file_dcrypt, 2: dir_dcrypt, 3: text_dcrypt_opts}
    print("1.) Decrypt a file\n")
    print("2.) Decrypt a folder\n")
    print("3.) Decrypt text\n")
    choice = int(input("Make youre choice: "))
    opts[choice]()

def misc():
    print("misc")

if __name__ == "__main__":
    main()
