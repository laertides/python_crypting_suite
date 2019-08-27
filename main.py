#!/usr/bin/python
import os
import sys
import time
import argparse
import getpass
import base64
from rsa import rsa
from aes import aes

def key_gen():
    password = getpass.getpass("[->] Enter a password: ")
    password1 = getpass.getpass("[->] Retype your password: ")
    while (password != password1):
        print("[x] Wrong password, Try Again!")
        password = getpass.getpass("[->] Enter a password: ")
        password1 = getpass.getpass("[->] Retype your password: ")

    rsa.gen_rsa(password)
    main()

def dir_RSA_crypt():
    dirr = input("[->] Enter Directory to Encrypt (BE CAREFUL!): ")
    while (os.path.isdir(dirr) == False):
        print("[x] No such Directory Exists!")
        dirr = input("[->] Enter Directory to Encrypt (BE CAREFUL!) ")

    pubkey = input("[->] Enter path to public key: ")
    while (os.path.exists(pubkey) == False) :
        print("[x] Could not find File Specified")
        pubkey = input("[->] Enter path to public key: ") 
    rsa.dir_crypt(pubkey, dirr)
    
    main()

def dir_RSA_dcrypt():
    password = getpass.getpass("[->] Enter Decryption Password: ")

    privkey = input("[->] Enter path to private key: ")
    while (os.path.exists(privkey) == False) :
        print("[x] Could not find File Specified")
        pubkey = input("[->] Enter path to private key: ") 

    dirr = input("[->] Enter Path Conaining Encrypted Data: ")
    while (os.path.isdir(dirr) == False):
        print("[x] Could not find File Specified")
        path = input("[->] Enter Path Conaining Encrypted Data: ")
    
    rsa.dir_dcrypt(password, privkey, dirr)
    main()
            
def rsa_data_crypt():
    pubkey = input("[->] Enter path to public key: ")
    while (os.path.exists(pubkey) == False) :
        print("[x] Could not find File Specified")
        pubkey = input("[->] Enter path to public key: ") 

    path = input("[->] Enter File to be Encrypted ")
    while (os.path.exists(path) == False):
        print("[x] Could not find File Specified")
        path = input("[->] Enter File to be Encrypted ")
    
    rsa.rsa_encrypt(pubkey, path)
    main()

def rsa_data_dcrypt():
    password = getpass.getpass("[->] Enter Decryption Password: ")

    privkey = input("[->] Enter path to private key: ")
    while (os.path.exists(privkey) == False) :
        print("[x] Could not find File Specified")
        pubkey = input("[->] Enter path to private key: ") 

    path = input("[->] Enter File Conaining Encrypted Data: ")
    while (os.path.exists(path) == False):
        print("[x] Could not find File Specified")
        path = input("[->] Enter File Conaining Encrypted Data: ")
    
    rsa.rsa_dcrypt(password, privkey, path)
    main()
    

def rsa_text_crypt():
    data = str(input("[->] Enter text to be encrypt: "))
    
    pubkey = input("[->] Enter path to public key: ")
    while (os.path.exists(pubkey) == False) :
        print("[x] Could not find File Specified")
        pubkey = input("[->] Enter path to public key: ") 
    
    rsa.rsa_text_encrypt(pubkey, data)
    main()
    
        
def rsa_text_dcrypt():
    password = getpass.getpass("[->] Enter Decryption Password: ")

    path = input("[->] Enter File Conaining Encrypted text: ")
    while (os.path.exists(path) == False):
        print("[x] Could not find File Specified")
        path = input("[->] Enter File Conaining Encrypted text: ")

    privkey = input("[->] Enter path to private key: ")
    while (os.path.exists(privkey) == False) :
        print("[x] Could not find File Specified")
        pubkey = input("[->] Enter path to private key: ")
    
    rsa.rsa_text_dcrypt(password, privkey, path)
    main()


def RSA():
    opts = {1: key_gen, 2: rsa_data_crypt, 3: dir_RSA_crypt, 4: rsa_text_crypt, 5: rsa_data_dcrypt, 6:dir_RSA_dcrypt, 7: rsa_text_dcrypt, 8: main}
    print("-------RSA TOOLS-------")
    print("1.) Generate 4096-bit RSA Key Pair")
    print("2.) Encrypt File Using RSA")
    print("3.) Encrypt Directory Using RSA")
    print("4.) Encrypt Text Using RSA")
    print("5.) Decrypt File Using RSA")
    print("6.) Decrypt Directory Using RSA")
    print("7.) Decrypt Text Using RSA")
    print("8.) Main Menu")

    x = int(input("[->] Make a selection: "))
    while(x > 6):
        x = int(input("[->] Make a selection: "))
    
    opts[x]()

def aes_data_crypt():
    path = input("[->] Enter Filename: ")
    while (os.path.exists(path) == False):
        print("[x] Could not find File Specified")
        path = input("[->] Enter Filename: ")

    password = getpass.getpass("[->] Enter Encryption Password: ")
    aes.aes_crypt_eax(password, path)
    main()

def aes_dir_crypt():
    password = getpass.getpass("[->] Enter Encryption Password: ")
    dirr = input("[->] Enter Directory to Encrypt (BE CAREFUL!): ")
    while (os.path.isdir(dirr) == False):
        print("[x] No such Directory Exists!")
        dirr = input("[->] Enter Directory to Encrypt (BE CAREFUL!) ")

    aes.dir_encrypt(password, dirr)
    main()

def aes_dir_dcrypt():
    password = getpass.getpass("[->] Enter Decryption Password: ")
    dirr = input("[->] Enter Directory to Decrypt (BE CAREFUL!): ")
    while (os.path.isdir(dirr) == False):
        print("[x] No such Directory Exists!")
        dirr = input("[->] Enter Directory to Decrypt (BE CAREFUL!) ")

    aes.dir_dcrypt(password, dirr)
    main()


def aes_data_dcrypt():
    path = input("[->] Enter File to be Decrypted: ")
    while (os.path.exists(path) == False):
        print("[x] Could not find File Specified")
        path = input("[->] Enter File to be Decrypted: ")
    password = getpass.getpass("[->] Enter Decryption Password: ")
    aes.aes_dcrypt_eax(password, path)
    main()

def aes_text_crypt():
    raw = str(input("[->] Enter text to be Encrypted "))
    password = getpass.getpass("[->] Enter Encryption Password: ")
    aes.aes_crypt_cbc(password, raw)
    main()

def aes_text_dcrypt():
    path = input("[->] Enter File Conaining Encrypted text: ")
    while (os.path.exists(path) == False):
        print("[x] Could not find File Specified")
        path = input("[->] Enter File Conaining Encrypted text: ")

    password = getpass.getpass("[->] Enter Decryption Password: ")
    aes.aex_dcrypt_cbc(password,path)
    main()

def AES():
    opts = {1: aes_data_crypt, 2: aes_data_dcrypt, 3:aes_dir_crypt, 4:aes_dir_dcrypt, 5: aes_text_crypt, 6: aes_text_dcrypt, 7: main}
    print("-------AES TOOLS-------")
    print("1.) Data Encryption (Using EAX)")
    print("2.) Data Decryption (Using EAX)")
    print("3.) Directory Encryption (Using EAX)")
    print("4.) Directory Decryption (Using EAX)")
    print("5.) Text Encryption (Using CBC)")
    print("6.) Text Decryption (Using CBC)")
    print("7.) Main Menu")
    x = int(input("[->] Make a selection: "))
    while(x > 7):
        x = int(input("[->] Make a selection: "))
    
    opts[x]()

def main():
    opts = {1: RSA, 2: AES, 3: exit}
    print('-------MAIN MENU-------')
    print("1.) RSA Tools")
    print("2.) AES Tools")
    print("3.) Exit")
    x = int(input("[->] Make a selection: "))
    while(x > 3):
        x = int(input("[->] Make a selection: "))

    opts[x]() 

def pass_arg():
    pass
    


if __name__ == "__main__":
    if (os.name != 'nt'):
        if(os.getuid() == 0): 
            print("YOU SHOULD NOT RUN THIS PROGRAM AS ROOT!")
            x = input("Are you sure you want to continue running as root? [y/N] ")
            if (x == '' or x == 'n' or x == 'N'):
                exit()
            elif(x == 'y' or x == 'Y'):
                if(len(sys.argv) > 1):
                    print("[!] USING CLI")
                    time.sleep(1)
                    pass_arg()
                else:
                    main()
    else:
        if(len(sys.argv) > 1):
            print("[!] USING CLI")
            time.sleep(1)
            pass_arg()
        else:
            main()

