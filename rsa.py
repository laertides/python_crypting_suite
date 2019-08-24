import os
import time
import sys
import hashlib
import base64
import ast
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

class rsa:

    def rsa_key(password):
        key = hashlib.sha256(password.encode())
        print("[!] SHA256 KEY:" ,key.hexdigest().upper())
        time.sleep(1)
        key = key.digest()
        return key

    def gen_rsa(password):
        passphrase = rsa.rsa_key(password)
        print("[!] Generating 4096-bit RSA Key Pair")
        key = RSA.generate(4096)
        enc_rsa = key.export_key(passphrase= passphrase, pkcs=8, protection="scryptAndAES256-CBC")

        print("[!] Exporting Private Key")
        time.sleep(1)
        with open("private_KEY.pem", 'wb') as f:
            f.write(enc_rsa)

        print("[!] Exporting Public Key")
        time.sleep(1)
        with open("public_KEY.pem", "wb") as f:
            f.write(key.publickey().export_key())
        #write the keys to files
        print("[!] Keys Exported Successfully!")
        time.sleep(1)

    def rsa_encrypt(pubkey, filename):
        print("[!] Importing Public Key")
        time.sleep(1)
        with open(pubkey, "r") as f:
            pub_key = RSA.import_key(f.read())

        session_key = get_random_bytes(16)
        cipher_rsa = PKCS1_OAEP.new(pub_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        with open(filename, "rb") as f:
            data = f.read()

        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)

        with open(filename + ".lck", "wb") as f:
            try:
                print("[!] Encrypting")
                time.sleep(1)
                [f.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
            except Exception as e:
                print("[x] Error: %s" % str(e) )
                return -1
        
        x = input("Would you like to remove the original file? [Y/n]: ")

        if (x == '' or x == "y" or x == "Y"):
            os.remove(filename)
            print("[!] Done Encrypting!")
            time.sleep(1)
        elif (x == "n" or x == "N"):
            print("[!] Done Encrypting!")
            time.sleep(1)

        return 0

    def dir_crypt(pubkey, dirr):
        print("[!] Importing Public Key")
        time.sleep(1)
        with open(pubkey, "r") as f:
            pub_key = RSA.import_key(f.read())

        cipher_rsa = PKCS1_OAEP.new(pub_key)
        for path, subdirs, files in os.walk(dirr):
            print("[!] Encrypting: ", path)            
            for name in files:
                file = (os.path.join(path, name))
                print("[!] Encypting %s" %name)
                time.sleep(0.3)
                session_key = get_random_bytes(16)
                enc_session_key = cipher_rsa.encrypt(session_key)
                with open(file, "rb") as f:
                    data = f.read()

                cipher_aes = AES.new(session_key, AES.MODE_EAX)
                ciphertext, tag = cipher_aes.encrypt_and_digest(data)

                with open(file + ".lck", "wb") as f:
                    try:
                        [f.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
                    except Exception as e:
                        print("[x] Error: %s" % str(e) )
                os.remove(file)

    def dir_dcrypt(password, privkey, dirr):
        passphrase = rsa.rsa_key(password)
        print("[!] Importing Private Key")
        time.sleep(1)
        with open(privkey, 'r') as f:
            priv_key = RSA.import_key(f.read(), passphrase=passphrase)
            print("[!] Unlocked Private Key")
            time.sleep(1)
        cipher_rsa = PKCS1_OAEP.new(priv_key)
        for path, subdirs, files in os.walk(dirr):
            print("[!] Decrypting: ", path)            
            for name in files:
                file = (os.path.join(path, name))
                print("[!] Decrypting %s" %name)
                time.sleep(0.2)
                with open(file, 'rb') as f: 
                    enc_session_key, nonce, tag, ciphertext = [ f.read(x) for x in (priv_key.size_in_bytes(), 16, 16, -1) ]
                session_key = cipher_rsa.decrypt(enc_session_key)
                cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
                data = cipher_aes.decrypt_and_verify(ciphertext, tag)
                fn = file.replace(".lck", "")
                with open(fn, "wb") as f:
                    f.write(data)
                os.remove(file)

    def rsa_dcrypt(password, privkey, filename):
        passphrase = rsa.rsa_key(password)
        print("[!] Importing Private Key")
        time.sleep(1)
        with open(privkey, 'r') as f:
            try:
                priv_key = RSA.import_key(f.read(), passphrase=passphrase)
                print("[!] Unlocked Private Key")
                time.sleep(1)
                with open(filename, 'rb') as f: 
                    enc_session_key, nonce, tag, ciphertext = [ f.read(x) for x in (priv_key.size_in_bytes(), 16, 16, -1) ]
                print("[!] Decrypting")
                time.sleep(1)
                cipher_rsa = PKCS1_OAEP.new(priv_key)
                session_key = cipher_rsa.decrypt(enc_session_key)
                cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
                data = cipher_aes.decrypt_and_verify(ciphertext, tag)
                fn = filename.replace(".lck", "")
                with open(fn, "wb") as f:
                    f.write(data)
                os.remove(filename)
                print("[!] Done Decrypting!")
                time.sleep(1)
            except Exception as e:
                print("[x] Error: %s" % str(e) )

    def rsa_text_encrypt(pubkey, raw):
        print("[!] Importing Public Key")
        time.sleep(1)
        with open(pubkey, "r") as f:
            pub_key = RSA.import_key(f.read())

        print("[!] Encrypting")
        time.sleep(1)
        cipher_rsa = PKCS1_OAEP.new(pub_key)
        enc_data = cipher_rsa.encrypt(raw.encode("utf-8"))
        x = str(input("Enter filename to save output: "))
        with open(x, 'wb') as f:
            f.write(base64.b64encode(enc_data))
        print("[!] Done Encrypting!")
        time.sleep(1)
        print("[!] Check %s file for the encrypted Text (base64)" % x)
        time.sleep(1)
 
    def rsa_text_dcrypt(password, privkey, filename):
        passphrase = rsa.rsa_key(password)

        print("[!] Importing Private Key")
        time.sleep(1)
        with open(privkey, 'r') as f:
            priv_key = RSA.import_key(f.read(), passphrase=passphrase)
        
        print("[!] Unlocked Private Key")
        time.sleep(1)
        cipher_rsa = PKCS1_OAEP.new(priv_key)
        print("[!] Reading Data")
        time.sleep(1)
        with open(filename, 'rb') as f:
            data = base64.b64decode(f.read())
        try:
            print("[!] Decrypting")
            time.sleep(1)
            raw = cipher_rsa.decrypt(data).decode("utf-8")
            print("[!] Resulted Text: ", raw)
            os.remove(filename)
        except Exception as e:
            print("[x] Error: %s" % str(e) )