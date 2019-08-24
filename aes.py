import os
import sys
import time
import hashlib
import base64
from Crypto import Random
from Crypto.Cipher import AES

class aes:
    salt = "@7HdvDEh][.]/[.}{>}{{}:bLDqDYZFJ59+L#D6GT"

    def sha256(password):
        key = hashlib.sha256(password.encode())
        key = key.digest()
        return key
    
    def pad(s):
        return s + (32 - len(s) % 32) * chr(32 - len(s) % 32)

    def aes_crypt_eax(password, filename):
        key = aes.sha256(password)
        print("[!] SHA256: ", key.hex().upper())
        ext = ".lck"
        print("[!] Reading Data")
        time.sleep(1)
        with open(filename, "rb") as f:
            data = f.read()
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        fn = filename + ext
        print("[!] Encrypring")
        time.sleep(1)
        sig = aes.sha256(str(password) + aes.salt)
        with open(fn, "wb") as f:
             [f.write(x) for x in (sig, cipher.nonce, tag, ciphertext)]

        x = input("[->] Would you like to remove the original file? [Y/n]: ")

        if (x == '' or x == "y" or x == "Y"):
            os.remove(filename)
            print("[!] Done Encrypting!")
            time.sleep(1)
        elif (x == "n" or x == "N"):
            print("[!] Done Encrypting!")
            time.sleep(1)

    def dir_encrypt(password, dirr):
        key = aes.sha256(password)
        ext = ".lck"
        print("[!] Reading Data")
        time.sleep(1)
        for path, subdirs, files in os.walk(dirr):
            print("[!] Encrypting: ", path)            
            for name in files:
                cipher = AES.new(key, AES.MODE_EAX)
                file = (os.path.join(path, name))
                print("[!] Encypting %s" %name)
                time.sleep(0.3)
                with open(file, "rb") as f:
                    data = f.read()
                ciphertext, tag = cipher.encrypt_and_digest(data)
                fn = file + ext
                with open(fn, "wb") as f:
                    [f.write(x) for x in (cipher.nonce, tag, ciphertext)]
                os.remove(file)
                


    def aes_dcrypt_eax(password, filename):
        key = aes.sha256(password)
        print("[!] Reading Data")
        time.sleep(1)
        with open(filename, "rb") as f:
            sig, nonce, tag, ciphertext = [f.read(x) for x in (32, 16, 16, -1)]
        sig_orig = aes.sha256(str(password) + aes.salt)
        if(sig_orig == sig):
            cipher = AES.new(key, AES.MODE_EAX, nonce)
            try:
                print("[!] Decrypting!")
                time.sleep(1)
                data = cipher.decrypt_and_verify(ciphertext, tag)
                fn = filename.replace(".lck","")
                print("[!] Done Decrypting!")
                os.remove(filename)
                time.sleep(1)
                with open(fn, "wb") as f:
                    f.write(data)
            except Exception as e:
                print("[x] Error: %s" % str(e) )
        else:
            print("[x] Wrong Signatures!")
#only used for text
    def aes_crypt_cbc(password, raw):
        key = aes.sha256(password)
        print("[!] Reading Data")
        time.sleep(1)
        data = aes.pad(raw)
        iv = Random.new().read(16)
        try:
            print("[!] Encrypting Text!")
            time.sleep(1)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            out = iv + cipher.encrypt(data.encode("utf-8"))
            print("[!] Done encrypting!")
            time.sleep(1)
            x = str(input("[->] Enter filename for the output: "))
            with open(x, 'wb') as f:
                f.write(base64.b64encode(out))
            print("[!] Check %s for encrypted text (base64 encoded)" %x)
        except Exception as e:
            print("[x] Error: %s" % str(e) )
    
    def aex_dcrypt_cbc(password, filename):
        key = aes.sha256(password)
        print("[!] Reading Data")
        time.sleep(1)
        with open(filename, 'rb') as f:
            data = f.read()
        data = base64.b64decode(data)
        iv = data[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        try:
            print("[!] Decrypting!")
            time.sleep(1)
            plaintext = cipher.decrypt(data[16:])
            print("[!] Done Decrypting")
            time.sleep(1)
            text = aes.unpad(plaintext)
            text = text.decode("utf-8")
            print("[!] Resulted Text: ", text)
            time.sleep(1)
            os.remove(filename)
        except Exception as e:
            print("[x] Error: %s" % str(e) )
       
    def unpad(s):
        return s[:-ord(s[len(s)-1:])]
