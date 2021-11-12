from os import error
from getpass import *
import Crypto
from Crypto.PublicKey import RSA

import ast
from Crypto.Cipher import PKCS1_OAEP


def getPass(privateKey, passwords, usernames, website):
    try:
        currentPwd = passwords[website]
        decryptor = PKCS1_OAEP.new(privateKey)
        decrypted = decryptor.decrypt(ast.literal_eval(str(currentPwd)))


        

        print("username: {} | website: {}".format(usernames[website], website) +" | password: {}".format(str(decrypted)))


    except (RuntimeError, TypeError, NameError, ValueError):
        print(error)





def addPass(publicKey, passwords, usernames, file):
    file = open('passwords.txt', 'a')

    userName = input("Enter username: ")
    password = getpass(prompt='Password: ', stream=None) 
    website = input("Enter website URL: ")

    encryptor = PKCS1_OAEP.new(publicKey)

    password = encryptor.encrypt(str.encode(password))

    usnm = "Username: "+userName
    psswd = "Password (Encrypted): "+str(password)
    siteName = "Website: "+website

    file.write("\n-------------------\n")
    file.write(usnm + " | " )
    file.write(psswd + " | ")
    file.write(siteName + " | ")
    file.write("\n-------------------\n")

    passwords[website] = password
    usernames[website] = userName


def main():
    #pwd = input("Enter master password: ")
    key = RSA.generate(2048)
    print("Your public key is available in public.pem")
    print("Your private key is available in private.pem")
    with open ("private.pem", "wb") as prv_file:
        prv_file.write(key.export_key('PEM'))
    with open ("public.pem", "wb") as pub_file:  
        pub_file.write(key.publickey().export_key('PEM'))
    
    passwords = {}
    usernames = {}
    cont = True

    file = open('passwords.txt', 'w')
    file.truncate()

    while(cont == True):
        mode = int(input("\n1. Add a password \n2. Get password\n3. Quit\n"))
        if mode == 1:
            addPass(key.publickey(), passwords, usernames, file)
        elif mode == 2:
            website = input("enter site name to getpass: ")
            with open('private.pem', 'r') as f:
                privkey = RSA.import_key(f.read())
            getPass(privkey, passwords, usernames, website)
        elif mode == 3:
            cont = False
        else:
            print("invalid input")


if __name__ == "__main__":
    main()