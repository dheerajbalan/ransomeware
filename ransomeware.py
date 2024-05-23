
import pathlib,os,base64, getpass
import argparse
import cryptography
import secrets
from cryptography.fernet import Fernet
import cryptography.fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from colorama import Fore
green = Fore.LIGHTGREEN_EX
red = Fore.RED


def get_banner():
    banner = """

          ░▒▓███████▓▒░  ░▒▓██████▓▒░ ░▒▓███████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░       ░▒▓██████▓▒░ ░▒▓█▓▒░░▒▓███████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓████████▓▒░░▒▓███████▓▒░  
          ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░       ░▒▓█▓▒░░▒▓█▓▒░ 
          ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░       ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░       ░▒▓█▓▒░░▒▓█▓▒░ 
          ░▒▓█▓▒░░▒▓█▓▒░░▒▓████████▓▒░░▒▓███████▓▒░ ░▒▓███████▓▒░       ░▒▓█▓▒░       ░▒▓█▓▒░░▒▓███████▓▒░ ░▒▓████████▓▒░░▒▓██████▓▒░  ░▒▓███████▓▒░  
          ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░       ░▒▓█▓▒░░▒▓█▓▒░       ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░       ░▒▓█▓▒░░▒▓█▓▒░ 
          ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░       ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░       ░▒▓█▓▒░░▒▓█▓▒░ 
          ░▒▓███████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░       ░▒▓██████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░       ░▒▓█▓▒░░▒▓█▓▒░░▒▓████████▓▒░░▒▓█▓▒░░▒▓█▓▒░                                                                                                                                                                                                                                                                                                
    """
    print(red + banner)

def generate_salt(size=16):
    return secrets.token_bytes(size)

def derive_key(salt, password):
    if not isinstance(salt, bytes):
        raise TypeError("Salt must be bytes")
    kdf = Scrypt(salt=salt, length=32 , n = 2**14 , r=8, p=1)
    return kdf.derive(password.encode())

def load_salt():
    with open("salt.salt" , "rb") as save_file:
        return save_file.read()

def encrypt_key(password, salt_size=16 ,load_existing_salt=False, save_salt=True):
    if load_existing_salt:
        salt = load_salt()
    elif save_salt:
        salt = generate_salt(salt_size)
        with open("salt.salt", "wb") as save_file:
            save_file.write(salt)
    if not isinstance(salt, bytes):
        raise TypeError("Salt must be bytes")
    derived_key = derive_key(salt, password)
    return base64.urlsafe_b64encode(derived_key)

def encryption(filename , key ):
    f = Fernet(key)
    with open(filename, "rb") as file:
        file_data = file.read()
    encrypted_data = f.encrypt(file_data)
    with open(filename, "wb") as file:
        file.write(encrypted_data)

def decryption(filename,key):
    f = Fernet(key)
    with open(filename, "rb" ) as file:
        encrypted_data =  file.read()
    try:
        decrypted_data = f.decrypt(encrypted_data)
    except cryptography.fernet.InvalidToken:
        print("[*]Incorrect password try with a corect password!!")
        return
    with open(filename,"wb") as file:
        file.write(decrypted_data)

def encrypt_folder(foldername ,key):
    for child in pathlib.Path(foldername).glob("*"):
        if child.is_file():
            print(f"{green}[+] encrypting file :  {child}!!")
            encryption(child,key)
        elif child.is_dir():
            print(f"{green}[+] encrypting folder: {child}!!")
            encrypt_folder(child,key)

def decrypt_folder(foldername , key):
    for child in pathlib.Path(foldername).glob("*"):
        if child.is_file():
            print(f"{red}[-] decrypting file : {child}!!")
            decryption(child,key)
        elif child.is_dir():
            print(f"{red}[-] decrypting file: {child}")
            decrypt_folder(child,key)

get_banner()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="File Encryptor Script with a Password")
    parser.add_argument("path", help="Path to encrypt/decrypt, can be a file or an entire folder")
    parser.add_argument("-s", "--salt-size", help="If this is set, a new salt with the passed size is generated",type=int)
    parser.add_argument("-e", "--encrypt", action="store_true",help="Whether to encrypt the file/folder, only -e or -d can be specified.")
    parser.add_argument("-d", "--decrypt", action="store_true",help="Whether to decrypt the file/folder, only -e or-d can be specified.")
    args = parser.parse_args()

    if args.encrypt:
        password=getpass.getpass(f"enter the password to encrypt:")
    elif args.decrypt:
        password=getpass.getpass(f"enter the password u used for encryption: ")

    if args.salt_size:
        key = encrypt_key(password , salt_size=args.salt_size, save_salt=True)
    else :
        key = encrypt_key(password , load_existing_salt=True)

    if args.encrypt and args.decrypt:
        raise TypeError("please specify wheter to encrypt or decrypt the file!! ")
    elif args.encrypt:
        if os.path.isfile(args.path):
            encryption(args.path , key)
        elif os.path.isdir(args.path):
            encrypt_folder(args.path, key)
    elif args.decrypt:
        if  os.path.isfile(args.path):
            decryption(args.path, key)
        elif os.path.isdir(args.path):
            decrypt_folder(args.path,key)
else:
    raise TypeError("please specify wheter to encrypt or decrypt the file!!")

