import os
import string
import random
import json
from termcolor import colored 
from json.decoder import JSONDecodeError
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes



def generate_password():

        password_str = []
        length = input("Enter Length for Password (At least 8): ")

        if length.lower().strip() == "exit":
            raise UserExits
        elif length.strip() == "":
            raise EmptyField
        elif int(length) < 8:
            raise PasswordNotLongEnough
        else:
            for i in range(0, int(length)):
                password_str.append(random.choice(random.choice([string.ascii_lowercase, string.ascii_uppercase, string.digits])))

            finalPass = "".join(password_str)

            return finalPass


def open_manager(file_name, password_hash):
     
    while True:
        print("\n")
        print(colored("What do you want to do ?", "magenta"))
        print(colored("    1. Show every entry", "light_blue"))
        print(colored("    2. Add a new entry", "light_blue"))
        print(colored("    3. Delete an entry", "light_red"))
        print(colored("    4. Modify an entry [Need to implement]", "light_magenta"))
        print(colored("    5. Back to main menu", "light_green"))
        print(colored("    6. Exit", "light_red"))
        op = input("Choose your option : ")

        if not op:
            pass


        match int(op):
            case 1:
                    # Prints every data in the file
                    with open(file_name+".edb", "rb") as f:
                        salt = f.read(32)
                        iv = f.read(16)
                        decrypt_data = f.read()
      
                    key = password_hash
                    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                    raw_data = unpad(cipher.decrypt(decrypt_data), AES.block_size)

                    raw_data = raw_data.decode()
                    original_data = raw_data.replace("\'", "\"")

                    json_object = json.loads(original_data)
                        
                    if not json_object :
                        print(colored("File is EMPTY....", "yellow"))
                    else:
                        data_keys = json_object.keys()
                        print("\n")
                        for key in data_keys:
                            print("For account : ", bytes.fromhex(key).decode())
                            tmp = json_object[key]["username"]
                            print("  Username : ", bytes.fromhex(tmp).decode())
                            tmp = json_object[key]["password"]
                            print("  Password : ", bytes.fromhex(tmp).decode())
                            print("\n")


            case 2:
                    # Add an entry   
                    print("\n")
                    print("Adding a new entry....\n")
                    title = input("Enter title : ")
                    acc_username = input("Enter username : ")
                    
                    choice = input("Do you want to generate a password? <y/N> : ")
                    if( choice == "y" or choice == "Y"):
                        acc_password = generate_password()
                    else:
                        acc_password = input("Enter password : ")
                    
                    # Converting str -> bytes -> hex
                    site_in_hex = title.encode().hex()
                    uname_in_hex = acc_username.encode().hex()
                    password_in_hex = acc_password.encode().hex()

                    new_entry = {}
                    new_entry = {"username" : uname_in_hex, "password": password_in_hex}

                    with open(file_name+".edb", "rb+") as f:
                        # Decrypting data from file 
                        salt = f.read(32)
                        iv = f.read(16)
                        decrypt_data = f.read()
      
                        key = password_hash
                        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                        raw_data_in_bytes = unpad(cipher.decrypt(decrypt_data), AES.block_size)

                        raw_data_in_str = raw_data_in_bytes.decode()
                        original_data = raw_data_in_str.replace("\'", "\"")

                        json_object = json.loads(original_data)
                        json_object[site_in_hex] = new_entry

                        
                        # Encrypting updated data to file
                        f.seek(0)

                        cipher = AES.new(key, AES.MODE_CBC)
                        enc_data = cipher.encrypt(pad(str(json_object).encode(), AES.block_size))

                        f.write(salt)
                        f.write(cipher.iv)
                        f.write(enc_data)
                    
                    print(colored("Data entered sucessfully....", "green"))

            case 3:
                    print(colored("Delete an entry....", "red"))

                    raw_data_in_str = ""
                    with open(file_name+".edb", "rb") as f:

                        salt = f.read(32)
                        iv = f.read(16)
                        decrypt_data = f.read()
      
                        key = password_hash
                        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                        raw_data_in_bytes = unpad(cipher.decrypt(decrypt_data), AES.block_size)

                        raw_data_in_str = raw_data_in_bytes.decode()
                        

                    original_data = raw_data_in_str.replace("\'", "\"")
                    json_object = json.loads(original_data)

                    if not json_object :
                        print(colored("File is EMPTY....", "yellow"))
                    else:
                        data_keys = json_object.keys()
                        print("\n")
                        i = 1
                        for key in data_keys:
                            print("Entry No. ", i, ":")
                            print("Account : ", bytes.fromhex(key).decode())
                            tmp = json_object[key]["username"]
                            print("  Username : ", bytes.fromhex(tmp).decode())
                            tmp = json_object[key]["password"]
                            print("  Password : ", bytes.fromhex(tmp).decode())
                            print("\n")
                            i = i+1

                        seq_no = input("Entry sequence number of the account to be deleted : ")
                        seq_no = int(seq_no)

                        if seq_no in range(1, len(data_keys)+1 ):
                            tmp = bytes.fromhex(list(data_keys)[seq_no - 1]).decode()
                            json_object.pop(list(data_keys)[seq_no - 1])
                            print(colored("Entry deleted sucessfully!! ", "green"))

                            print(str(json_object))

                            with open(file_name+".edb", "wb") as f:
                                key = password_hash
                                cipher = AES.new(key, AES.MODE_CBC)
                                enc_data = cipher.encrypt(pad(str(json_object).encode(), AES.block_size))

                                f.write(salt)
                                f.write(cipher.iv)
                                f.write(enc_data)
                        else:
                            print("Entry number not in the range!!")

            case 4:
                    # Modify an entry
                    print("Modifying....[WORK IN PROGRESS]")

            case 5:
                    # Go back to the main() function
                    main()
            case 6:
                    exit()

            case _:
                    print(colored("Invalid option... Try again...\n", "red"))


def verify_password(file_name):

    with open(file_name+".edb", "rb") as f:
        salt = f.read(32)
        iv = f.read(16)
        decrypt_data = f.read()
    
    ### Run three times 
    key = ""
    for i in range(1, 4):

        flag = 0
        try:
            password = input("Enter the file password : ")
            key = PBKDF2(password, salt, dkLen=32)
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            raw_data = unpad(cipher.decrypt(decrypt_data), AES.block_size)

            flag = 1
            break
        except:
            print(colored("Incorrect password... Try again...\n", "red"))

    if flag == 1:
        open_manager(file_name, key)
    else:
        print(colored("All attempts has been made...\n", "red"))
        exit()


def import_db_file(file_name):

    if os.path.exists(file_name+".edb"):
        print(colored("File found...", "green"))
        verify_password(file_name)
    else:
        print(colored("File not found.. ", "red"))
        exit()


def create_new_file(file_name, password):

    empty_obj = {}

    salt = get_random_bytes(32)
    key = PBKDF2(password, salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_CBC)
    enc_data = cipher.encrypt(pad(str(empty_obj).encode(), AES.block_size))

    with open(file_name+".edb", "wb") as f:
        f.write(salt)
        f.write(cipher.iv)
        f.write(enc_data)
        
    print(colored("File has been sucessfully created!!", "green"))
    print(colored("Now you can IMPORT the file.\n\n", "blue"))


def main():

    print("\n")
    print(colored("#####################################################", "yellow"))
    print(colored("                 Simple Password Manager             ", "yellow"))
    print(colored("#####################################################", "yellow"))
    print("\n")

    while True:
        print("\n")
        print(colored("1. Import a file", "light_blue"))
        print(colored("2. Create a new file", "light_blue"))
        print(colored("3. Exit", "light_red"))
        op = input("\nEnter your choice : ")

        match int(op):
            case 1:
                    print(colored("\nImporting a file...", "light_blue"))
                    file_name = input("Please enter the name of the file : ")
                    # mode = "ab+"
                    import_db_file(file_name)
            case 2:
                    print(colored("Creating a file...", "light_blue"))
                    file_name = input("Enter a file name : ")
                    get_password  = input("Enter a password for the file : ")

                    create_new_file(file_name, get_password)
            case 3:
                    print(colored("Exiting...", "red"))
                    exit()
        
            case _:
                    print(colored("\nInvalid option... Please try again..\n", "red"))
    
if __name__ == "__main__" :
    main()

