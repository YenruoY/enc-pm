# Enc-pm 

Simple password manager built using Python3. The passwords are stored inside an encrypted file. This file must be kept safe and the password for the database file should be remembered as it's necessary during decryption and is not recoverable.

**Note :** This script should not be used in professional setting.

# Initial version

1. The first alpha release of the script. 
2. Have encryption and decryption implemented.
3. Can add or delete an entry.

# Usage

Clone the repo :

    $ git clone https://github.com/YenruoY/enc-pm.git

Install requirments :

    $ cd enc-pm && python -m pip install -r requirements.txt 

Run the script :
    
    $ python encpm.py

**Note :** In some distributions you have to use `python3` instead of `python` and `pip3` instead of `pip`.

# Requirements

1. termcolor
1. pycryptodome

# To implement 

1. Function to edit entries 

