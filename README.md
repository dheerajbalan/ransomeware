Dark Cipher

Dark Cipher is a Python tool for encrypting and decrypting files and folders using a password. It leverages the `cryptography` library to provide secure encryption and decryption.

Disclaimer

**This tool is for educational purposes only. The author is not responsible for any misuse or damage caused by this tool. Use it responsibly.**

Features

- Encrypt individual files or entire folders.
- Decrypt individual files or entire folders.
- Uses password-based encryption with a generated salt for security.

 Installation

1. Clone the repository:
    
    sh
    	git clone https://github.com/dheerajbalan/ransomeware.git
    	cd ransomeware
    

2. Create and activate a virtual environment:
    
    sh
    	python -m venv venv
    	source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    

3. Install the required packages:
    
    sh
    	pip install -r requirements.txt
    

Usage

Dark Cipher can be used to encrypt or decrypt files and folders from the command line.

**Warning: Do not attempt to encrypt files or folders that have already been encrypted using this tool. Doing so may result in data loss.**

Encrypting a File

To encrypt a file:

 sh
	python ransomeware.py -e path/to/your/file

You will be prompted to enter a password for encryption.
Decrypting a File

To decrypt a file:

sh

	python ransomeware.py -d path/to/your/file

You will be prompted to enter the password you used for encryption.
Encrypting a Folder

To encrypt an entire folder:

sh
	
	python ransomeware.py -e path/to/your/folder

You will be prompted to enter a password for encryption.
Decrypting a Folder

To decrypt an entire folder:

sh

	python ransomeware.py -d path/to/your/folder

You will be prompted to enter the password you used for encryption.
Options

    -s, --salt-size: Specify a custom salt size. If not provided, a default size of 16 bytes is used.
    -e, --encrypt: Encrypt the specified file or folder.
    -d, --decrypt: Decrypt the specified file or folder.

Example

Encrypting a file with a custom salt size:

sh

	python ransomeware.py -e path/to/your/file -s 32

Decrypting a folder:

sh

	python ransomeware.py -d path/to/your/folder

License

This project is licensed under the MIT License - see the LICENSE file for details.
