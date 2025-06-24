# STOCKHOLM
Stockholm project as part of the cybersecurity pool at school 42.
This program allows you to encrypt files or decrypt them using the correct encryption key.

## Installation
1. Clone the repository:
	git clone https://github.com/

 2. Compile the program (need cargo and rustc 1.85.*):
	make stockholm

3. Run the programm:
	./target/release/stockholm

## Warning
- This project is for educational purposes only. You should never use this type of program for malicious purposes.

- The programm only work in a folder called 'infection' in the user's HOME directory

- The program only act on files whose extensions have been affected by Wannacry.

## Usage

- To encrypt all files of the current directory and all subdirectories, you have
to run the program in the right directory (see Warning). All encrypted files will be rename to add ".ft" at the end of their name.

- DO NOT modify any byte of the encrypted files if you want to restore them to their original state.

- If you run the program while already encrypted files are present in the folder, they will not be affected.

- To decrypt the infected files, you have to run the programm with the --reverse option
following by the hexadecimal string used for the encryption :
	./target/release/stockholm --reverse hexa_string

The decryption key is located in the file "key.hex".

- The program displays all successful file encryptions or decryptions. You can prevent this by using the --silent option.

## Encryption Method
- We use XChaCha20-Poly1305 ([See](https://en.wikipedia.org/wiki/ChaCha20-Poly1305)) as encryption algorithm.

- The encryption key is constant but we use a randomly generated once for each encrypted file
(24 bytes) and write it at the begining of the encrypted file. This prevents decryption by re-encrypting the same file without using the --reverse option.

- Data is encrypted using 4096 bytes chunks. As XChaCha20-Poly1305 adds a 16 bytes ciphertext expansion to the encrypted data, the size of the encrypted file will be :
			(SIZE OF THE NONCE) + (ORIGINAL FILE SIZE) + 16 * (ORIGINAL FILE SIZE) % 4096

- The encrypted data is first written to a temporary file. Then, the original file is
deleted, and the temporary file is renamed using the original file's name with the ".ft" extension added.