use std::path::PathBuf;
use std::error::Error;
use chacha20poly1305::{XChaCha20Poly1305, aead::Aead};
use crate::custom_error::CustomError;
use std::io::{Read, Write};
use std::fs::{File, rename, remove_file};

const READ_SIZE: usize = 4096 + 16;
const KEY : &[u8 ; 32] = &[1, 1, 2, 3, 1, 5, 8, 8, 8, 7, 8, 5, 9, 9, 4, 4, 1,
	1, 2, 3, 1, 5, 8, 8, 8, 7, 8, 5, 9, 9, 4, 4];
const GREEN: &str = "\x1b[32m";
const RESET: &str = "\x1b[0m";

/*Protection to ensure that the user is using the right key
to decript files. Decrypting with the wrong key can lead to
file corruption.*/
fn check_key(bytes_key: &[u8]) -> Result<(), CustomError> {
	let mut i: usize = 0;
	if bytes_key.len() == 32 {
		for b in bytes_key {
			if b != &KEY[i] {return Err(CustomError::InvalidKey); }
			i += 1;
		}
	} else {
		return Err(CustomError::InvalidKey);
	}
	return Ok(());
}


fn get_new_filename(filename: &PathBuf) -> Result<PathBuf, CustomError> {
	let mut new_name = filename.clone();
	if let Some(ext) = new_name.extension().and_then(|e| e.to_str()) {
			if ext == "ft" {
				new_name.set_extension("");
				return Ok(new_name);
			} else {
				return Err(CustomError::WrongExtension);
			}
	}
	return Err(CustomError::WrongExtension)
}


fn	decrypt_content(contents: &[u8], key_bytes : &[u8],
		nonce: &[u8 ; 24]) -> Result<Vec<u8>,  Box<dyn Error>> {
	use chacha20poly1305::KeyInit;
	let cipher = XChaCha20Poly1305::new(key_bytes.into());
	match cipher.decrypt(nonce.into(), contents.as_ref()) {
		Ok(decrypted_content) => {return Ok(decrypted_content)},
		Err(_) => {	return Err(Box::new(CustomError::DecryptionError))},
	}
}

/*We first need to get the nonce we used for encryption at the begining of the file. Then we
decrypt the data in chuncks with the key given by the user.*/
fn decrypt_file(key_bytes : &Vec<u8>, filename: &PathBuf, silent: bool) -> Result<(), Box<dyn Error>> {
	let new_name = get_new_filename(filename)?;
	let mut tmp = File::create(".tmp_sotckholm_file")?;
	let mut file = File::open(filename)?;
	let mut read_buf: [u8 ; READ_SIZE] = [0 ; READ_SIZE];
	let mut nonce: [u8 ; 24] = [0 ; 24];
	file.read_exact(&mut nonce)?;
	loop {
		let n = file.read(&mut read_buf)?;
		if n == 0 {break;}
		let write_buffer = decrypt_content(&read_buf[..n], key_bytes.as_slice(), &nonce)?;
		tmp.write_all(&write_buffer)?;
	}
	rename(".tmp_sotckholm_file", new_name)?;
	remove_file(filename)?;
	if silent == false {
		println!("{}stockholm: {} has been decrypted by stockholm malware{}", GREEN, filename.display(), RESET);
	}
	return Ok(());
}


pub fn decrypt(key: &str, files: &Vec<PathBuf>, silent: bool) -> Result<(), Box<dyn Error>> {
	match hex::decode(key) {
		Ok(bytes_key) => {
			check_key(&bytes_key)?;
			for filename in files {
				let _ = decrypt_file(&bytes_key, filename, silent);
			}
		},
		Err(_) => {return Err(Box::new(CustomError::InvalidKey));}
	}	
	let _ = remove_file(".tmp_sotckholm_file");
	return Ok(());
}
