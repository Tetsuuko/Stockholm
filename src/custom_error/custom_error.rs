use core::fmt;

pub enum CustomError {
	InvalidKey,
	WrongDirectory,
	NoHomeDirectory,
	EncryptionError,
	DecryptionError,
	WrongExtension,
}


impl fmt::Display for CustomError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			CustomError::InvalidKey => write!(f, "The encryption key is not valid"),
			CustomError::WrongDirectory => write!(f, "Wrong working directory, must be $HOME/infection/"),
			CustomError::NoHomeDirectory => write!(f, "Can not find user's home directory"),
			CustomError::EncryptionError => write!(f, "Can not encrypt data"),
			CustomError::DecryptionError => write!(f, "Can not decrypt data"),
			CustomError::WrongExtension => write!(f, "Extension not targeted by stockholm"),
		}
	}
}


impl fmt::Debug for CustomError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			CustomError::InvalidKey => write!(f, "The encryption key is not valid"),
			CustomError::WrongDirectory => write!(f, "Wrong working directory, must be $HOME/infection/"),
			CustomError::NoHomeDirectory => write!(f, "Can not find user's home directory"),
			CustomError::EncryptionError => write!(f, "Can not encrypt data"),
			CustomError::DecryptionError => write!(f, "Can not decrypt data"),
			CustomError::WrongExtension => write!(f, "Extension not targeted by stockholm"),
		}
	}
}


impl std::error::Error for CustomError {}