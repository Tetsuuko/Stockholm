use clap::Parser;
use std::process;
use std::error::Error;
use crate::stockholm::*;

pub mod stockholm;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None, disable_version_flag = true)]
struct Args {
	#[arg(help = "Decryption key (must be at least 16 len bytes)")]
	key: Option<String>,

    #[arg(short = 'v', long = "version", help = "Shows the current version of the program")]
    version: bool,

	#[arg(short = 's', long = "silent", help = "Suppresses all output")]
    silent: bool,

	#[arg(short = 'r', long = "reverse", help = "Restores the files to their original state providing the correct key")]
    reverse: bool,
}

mod custom_error;

fn main() -> Result<(), Box<dyn Error>> {
	let args = Args::parse();
	if args.version == true {
		println!("Stockholm version 1.0");
		process::exit(0);
	}
	match args.key {
		Some(key) => {
			stockholm(&key, args.silent, args.reverse)?;
		},
		None => {
			if args.reverse == true {
				eprintln!("stockholm: error: The encryption key is mandatory with --reverse");
				process::exit(1);
			} else {
				stockholm("", args.silent, args.reverse)?;
			}

		}
	}
	return Ok(());
}