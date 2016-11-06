#![feature(static_in_const)]
#![feature(conservative_impl_trait)]

extern crate clap;
extern crate rand;
extern crate sarkara;
extern crate seckey;
extern crate ttyaskpass;

use std::io::{ self, Read, Write };
use std::fs::File;
use std::error::Error;
use rand::{ Rng, OsRng };
use clap::{ Arg, App };
use sarkara::pwhash::{ KeyDerive, Argon2i };
use sarkara::stream::HC256;
use sarkara::auth::HMAC;
use sarkara::hash::Blake2b;
use sarkara::aead::{ AeadCipher, Ascon, General, RivGeneral, DecryptFail };
use sarkara::secretbox::SecretBox;
use seckey::Bytes;
use ttyaskpass::askpass;


const DEFAULT_CIPHER: Cipher = Cipher::HRHB;
const MAGIC_NUMBER: &[u8] = b"ENC.!ENC";

macro_rules! err {
    ( $err:ident, $msg:expr ) => {
        Err(::std::io::Error::new(
            ::std::io::ErrorKind::$err,
            $msg
        ))
    }
}


fn main() {
    let matches = App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(Arg::with_name("input").long("input").short("i").value_name("input file").help("input file path. if empty, use `stdin`"))
        .arg(Arg::with_name("output").long("output").short("o").value_name("output file").help("output file path. if empty, use `stdout`"))
        .arg(Arg::with_name("passphrase").long("passphrase").short("p").value_name("passphrase").help("passphrase. if empty, use `ttyaskpass`"))
        .arg(Arg::with_name("cipher").long("cipher").short("c").value_name("cipher").help("Choose cipher -- ASCON, HRHB, HHBB, if empty, use `HRHB`"))
        .arg(Arg::with_name("encrypt").short("e").help("encrypt mode").display_order(0))
        .arg(Arg::with_name("decrypt").short("d").help("decrypt mode").display_order(1))
        .get_matches();

    let mut input = if let Some(path) = matches.value_of("input") {
        Box::new(File::open(path).unwrap()) as Box<Read>
    } else {
        Box::new(io::stdin()) as Box<Read>
    };

    let mut output = if let Some(path) = matches.value_of("output") {
        Box::new(File::create(path).unwrap()) as Box<Write>
    } else {
        Box::new(io::stdout()) as Box<Write>
    };

    let cipher = matches.value_of("cipher")
        .map(|name| Cipher::from_str(name).unwrap());

    let passphrase = if let Some(pass) = matches.value_of("passphrase") {
        Bytes::new(pass.as_bytes())
    } else {
        askpass('~')
    };

    if matches.occurrences_of("encrypt") != 0 || matches.occurrences_of("decrypt") == 0 {
        encrypt(cipher, passphrase, &mut input, &mut output).unwrap();
    } else {
        decrypt(cipher, passphrase, &mut input, &mut output).unwrap();
    }
}


fn is_encrypted(input: &mut Read) -> io::Result<bool> {
    let mut magic = [0; 8];
    input.read_exact(&mut magic)?;
    Ok(magic == MAGIC_NUMBER)
}

fn encrypt(cipher: Option<Cipher>, pass: Bytes, input: &mut Read, output: &mut Write) -> io::Result<()> {
    let cipher = cipher.unwrap_or(DEFAULT_CIPHER);
    let mut salt = [0; 16];
    let mut data = Vec::new();

    input.read_to_end(&mut data)?;
    OsRng::new()?.fill_bytes(&mut salt);
    let data = Argon2i::default()
        .with_size(cipher.key_length())
        .derive::<Bytes>(&pass, &salt)
        .map(|key| cipher.encrypt(&key, &data))
        .or_else(|err| err!(Other, err.description()))?;

    output.write(MAGIC_NUMBER)?;
    output.write(&[cipher as u8])?;
    output.write(&salt)?;
    output.write_all(&data)
}

fn decrypt(cipher: Option<Cipher>, pass: Bytes, input: &mut Read, output: &mut Write) -> io::Result<()> {
    let mut cipher_number = [0; 1];
    let mut salt = [0; 16];
    let mut data = Vec::new();

    if !is_encrypted(input)? { err!(Other, "Magic Number Error.")? };
    input.read_exact(&mut cipher_number)?;
    let cipher = cipher.unwrap_or_else(|| Cipher::from_num(cipher_number[0]).unwrap());
    input.read_exact(&mut salt)?;
    input.read_to_end(&mut data)?;

    let data = Argon2i::default()
        .with_size(cipher.key_length())
        .derive::<Bytes>(&pass, &salt)
        .or_else(|err| err!(Other, err.description()))
        .and_then(|key|
            cipher.decrypt(&key, &data)
                .or_else(|err| err!(Other, err.description()))
        )?;

    output.write_all(&data)
}


#[derive(Clone)]
enum Cipher {
    ASCON = 0,
    HRHB = 1,
    HHBB = 2
}

impl Cipher {
    pub fn from_num(num: u8) -> Result<Cipher, u8> {
        match num {
            0 => Ok(Cipher::ASCON),
            1 => Ok(Cipher::HRHB),
            2 => Ok(Cipher::HHBB),
            n => Err(n)
        }
    }

    pub fn from_str(name: &str) -> Result<Cipher, &str> {
        match name.to_lowercase().as_str() {
            "ascon" => Ok(Cipher::ASCON),
            "hrhb" => Ok(Cipher::HRHB),
            "hhb" => Ok(Cipher::HHBB),
            _ => Err(name)
        }
    }

    pub fn key_length(&self) -> usize {
        match *self {
            Cipher::ASCON => Ascon::key_length(),
            Cipher::HRHB => RivGeneral::<HC256, HMAC<Blake2b>, Blake2b>::key_length(),
            Cipher::HHBB => General::<HC256, HMAC<Blake2b>, Blake2b>::key_length()
        }
    }

    pub fn encrypt(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match *self {
            Cipher::ASCON => Ascon::seal(key, data),
            Cipher::HRHB => RivGeneral::<HC256, HMAC<Blake2b>, Blake2b>::seal(key, data),
            Cipher::HHBB => General::<HC256, HMAC<Blake2b>, Blake2b>::seal(key, data)
        }
    }

    pub fn decrypt(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, DecryptFail> {
        match *self {
            Cipher::ASCON => Ascon::open(key, data),
            Cipher::HRHB => RivGeneral::<HC256, HMAC<Blake2b>, Blake2b>::open(key, data),
            Cipher::HHBB => General::<HC256, HMAC<Blake2b>, Blake2b>::open(key, data)
        }
    }
}


#[test]
fn test_encrypt_decrypt() {
    use std::io::Cursor;
    use rand::sample;

    let mut rng = OsRng::new().unwrap();
    let cipher = Cipher::from_num(sample(&mut rng, 0..3, 1)[0]).ok();
    let mut pass = vec![0; 12];
    let mut plaintext = vec![0; 1024];
    rng.fill_bytes(&mut plaintext);
    rng.fill_bytes(&mut pass);
    let mut input = Cursor::new(plaintext.clone());
    let mut output = Cursor::new(Vec::new());
    let mut output2 = Cursor::new(Vec::new());

    encrypt(cipher.clone(), Bytes::new(&pass), &mut input, &mut output).unwrap();
    output.set_position(0);
    assert!(is_encrypted(&mut output).unwrap());
    output.set_position(0);
    decrypt(cipher, Bytes::from(pass), &mut output, &mut output2).unwrap();

    let mut cleartext = Vec::new();
    output2.set_position(0);
    output2.read_to_end(&mut cleartext).unwrap();
    assert_eq!(plaintext, cleartext);
}
