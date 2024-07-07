use std::cmp::min;
use std::fs;
use std::io::{ Read};

use reqwest::StatusCode;
use std::fmt::Write;
use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};

use colored::Colorize;

pub static COMPLETE: AtomicBool = AtomicBool::new(false);
pub static MALICIOUS: AtomicBool = AtomicBool::new(false);

pub async fn checkinfile(turl: &Option<String>, tfile: &Option<String>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {



    let url =option_to_string(turl);
   // println!("url: {}",url);
    let targetfile = option_to_string(tfile);
   // println!("targetfile: {}",targetfile);

    if url.is_empty() && targetfile.is_empty() {
        println!("[-] Check targeturl or targetfile value");
        std::process::exit(1);
    }
    if !url.is_empty() {
        let client = reqwest::Client::new();

        let head_response = client.head(&url).send().await?;
        if head_response.status() != StatusCode::OK {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "[-] URLFile not found",
            )));
        }

        println!("[+] Reading url file to bytes...");
        let response = client.get(&url).send().await?;
        let bytes = response.bytes().await?;
        return Ok(bytes.to_vec());
    }
    if !targetfile.is_empty() {
        println!("[+] Reading Disk file to bytes...");
        let mut file = fs::File::open(targetfile)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        return Ok(buffer);
    }

    Ok(Vec::new())


}

fn option_to_string(option: &Option<String>) -> String {
    option.as_deref().unwrap_or("").to_string()
}

pub fn format_hex_dump(data: &[u8]) -> String {
    const BYTES_PER_LINE: usize = 16;
    let mut result = String::new();

    for (i, chunk) in data.chunks(BYTES_PER_LINE).enumerate() {
        // Print the address
        let mut line = format!("{:08X}  ", i * BYTES_PER_LINE);

        // Print the hex codes
        for (j, byte) in chunk.iter().enumerate() {
            if j > 0 && j % 8 == 0 {
                write!(line, " ").unwrap();
            }
            write!(line, "{:02X} ", byte).unwrap();
        }


        if chunk.len() < BYTES_PER_LINE {
            let padding_spaces = (BYTES_PER_LINE - chunk.len()) * 3;
            let padding_blocks = (BYTES_PER_LINE - chunk.len() + 7) / 8;
            for _ in 0..padding_spaces {
                line.push_str(" ");
            }
            for _ in 0..padding_blocks {
                line.push_str(" ");
            }
        }

        // Print the ASCII representation
        line.push_str(" |");
        for &byte in chunk {
            if byte.is_ascii_graphic() {
                write!(line, "{}", byte as char).unwrap();
            } else {
                line.push('·');
            }
        }
        line.push_str("\n");

        // Append line to the result
        result.push_str(&line);
    }

    result
}

pub fn half_splitter(original_array: &[u8], last_good: usize) -> Vec<u8> {
    let split_size = (original_array.len() - last_good) / 2 + last_good;
    let mut split_array = Vec::with_capacity(split_size);

    if original_array.len() == split_size + 1 {
        println!("{}",format!("[!] Identified end of bad bytes at offset 0x{:X}", original_array.len()).red());

        let offending_size = min(original_array.len(), 256);
        let offending_bytes = &original_array[original_array.len() - offending_size..];
        println!("{}", format_hex_dump(offending_bytes));

        COMPLETE.store(true, Ordering::SeqCst);
    }

    split_array.extend_from_slice(&original_array[..split_size]);
    split_array
}
pub fn overshot(original_array: &[u8], split_array_size: usize) -> Option<Vec<u8>> {
    let new_size = (original_array.len() - split_array_size) / 2 + split_array_size;

    if new_size == original_array.len() - 1 {
        COMPLETE.store(true, Ordering::SeqCst);

        if MALICIOUS.load(Ordering::SeqCst) {
            println!("[!] File is malicious, but couldn't identify bad bytes");

            return None;
        }
    }

    let mut new_array = Vec::with_capacity(new_size);
    new_array.extend_from_slice(&original_array[..new_size]);
    Some(new_array)
}


//  Converts &[u8] to a string
pub fn bytes_to_string(bytes: &[u8]) -> Result<String, std::string::FromUtf8Error> {
    String::from_utf8(bytes.to_vec())
}

pub fn read_yarafile_to_bytes(file_path: &Option<String>) -> Vec<u8> {
    let targetfile = option_to_string(file_path);
    let mut file = match File::open(targetfile.clone()) {
        Ok(f) => f,
        Err(_) => {
            eprintln!("[-] Open Yara File with error: {}", &targetfile);
            return Vec::new();
        }
    };

    let mut buffer = Vec::new();
    match file.read_to_end(&mut buffer) {
        Ok(_) => buffer,
        Err(_) => {
            eprintln!("[-] Read Yara File with error: {}", &targetfile);
            Vec::new()
        }
    }
}