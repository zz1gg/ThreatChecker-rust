use std::path::Path;
use std::process::{Command, Stdio};
use std::{fs, thread};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use colored::Colorize;
use crate::filehandler::{COMPLETE, half_splitter, overshot};

#[derive(Debug)]
enum ScanResult {
    NoThreatFound,
    ThreatFound,
    FileNotFound,
    Timeout,
    Error,
}

#[derive(Debug)]
struct DefenderScanResult {
    result: ScanResult,
    signature: Option<String>,
}


pub fn defender_analyze_bytes(targetfilebytes: &[u8]){

    if !Path::new("C:\\Temp").exists() {
        println!("C:\\Temp doesn't exist. Creating it...");
        fs::create_dir_all("C:\\Temp").expect("[-] Create Temp folder Failed!");
    }

    let tmp_file_path = "C:\\Temp\\file.exe.bak";
    fs::write(&tmp_file_path, targetfilebytes).expect("[-] Write Temp file Failed!");
   // println!("targetfilebytes:{:?}",targetfilebytes);

    match scan_file(tmp_file_path) {
        Ok(result) => match result.result {
            ScanResult::NoThreatFound => println!("{}","[+] No threat found".green()),
            ScanResult::ThreatFound => {
                if let Some(signature) = result.signature {
                    println!("{}",format!("[!] Threat found: {}", signature).red());
                } else {
                    eprintln!("[-] Threat found but failed to extract signature");
                }

                println!("[+] Target file size: {} bytes", targetfilebytes.len());
                println!("[+] Defender Analyzing...");

                let mut split_array = targetfilebytes[0..targetfilebytes.len() / 2].to_vec();
                let mut last_good = 0;
                while !COMPLETE.load(Ordering::SeqCst) {
                    fs::write(&tmp_file_path, &split_array)
                        .expect("[-] Error writing split file.");
                   let mut detection_status = scan_file(&tmp_file_path)
                        .expect("[-] Scan with Defender Failed!");
                    //let detection_status = scan_with_defender(&split_array);
                    match detection_status.result {
                        ScanResult::ThreatFound => {
                            // println!("[!] Threat found, splitting");
                            split_array = half_splitter(&split_array, last_good);
                        }
                        ScanResult::NoThreatFound => {
                            //println!("[+] No threat found, increasing size");
                            last_good = split_array.len();
                            if let Some(tmp_array) = overshot(&targetfilebytes, split_array.len()) {
                                split_array = tmp_array;
                            } else {

                                break;
                            }
                        }
                        _ => break,
                    }
                }

            }
            ScanResult::FileNotFound => eprintln!("[-] File not found"),
            ScanResult::Timeout => eprintln!("[-] Command execution timed out"),
            ScanResult::Error => eprintln!("[-] Command execution failed"),
        },
        Err(e) => eprintln!("[-] Failed to execute scan: {}", e),
    }
}

fn scan_file(targetfile_path: &str) -> Result<DefenderScanResult, String> {
    let start = Instant::now();
    let mut child = Command::new("C:/Program Files/Windows Defender/MpCmdRun.exe")
        .args(&[
            "-Scan",
            "-ScanType",
            "3",
            "-File",
            targetfile_path,
            "-DisableRemediation",
            "-Trace",
            "-Level",
            "0x10",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("[-] Failed to execute process: {}", e))?;
    //println!("{:?}",child.stdout);
    loop {
        if start.elapsed() > Duration::from_secs(30) {
            child
                .kill()
                .map_err(|e| format!("[-] Failed to kill the process: {}", e))?;
            return Ok(DefenderScanResult {
                result: ScanResult::Timeout,
                signature: None,
            });
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                let output = child
                    .wait_with_output()
                    .map_err(|e| format!("[-] Failed to read output: {}", e))?;
                return handle_output(output);
            }
            Ok(None) => {
                thread::sleep(Duration::from_millis(500));
                continue;
            }
            Err(e) => {
                return Err(format!("[-] Error while waiting for the process: {}", e));
            }
        }
    }
}

fn handle_output(output: std::process::Output) -> Result<DefenderScanResult, String> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let status_code = output.status.code().unwrap_or(-1);

     //println!("stdout: {}", stdout);
     //println!("stderr: {}", stderr);
     //println!("status_code: {}", status_code);

    match status_code {
        2 => {
            let signature = extract_signature(&stdout);
            if let Some(signature) = signature {
                Ok(DefenderScanResult {
                    result: ScanResult::ThreatFound,
                    signature: Some(signature),
                })
            } else {
                Ok(DefenderScanResult {
                    result: ScanResult::Error,
                    signature: None,
                })
            }
        }
        0 => Ok(DefenderScanResult {
            result: ScanResult::NoThreatFound,
            signature: None,
        }),
        1 => Ok(DefenderScanResult {
            result: ScanResult::FileNotFound,
            signature: None,
        }),
        _ => Ok(DefenderScanResult {
            result: ScanResult::Error,
            signature: None,
        }),
    }
}

fn extract_signature(output: &str) -> Option<String> {
    let lines: Vec<&str> = output.lines().collect();
    for line in lines {

        if line.contains("Threat  ") {
            let threatparts: Vec<&str> = line.split_whitespace().collect();

            if threatparts.len() >= 2 {
                return Some(threatparts[2].to_string());
            }
        }
    }
    None
}
