
use colored::Colorize;
use windows::core::w;
use crate::filehandler::{COMPLETE, half_splitter, overshot};
use windows::Win32::System::Antimalware::{AMSI_RESULT, AMSI_RESULT_CLEAN, AMSI_RESULT_DETECTED, AMSI_RESULT_NOT_DETECTED, AmsiCloseSession, AmsiInitialize, AmsiOpenSession, AmsiScanBuffer, AmsiUninitialize};
use std::sync::atomic::{Ordering};


pub fn amsi_analyze_bytes(targetfilebytes: &[u8]) {
    // targetfilebytes = bytes.to_vec();

    let status = scan_with_amsi(targetfilebytes);
    println!("[+] status value: {:?}", status);
    if status != Ok(AMSI_RESULT_DETECTED) {
        println!("{}","[+] No threat found!".green());
        return;
    } else {
        println!("{}","[!] Threat detected!".red());
    }

    println!("[+] Target file size: {} bytes", targetfilebytes.len());
    println!("[+] AMSI Analyzing...");

    let mut split_array = targetfilebytes[..targetfilebytes.len() / 2].to_vec();
    let mut last_good = 0;
    while !COMPLETE.load(Ordering::SeqCst) {
        let detection_status = scan_with_amsi(&split_array);

        if detection_status == Ok(AMSI_RESULT_DETECTED) {
            let tmp_array = half_splitter(&split_array, last_good);
            split_array = tmp_array;
        } else {
            last_good = split_array.len();
            if let Some(tmp_array) = overshot(&targetfilebytes, split_array.len()) {
                split_array = tmp_array;
            } else {
                break;
            }
        }
    }
}



pub fn scan_with_amsi(content_to_scan:  &[u8]) -> windows::core::Result<AMSI_RESULT> {
    unsafe {


        let amsi_context_result = AmsiInitialize(w!("MyApp"));

        // println!("amsi_context_result: {:?}", amsi_context_result);

        let amsi_context = match amsi_context_result {
            Ok(context) => context,
            Err(error) => {
                eprintln!("[-] Failed to initialize AMSI: {:?}", error);
                return Err(error);
                // std::process::exit(1);
            }
        };
        // println!("amsi_context: {:?}", amsi_context);

        let amsi_session_result = AmsiOpenSession(amsi_context);
        // println!("amsi_session_result: {:?}", amsi_session_result);
        let amsi_session = match amsi_session_result {
            Ok(session) => session,
            Err(error) => {
                eprintln!("[-] Failed to open AMSI session: {:?}", error);
                return Err(error);
                //std::process::exit(1);
            }
        };
        //println!("amsi_session: {:?}", amsi_session);

        let amsi_scan_result = AmsiScanBuffer(
            amsi_context,
            content_to_scan.as_ptr() as *const _,
            content_to_scan.len() as u32,
            w!("MyApp"),
            amsi_session,
        );

        // println!("amsi_scan_result:{:?}", amsi_scan_result);


        let amsi_result = match amsi_scan_result {
            Ok(result) => result,
            Err(error) => {
                eprintln!("[-] Failed to scan buffer: {:?}", error);
                AmsiCloseSession(amsi_context, amsi_session);
                AmsiUninitialize(amsi_context);
                return Err(error);
                //std::process::exit(1);
            }
        };
        // println!("amsi_result:{:?}", amsi_result);



        AmsiCloseSession(amsi_context, amsi_session);
        AmsiUninitialize(amsi_context);
        Ok(amsi_result)
    }
}

