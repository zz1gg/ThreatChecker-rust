mod commands;
mod defenderscanner;
mod yarascanner;
mod filehandler;
mod amsiscanner;



use clap::{Parser, Subcommand};
use colored::Colorize;
use crate::amsiscanner::{amsi_analyze_bytes};
use crate::defenderscanner::defender_analyze_bytes;
use crate::filehandler::{checkinfile, read_yarafile_to_bytes};
use crate::yarascanner::scan_with_yara;

#[tokio::main]
async fn main() {


    let args = commands::Args::parse();

   // println!("{:?}", args);



    if args.targetfile.is_none() && args.url.is_none() {
        eprintln!("{}","[-] Error: Either targetfile or url must be provided.".red());
        println!("{}","[!]Tips: Please input -h or --help flag, try <ThreatChecker.exe -h>".green());
        std::process::exit(1);
    }


    match args.filetype.as_deref() {
        Some("bin") => match args.engine.as_deref() {
            Some("amsi") => amsihandler(args.targetfile.as_deref(), args.url.as_deref()).await,
            Some("defender") => defenderhandler(args.targetfile.as_deref(), args.url.as_deref()).await,
            Some("yara") => yarahandler(args.targetfile.as_deref(), args.url.as_deref(), args.yarafile.as_deref()).await,
            _ => eprintln!("[-] Error: Invalid Engine value for bin in filetype."),
        },
        Some("script") | Some(_) => amsihandler(args.targetfile.as_deref(), args.url.as_deref()).await,
        None => match args.engine.as_deref() {
            Some("amsi") => amsihandler(args.targetfile.as_deref(), args.url.as_deref()).await,
            Some("defender") => defenderhandler(args.targetfile.as_deref(), args.url.as_deref()).await,
            Some("yara") => yarahandler(args.targetfile.as_deref(), args.url.as_deref(), args.yarafile.as_deref()).await,
            _ => eprintln!("[-] Error: Invalid engine value."),
        },
    }
}

async fn amsihandler(targetfile: Option<&str>, url: Option<&str>) {

        let tf_string = targetfile.map(|s| s.to_string());
        let u1_string = url.map(|s| s.to_string());

        match checkinfile(&u1_string, &tf_string).await {
            Ok(targetfilebytes) => {
               // println!("checkinfile returned data: {:?}", targetfilebytes);

                amsi_analyze_bytes(&targetfilebytes);
            }
            Err(e) => {
                eprintln!("Error calling checkinfile function: {}", e);
            }
        }
}

async fn defenderhandler(targetfile: Option<&str>, url: Option<&str>) {
    let tf_string = targetfile.map(|s| s.to_string());
    let u1_string = url.map(|s| s.to_string());

    match checkinfile(&u1_string, &tf_string).await {
        Ok(targetfilebytes) => {
           // println!("checkinfile returned data: {:?}", targetfilebytes);

            defender_analyze_bytes(&targetfilebytes);
        }
        Err(e) => {
            eprintln!("Error calling checkinfile function: {}", e);
        }
    }
}

async fn yarahandler(targetfile: Option<&str>, url: Option<&str>, yarafile: Option<&str>) {

    let tf_string = targetfile.map(|s| s.to_string());
    let u1_string = url.map(|s| s.to_string());


    let targetfilebytes = match checkinfile(&u1_string, &tf_string).await {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error calling checkinfile function: {}", e);
            return;
        }
    };


    let yf_string = yarafile.map(|s| s.to_string());
    let yarafilebytes = read_yarafile_to_bytes(&yf_string);

    scan_with_yara(&targetfilebytes, &yarafilebytes);

}






