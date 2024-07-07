use clap::{Parser};



const ASCII_ART: &str = r#"ThreatChecker-rust version: threatchecker-rs/0.0.1
████████ ██   ██ ██████  ███████  █████  ████████  ██████ ██   ██ ███████  ██████ ██   ██ ███████ ██████
   ██    ██   ██ ██   ██ ██      ██   ██    ██    ██      ██   ██ ██      ██      ██  ██  ██      ██   ██
   ██    ███████ ██████  █████   ███████    ██    ██      ███████ █████   ██      █████   █████   ██████
   ██    ██   ██ ██   ██ ██      ██   ██    ██    ██      ██   ██ ██      ██      ██  ██  ██      ██   ██
   ██    ██   ██ ██   ██ ███████ ██   ██    ██     ██████ ██   ██ ███████  ██████ ██   ██ ███████ ██   ██--rust
   Analyze malicious files and identify bad bytes
   "#;

#[derive(Parser, Debug)]
#[command(author="zz1gg",name="ThreatChecker-rust", bin_name="ThreatChecker", version="0.0.1", about=ASCII_ART)]
pub struct Args {

    ///Scanning engine. Options: defender or amsi or yara
    #[arg(long, short = 'e',default_value = "amsi")]
    pub engine: Option<String>,

    ///Filepath, analyze a file on disk
    #[arg(long, short = 'f')]
    pub targetfile: Option<String>,

    /// File type to scan. Options: bin or script
    #[arg(long, short = 't')]
    pub filetype: Option<String>,
    ///FileURL, analyze a file from a URL
    #[arg(long, short = 'u')]
    pub url: Option<String>,

    ///YaraFile, Specify the Yara file for analysis
    #[arg(long, short = 'y')]
    pub yarafile: Option<String>,


    //#[arg(long, short = 'v')]
   // pub verbose: Option<String>,
}




