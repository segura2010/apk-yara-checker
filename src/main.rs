
use std::io::{Read, Write, Cursor};
use walkdir::WalkDir;

enum ProcessedFile {
    Done(),
}

fn parse_file_extension_filter(extensions: &str) -> Vec<String> {
    extensions.split(",").map(str::to_string).collect()
}

fn compile_rules_to_vec(rules: &str) -> Result<Vec<u8>, &str> {
    let mut compiler = yara::Compiler::new().unwrap();
    compiler = compiler.add_rules_file(rules).unwrap();
    match compiler.compile_rules() {
        Ok(mut rules) => { 
            let mut out_vec = Vec::new();
            let mut s = Cursor::new(Vec::new());
            rules.save_to_stream(s.get_mut());
            s.read_to_end(&mut out_vec);
            return Ok(out_vec);
        },
        Err(e) => { return Err("Error compiling rules!"); },
    }
}

fn load_rules_from_vec(rules: Vec<u8>) -> Result<yara::Rules, &'static str> {
    let mut s = Cursor::new(rules);
    match yara::Rules::load_from_stream(s) {
        Ok(mut rls) => { 
            return Ok(rls);
        },
        Err(e) => { return Err("Error loading rules!"); },
    }
}

fn process_apk(file_path: &str, rules: Vec<u8>, extension_filters: Vec<String>) {
    let fname = std::path::Path::new(file_path);
    if let Ok(apk_file) = std::fs::File::open(file_path) {
        if let Ok(mut archive) = zip::ZipArchive::new(apk_file) {
            for i in 0..archive.len() {
                let match_extension: bool = extension_filters[0].eq("*") || {
                    let com_file = archive.by_index_raw(i).unwrap();
                    let mut found = false;
                    for ex in extension_filters.iter() {
                        if com_file.name().ends_with(&format!(".{}", ex)) {
                            found = true; break;
                        }
                    }
                    found
                };
                if match_extension {
                    let mut decom_file = archive.by_index(i).unwrap();
                    let mut file_buff = Vec::with_capacity(1000000 * 20);
                    decom_file.read_to_end(&mut file_buff);
                    if let Ok(com_rules) = load_rules_from_vec(rules.clone()) {
                        if let Ok(matches) = com_rules.scan_mem(&file_buff, 60) {
                            let matched_rules: Vec<&str> = matches.iter().map(|r| r.identifier).collect();
                            println!("{} in {} -> Matches: {}. Rules: {:?}.", decom_file.name(), file_path, matches.len(), matched_rules);
                        }
                    } else {
                        println!("Error: Unable to compile rules!");
                    }
                }
            }
        } else {
            println!("Error: Unable to open APKZip file ({})", file_path);
        }
    } else {
        println!("Error: Unable to open APK file ({})", file_path);
    }
}

fn process_folder(path: &str, threads: usize, rules: Vec<u8>, extension_filters: Vec<String>) {
    let pool = threadpool::ThreadPool::new(threads);
    let (tx, rx) = std::sync::mpsc::channel::<ProcessedFile>();
    let mut file_counter = 0;

    for entry in WalkDir::new(path) {
        if let Ok(entry) = entry {
            let filename = entry.file_name().to_str().unwrap();
            if entry.file_type().is_file() {
                let entry_path = entry.path().to_str().unwrap().to_string();
                let tx = tx.clone();
                let rls = rules.clone();
                let ext_fil = extension_filters.clone();
                pool.execute(move|| {
                    process_apk(&entry_path, rls, ext_fil);
                    tx.send(ProcessedFile::Done());
                });
                file_counter += 1;
            }
        }
    }

    println!("Waiting to process {} files", file_counter);
    let mut processed_files = 0usize;
    loop {
        match rx.recv() {
            Ok(inf) => {
                match inf {
                    ProcessedFile::Done() => {
                        processed_files += 1;
                    },
                    _ => {
                    },
                }
            },
            Err(e) => {},
        }

        if processed_files >= file_counter {
            break;
        }
    }
}

fn main() {
    let args = clap::App::new("APK Yara checker")
                .version("0.1")
                .arg(clap::Arg::with_name("path")
                    .short("p")
                    .help("Path to folder which contains files to check")
                    .required(true)
                    .takes_value(true))
                .arg(clap::Arg::with_name("rules")
                    .short("r")
                    .help("Yara rule(s) file (.yar)")
                    .required(true)
                    .takes_value(true))
                .arg(clap::Arg::with_name("threads")
                    .short("t")
                    .help("Threads")
                    .required(false)
                    .takes_value(true))
                .arg(clap::Arg::with_name("extensions")
                    .short("x")
                    .help("File extensions inside APK to check rules (ej: -x dex,so,png). Use -x \"*\" to scan all files inside APK")
                    .required(false)
                    .takes_value(true))
                .get_matches();

    let threads: usize = args.value_of("threads").unwrap_or("4").parse().unwrap();
    let extensions: String = args.value_of("extensions").unwrap_or("dex,so").parse().unwrap();

    let extension_filters = parse_file_extension_filter(&extensions);

    let mut rules: Option<Vec<u8>> = None;
    if let Some(rules_file) = args.value_of("rules") {
        match compile_rules_to_vec(rules_file) {
            Ok(rs) => { rules = Some(rs) },
            Err(e) => { println!("Error: {}", e) }
        }
    } else {
        println!("ERROR: You must provide path to yara rules file using '-r' argument!");
        return;
    }
    
    if let Some(path) = args.value_of("path") {
        println!("Processing files in {}", path);
        if let Some(rls) = rules {
            process_folder(path, threads, rls, extension_filters);
        }
    } else {
        println!("ERROR: You must provide path to folder with files to check using '-p' argument!");
    }
}
