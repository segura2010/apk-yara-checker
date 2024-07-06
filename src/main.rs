
use std::io::{Read, Cursor};
use walkdir::WalkDir;

enum ProcessedFile {
    Done(),
}

fn parse_file_extension_filter(extensions: &str) -> Vec<String> {
    extensions.split(',').map(str::to_string).collect()
}

fn compile_rules_to_vec(rules_file: &str) -> Result<Vec<u8>, String> {
    let rules = std::fs::read(rules_file).unwrap();
    let mut compiler = yara_x::Compiler::new();
    compiler.add_source(rules.as_slice()).unwrap();
    let rules = compiler.build();
    match rules.serialize() {
        Ok(rs) => { return Ok(rs); },
        Err(e) => { return Err(format!("Error saving rules to stream! {}", e)); },
    }
}

fn load_rules_from_vec(rules: Vec<u8>) -> Result<yara_x::Rules, String> {
    let s = Cursor::new(rules);
    match yara_x::Rules::deserialize_from(s) {
        Ok(rls) => { 
            Ok(rls)
        },
        Err(e) => { Err(format!("Error loading rules! {}", e)) },
    }
}

fn process_apk(file_path: &str, rules: Vec<u8>, extension_filters: Vec<String>) {
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
                    if let Err(e) = decom_file.read_to_end(&mut file_buff) {
                        println!("Error: {}", e);
                    } else if let Ok(com_rules) = load_rules_from_vec(rules.clone()) {
                        let mut scanner = yara_x::Scanner::new(&com_rules);
                        if let Ok(result) = scanner.scan(&file_buff) {
                            let matched_rules: Vec<&str> = result.matching_rules().map(|r| r.identifier()).collect();
                            println!("{} in {} -> Matches: {}. Rules: {:?}.", decom_file.name(), file_path, result.matching_rules().len(), matched_rules);
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
            if entry.file_type().is_file() {
                let entry_path = entry.path().to_str().unwrap().to_string();
                let tx = tx.clone();
                let rls = rules.clone();
                let ext_fil = extension_filters.clone();
                pool.execute(move|| {
                    process_apk(&entry_path, rls, ext_fil);
                    let _ = tx.send(ProcessedFile::Done());
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
                }
            },
            Err(_) => {},
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
