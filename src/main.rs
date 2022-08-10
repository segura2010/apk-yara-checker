
use walkdir::WalkDir;

enum ProcessedFile {
    Done(),
}

fn compile_rules(rules_path: &str) -> Result<yara::Rules, yara::errors::YaraError> {
    let mut compiler = yara::Compiler::new().unwrap();
    compiler = compiler.add_rules_file(rules_path).unwrap();
    compiler.compile_rules()
}

fn process_apk(file_path: &str /*, rules: yara::Rules*/) {
    let fname = std::path::Path::new(file_path);
    if let Ok(apk_file) = std::fs::File::open(file_path) {
        if let Ok(mut archive) = zip::ZipArchive::new(apk_file) {
            for i in 0..archive.len() {
                let file = archive.by_index_raw(i).unwrap();
                if file.name().ends_with(".dex") {
                    println!("Found dex file {} in {}", file.name(), file_path);
                    //rules.scan_mem();
                }
            }
        } else {
            println!("Error: Unable to open APKZip file ({})", file_path);
        }
    } else {
        println!("Error: Unable to open APK file ({})", file_path);
    }
}

fn process_folder(path: &str, threads: usize) {
    let pool = threadpool::ThreadPool::new(threads);
    let (tx, rx) = std::sync::mpsc::channel::<ProcessedFile>();
    let mut file_counter = 0;

    for entry in WalkDir::new(path) {
        if let Ok(entry) = entry {
            let filename = entry.file_name().to_str().unwrap();
            if entry.file_type().is_file() {
                let entry_path = entry.path().to_str().unwrap().to_string();
                let tx = tx.clone();
                pool.execute(move|| {
                    // TODO: process apk
                    process_apk(&entry_path);
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
                .get_matches();

    let threads: usize = args.value_of("threads").unwrap_or("4").parse().unwrap();

    let mut rules: Option<yara::Rules> = None;
    if let Some(rules_file) = args.value_of("rules") {
        match compile_rules(rules_file) {
            Ok(rs) => { rules = Some(rs) },
            Err(e) => { println!("Error: {}", e) }
        }
    } else {
        println!("ERROR: You must provide path to yara rules file using '-r' argument!");
    }
    
    if let Some(path) = args.value_of("path") {
        println!("Processing files in {}", path);
        process_folder(path, threads);
    } else {
        println!("ERROR: You must provide path to folder with files to check using '-p' argument!");
    }
}
