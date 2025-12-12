use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("all_rules.yar");
    
    let yara_dir = Path::new("..").join("yara");
    
    let mut all_rules = String::new();
    
    fn visit_dirs(dir: &Path, all_rules: &mut String) -> std::io::Result<()> {
        if dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    visit_dirs(&path, all_rules)?;
                } else if let Some(extension) = path.extension() {
                    if extension == "yar" || extension == "yara" {
                        if let Ok(content) = fs::read_to_string(&path) {
                            all_rules.push_str(&format!("// File: {}\n", path.display()));
                            all_rules.push_str(&content);
                            all_rules.push('\n');
                        }
                    }
                }
            }
        }
        Ok(())
    }

    if yara_dir.exists() {
        println!("cargo:rerun-if-changed={}", yara_dir.display());
        if let Err(e) = visit_dirs(&yara_dir, &mut all_rules) {
             println!("cargo:warning=Failed to read YARA rules: {}", e);
        }
    } else {
        println!("cargo:warning=YARA directory not found at {}", yara_dir.display());
    }

    if all_rules.is_empty() {
        all_rules.push_str("// No YARA rules found\n");
    }

    fs::write(&dest_path, all_rules).unwrap();
}
