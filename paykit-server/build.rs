use std::{env, error::Error, fs, path::Path};

fn valid_source_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-env-changed=SOURCE_SHA");
    println!("cargo:rerun-if-env-changed=PAYKIT_SOURCE_SHA");

    let profile = env::var("PROFILE")?;
    let source_sha = env::var("SOURCE_SHA")
        .or_else(|_| env::var("PAYKIT_SOURCE_SHA"))
        .or_else(|_| {
            if profile == "debug" {
                Ok(String::from("dev-local"))
            } else {
                Err(env::VarError::NotPresent)
            }
        })?;

    if source_sha != "dev-local" && !valid_source_sha(&source_sha) {
        return Err(format!(
            "SOURCE_SHA must be exactly 40 hexadecimal characters, got {source_sha:?}"
        )
        .into());
    }
    if profile != "debug" && source_sha == "dev-local" {
        return Err("SOURCE_SHA is required for non-debug builds".into());
    }

    let out_dir = env::var_os("OUT_DIR").ok_or("OUT_DIR is not set")?;
    let metadata_path = Path::new(&out_dir).join("build_metadata.rs");
    fs::write(
        metadata_path,
        format!("pub const SOURCE_SHA: &str = {source_sha:?};\n"),
    )?;
    println!("cargo:rustc-env=PAYKIT_SOURCE_SHA={source_sha}");
    Ok(())
}
