use std::path::PathBuf;

fn main() {
    let crate_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let output_path = crate_dir.join("include/pnp.h");

    let status = std::process::Command::new("cbindgen")
        .arg("--crate")
        .arg("pnp-ffi")
        .arg("-c")
        .arg(crate_dir.join("cbindgen.toml"))
        .arg("-o")
        .arg(&output_path)
        .current_dir(&crate_dir)
        .status();

    match status {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!("cargo:warning=cbindgen exited with {}", s),
        Err(e) => eprintln!("cargo:warning=cbindgen not found: {}", e),
    }

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");
}
