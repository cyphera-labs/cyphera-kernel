fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let linker_script = format!("{crate_dir}/linker.ld");
    println!("cargo:rerun-if-changed={linker_script}");
    println!("cargo:rerun-if-changed=src/main.rs");
    println!("cargo:rustc-link-arg=-T{linker_script}");
}
