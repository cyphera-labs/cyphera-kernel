fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let linker_script = format!("{crate_dir}/linker.ld");
    println!("cargo:rerun-if-changed={linker_script}");
    println!("cargo:rustc-link-arg=-T{linker_script}");

    println!("cargo:rustc-check-cfg=cfg(coverage)");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let sine_path = std::path::Path::new(&out_dir).join("sine_table.rs");
    let mut body = String::from("const SINE_TABLE: [i16; 1024] = [\n");
    for i in 0..1024 {
        let x = (i as f64) * core::f64::consts::TAU / 1024.0;
        let v = (x.sin() * 32767.0).round();
        let v = v.clamp(-32768.0, 32767.0) as i16;
        body.push_str(&format!("    {},\n", v));
    }
    body.push_str("];\n");
    std::fs::write(&sine_path, body).expect("write sine_table.rs");

    let workspace_root = std::path::Path::new(&crate_dir)
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root not found");
    let target_debug = workspace_root.join("target/x86_64-unknown-none/debug");

    let userland_bundle = workspace_root.join("bundles/userland");
    println!("cargo:rerun-if-changed={}", userland_bundle.display());
    if userland_bundle.exists() {
        let entries = std::fs::read_dir(&userland_bundle).expect("read bundles/userland");
        for entry in entries.flatten() {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let file_name = entry.file_name();
            let name = match file_name.to_str() {
                Some(s) => s,
                None => continue,
            };
            let is_proc_binary = name == "hello" || name.starts_with("proc_");
            if !is_proc_binary {
                continue;
            }
            let var = if name == "hello" {
                "HELLO_ELF_PATH".to_string()
            } else {
                format!("{}_ELF_PATH", name.to_uppercase())
            };
            let path = entry.path();
            println!("cargo:rustc-env={}={}", var, path.display());
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }

    let script = workspace_root.join("tools/mk-ext4-img.sh");
    let img = target_debug.join("ext4-fixture.img");
    println!("cargo:rerun-if-changed={}", script.display());
    if let Some(parent) = img.parent() {
        std::fs::create_dir_all(parent).expect("create target dir for ext4 fixture");
    }
    let status = std::process::Command::new("bash")
        .arg(&script)
        .arg(&img)
        .status();
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => panic!("mk-ext4-img.sh exited with {s}"),
        Err(e) => panic!("failed to spawn mk-ext4-img.sh: {e}"),
    }
    println!("cargo:rustc-env=EXT4_FIXTURE_PATH={}", img.display());
    println!("cargo:rerun-if-changed={}", img.display());
}
