fn main() {
    println!("cargo:rustc-check-cfg=cfg(host_test)");
    if std::env::var("CARGO_FEATURE_HOST_TEST").is_ok() {
        println!("cargo:rustc-cfg=host_test");
    }
}
