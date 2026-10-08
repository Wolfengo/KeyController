use std::{env, path::PathBuf, process::Command};
fn main() {
    println!("cargo:rerun-if-changed=src/harden.c");
    let library = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("harden.so");
    assert!(
        Command::new("cc")
            .args([
                "-shared",
                "-fPIC",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wl,-z,relro,-z,now",
                "-o"
            ])
            .arg(&library)
            .arg("src/harden.c")
            .status()
            .unwrap()
            .success()
    );
    // Only cfg(test)/debug_assertions may reference this compile-time path.
    // Production release code uses the package-owned installed library.
    println!(
        "cargo:rustc-env=SSH_KEYS_BUILD_HARDEN={}",
        library.display()
    );
}
