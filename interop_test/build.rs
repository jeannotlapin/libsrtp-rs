fn main() {
    cc::Build::new()
        .file("src/srtp_helper.c")
        .include("/usr/include")
        .compile("srtp_helper");
    println!("cargo:rustc-link-lib=srtp2");
    /* For custom path libsrtp2
    // Add the library search path
    let lib_path = "<path to the srtp2 library's directory>";
    println!("cargo:rustc-link-search=native={}", lib_path);
    println!("cargo:rustc-link-lib=srtp2");

    // Embed the library path in the binary
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib_path);
    */
}
