fn main() {
    println!("cargo:rerun-if-changed=../../proto/ark_envelope.proto");

    // Use hermetically vendored protoc binary (no C compiler or cmake needed)
    let protoc_path = protoc_bin_vendored::protoc_bin_path()
        .expect("Failed to locate vendored protoc binary");
    std::env::set_var("PROTOC", protoc_path);

    let mut config = prost_build::Config::new();
    config
        .compile_protos(&["../../proto/ark_envelope.proto"], &["../../proto"])
        .expect("Failed to compile protobuf schemas hermetically");
}
