fn main() {
    println!("cargo:rerun-if-changed=../../proto/ark_worker.proto");

    // Use hermetically vendored protoc binary (no system protoc needed)
    let protoc_path =
        protoc_bin_vendored::protoc_bin_path().expect("Failed to locate vendored protoc binary");
    std::env::set_var("PROTOC", protoc_path);

    let mut config = prost_build::Config::new();
    config
        .compile_protos(&["../../proto/ark_worker.proto"], &["../../proto"])
        .expect("Failed to compile worker protobuf schema");
}
