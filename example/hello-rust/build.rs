use protobuf_codegen::Codegen;

fn main() {
    Codegen::new()
        .out_dir("src/proto")
        .include("proto")
        .inputs(&["proto/hello.proto"])
        .run_from_script();
}
