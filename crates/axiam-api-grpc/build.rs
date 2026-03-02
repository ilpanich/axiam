fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(false)
        .compile_protos(
            &[
                "../../proto/axiam/v1/authorization.proto",
                "../../proto/axiam/v1/user.proto",
                "../../proto/axiam/v1/token.proto",
            ],
            &["../../proto"],
        )?;
    Ok(())
}
