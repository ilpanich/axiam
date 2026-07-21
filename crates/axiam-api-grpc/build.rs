fn main() -> Result<(), Box<dyn std::error::Error>> {
    let build_client = std::env::var("CARGO_FEATURE_CLIENT").is_ok();
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(build_client)
        .compile_protos(
            &[
                "../../proto/axiam/v1/authorization.proto",
                "../../proto/axiam/v1/user.proto",
                "../../proto/axiam/v1/token.proto",
                "../../proto/axiam/v1/userinfo.proto",
            ],
            &["../../proto"],
        )?;
    Ok(())
}
