use ark_cli::identity_resolver::{resolve_identity, ResolvedIdentitySource};
use ark_crypto::identity::PersistentIdentity;
use rand::rngs::OsRng;
use std::fs;

#[test]
fn test_resolve_identity_precedence() {
    let temp_dir = std::env::temp_dir().join(format!("ark_res_test_{}", rand::random::<u64>()));
    fs::create_dir_all(&temp_dir).unwrap();

    let cli_path = temp_dir.join("cli.key");
    let env_path = temp_dir.join("env.key");
    let home_path = temp_dir.join("home.key");

    let mut rng = OsRng;
    let cli_id = PersistentIdentity::generate(&mut rng);
    cli_id.save_to_file(&cli_path).unwrap();

    let env_id = PersistentIdentity::generate(&mut rng);
    env_id.save_to_file(&env_path).unwrap();

    let home_id = PersistentIdentity::generate(&mut rng);
    home_id.save_to_file(&home_path).unwrap();

    // 1. CLI flag specified -> returns CLI identity
    let (res_cli, src_cli) = resolve_identity(
        Some(&cli_path),
        Some(env_path.to_str().unwrap()),
        Some(&home_path),
    ).expect("Resolution failed");
    assert_eq!(res_cli.ark_id, cli_id.ark_id);
    assert_eq!(src_cli, ResolvedIdentitySource::Cli);

    // 2. No CLI flag, but env var specified -> returns Env identity
    let (res_env, src_env) = resolve_identity(
        None,
        Some(env_path.to_str().unwrap()),
        Some(&home_path),
    ).expect("Resolution failed");
    assert_eq!(res_env.ark_id, env_id.ark_id);
    assert_eq!(src_env, ResolvedIdentitySource::Env);

    // 3. Neither CLI nor env, but ~/.ark/identity.key exists -> returns DefaultHome identity
    let (res_home, src_home) = resolve_identity(
        None,
        None,
        Some(&home_path),
    ).expect("Resolution failed");
    assert_eq!(res_home.ark_id, home_id.ark_id);
    assert_eq!(src_home, ResolvedIdentitySource::DefaultHome);

    // 4. Default home file does not exist -> returns Ephemeral identity
    let missing_home_path = temp_dir.join("nonexistent.key");
    let (res_ephemeral, src_ephemeral) = resolve_identity(
        None,
        None,
        Some(&missing_home_path),
    ).expect("Resolution failed");
    assert_eq!(src_ephemeral, ResolvedIdentitySource::Ephemeral);
    assert_ne!(res_ephemeral.ark_id, [0u8; 32]);

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}
