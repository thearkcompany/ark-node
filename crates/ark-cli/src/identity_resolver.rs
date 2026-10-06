//! Identity resolution policy conforming to ADR-0006:
//! 1. `--identity <path>` CLI option
//! 2. `ARK_IDENTITY_KEY` environment variable
//! 3. Default path `~/.ark/identity.key`
//! 4. Ephemeral in-memory identity for the lifecycle of the session

use ark_crypto::identity::PersistentIdentity;
use std::path::{Path, PathBuf};


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedIdentitySource {
    Cli,
    Env,
    DefaultHome,
    Ephemeral,
}

/// Resolves the default home path for identity keys: `~/.ark/identity.key`
pub fn get_default_identity_path() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".ark").join("identity.key"))
}

/// Resolves the node identity following ADR-0006 priority
pub fn resolve_identity(
    cli_identity: Option<&Path>,
    env_identity: Option<&str>,
    default_path: Option<&Path>,
) -> anyhow::Result<(PersistentIdentity, ResolvedIdentitySource)> {
    // 1. Explicit CLI flag
    if let Some(path) = cli_identity {
        let id = PersistentIdentity::load_from_file(path)
            .map_err(|e| anyhow::anyhow!("Failed to load identity from CLI flag {:?}: {}", path, e))?;
        return Ok((id, ResolvedIdentitySource::Cli));
    }

    // 2. ARK_IDENTITY_KEY environment variable
    if let Some(env_val) = env_identity {
        if !env_val.trim().is_empty() {
            let path = Path::new(env_val);
            let id = PersistentIdentity::load_from_file(path)
                .map_err(|e| anyhow::anyhow!("Failed to load identity from ARK_IDENTITY_KEY {:?}: {}", path, e))?;
            return Ok((id, ResolvedIdentitySource::Env));
        }
    }

    // 3. Default path (~/.ark/identity.key)
    if let Some(path) = default_path {
        if path.exists() {
            let id = PersistentIdentity::load_from_file(path)
                .map_err(|e| anyhow::anyhow!("Failed to load default identity from {:?}: {}", path, e))?;
            return Ok((id, ResolvedIdentitySource::DefaultHome));
        }
    }

    // 4. Fallback to ephemeral in-memory identity
    let mut rng = rand::rngs::OsRng;
    let id = PersistentIdentity::generate(&mut rng);
    Ok((id, ResolvedIdentitySource::Ephemeral))
}
