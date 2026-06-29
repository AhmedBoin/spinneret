use spinneret::{run, LoomConfig, LoomCtx};
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;

/// Spinneret Loom Server
///
/// Usage:
///     RUST_LOG=info ./target/release/spinneret-loom [path/to/loom.toml]
///
/// If np path giver, searches for loom.toml next to the binary or in cwd

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = match std::env::args().nth(1) {
        Some(p) => {
            info!("loading config: {}", p);
            LoomConfig::from_file(&p)?
        }
        None => {
            info!("auto-locating loom.toml");
            LoomConfig::load()?
        }
    };

    // Set unix permissions on db directory
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let db_path_s = config.resolved_db_path();
        let db_dir = std::path::Path::new(&db_path_s)
            .parent()
            .unwrap_or(std::path::Path::new("."));
        std::fs::create_dir_all(db_dir).ok();
        let _ = std::fs::set_permissions(db_dir, std::fs::Permissions::from_mode(0o755));
        if let Ok(exe) = std::env::current_exe() {
            let _ = std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755));
        }
    }

    info!("Spinneret Loom v{}", spinneret::VERSION);
    run(Arc::new(LoomCtx::new(config)?)).await?;
    Ok(())
}
