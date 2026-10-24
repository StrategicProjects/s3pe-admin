//! `s3pe-admin`: a small, secure web console for a Garage object store.
//!
//! Buckets, keys and permissions through Garage's administration API, behind
//! passkey (WebAuthn) sign-in, with an audit log. One binary, no runtime
//! dependencies, listening on localhost behind a reverse proxy.

use s3pe_admin::{db, invite, state, web};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::net::SocketAddr;

#[derive(Parser)]
#[command(
    name = "s3pe-admin",
    version,
    about = "Web console for a Garage object store: buckets, keys, permissions, audit"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the web server (configuration from the environment)
    Serve,
    /// Create a one-time invitation link for a new administrator
    Invite {
        name: String,
        email: String,
        /// Validity in hours
        #[arg(long, default_value_t = 24)]
        hours: i64,
    },
    /// List administrators and pending invitations
    Admins,
    /// Disable an administrator (sessions are closed; the passkeys stay but cannot sign in)
    Disable { email: String },
    /// Enable a disabled administrator
    Enable { email: String },
    /// Check the connection to the Garage administration API
    Check,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .init();
    let cli = Cli::parse();
    let cfg = state::Config::from_env()?;
    let db = db::Db::open(&cfg.db_path)?;
    let app = state::AppState::new(cfg, db)?;

    match cli.command {
        Command::Serve => serve(app).await,
        Command::Invite { name, email, hours } => {
            let (url, invite) = invite::create(&app, &name, &email, "cli", hours)?;
            app.db.audit(
                "cli",
                "admin.invited",
                &invite.email,
                serde_json::json!({ "name": invite.name, "expires_at": invite.expires_at }),
                "local",
            )?;
            println!("Invitation for {} <{}>, valid until {} (open it in the browser of the person invited; it works once):\n\n{url}\n", invite.name, invite.email, invite.expires_at);
            Ok(())
        }
        Command::Admins => {
            for a in app.db.admins()? {
                let n = app.db.passkeys_of(&a.id)?.len();
                println!(
                    "{:<30} {:<40} {} passkey(s){}",
                    a.name,
                    a.email,
                    n,
                    if a.disabled { "  [disabled]" } else { "" }
                );
            }
            for i in app
                .db
                .invites()?
                .into_iter()
                .filter(|i| i.used_at.is_none())
            {
                println!(
                    "invite  {:<22} {:<40} expires {}",
                    i.name, i.email, i.expires_at
                );
            }
            Ok(())
        }
        Command::Disable { email } => set_disabled(&app, &email, true),
        Command::Enable { email } => set_disabled(&app, &email, false),
        Command::Check => {
            let h = app.garage.health().await?;
            println!(
                "Garage at {}: {} ({} of {} nodes connected, {} partitions ok of {})",
                app.cfg.garage_url,
                h.status,
                h.connected_nodes,
                h.known_nodes,
                h.partitions_all_ok,
                h.partitions
            );
            let buckets = app.garage.list_buckets().await?;
            println!(
                "{} bucket(s): {}",
                buckets.len(),
                buckets
                    .iter()
                    .map(|b| b.global_aliases.join("/"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            Ok(())
        }
    }
}

fn set_disabled(app: &state::App, email: &str, disabled: bool) -> Result<()> {
    let a = app
        .db
        .admin_by_email(email)?
        .context("no such administrator")?;
    app.db.set_admin_disabled(&a.id, disabled)?;
    app.db.audit(
        "cli",
        if disabled {
            "admin.disabled"
        } else {
            "admin.enabled"
        },
        &a.email,
        serde_json::json!({}),
        "local",
    )?;
    println!(
        "{} {}",
        a.email,
        if disabled { "disabled" } else { "enabled" }
    );
    Ok(())
}

async fn serve(app: state::App) -> Result<()> {
    app.db.purge_expired()?;
    let bind: SocketAddr = app
        .cfg
        .bind
        .parse()
        .with_context(|| format!("S3PE_ADMIN_BIND={}", app.cfg.bind))?;
    let router = web::router(app.clone());
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(
        "s3pe-admin listening on http://{bind}{}/ (origin {}, Garage {})",
        app.cfg.base,
        app.cfg.origin,
        app.cfg.garage_url
    );
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(())
}
