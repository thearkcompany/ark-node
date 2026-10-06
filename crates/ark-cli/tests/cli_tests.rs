use ark_cli::commands::{Cli, Commands, Role};
use clap::Parser;

#[test]
fn test_cli_parsing_keygen() {
    let cli = Cli::try_parse_from(["ark-node", "keygen"]).unwrap();
    match cli.command {
        Some(Commands::Keygen { out }) => assert!(out.is_none()),
        _ => panic!("Expected Keygen subcommand"),
    }

    let cli_with_out = Cli::try_parse_from(["ark-node", "keygen", "--out", "/tmp/id.key"]).unwrap();
    match cli_with_out.command {
        Some(Commands::Keygen { out }) => assert_eq!(out, Some("/tmp/id.key".into())),
        _ => panic!("Expected Keygen subcommand with out"),
    }
}

#[test]
fn test_cli_parsing_status() {
    let cli = Cli::try_parse_from(["ark-node", "status"]).unwrap();
    assert!(matches!(cli.command, Some(Commands::Status)));
}

#[test]
fn test_cli_parsing_ping() {
    let cli = Cli::try_parse_from(["ark-node", "ping", "--target", "127.0.0.1:8443"]).unwrap();
    match cli.command {
        Some(Commands::Ping { target }) => assert_eq!(target, "127.0.0.1:8443"),
        _ => panic!("Expected Ping subcommand"),
    }
}

#[test]
fn test_cli_parsing_daemon_options() {
    let cli = Cli::try_parse_from([
        "ark-node",
        "--role",
        "relay",
        "--bind",
        "127.0.0.1:9000",
        "--identity",
        "/etc/ark/identity.key",
    ])
    .unwrap();

    assert_eq!(cli.role, Role::Relay);
    assert_eq!(cli.bind, "127.0.0.1:9000");
    assert_eq!(cli.identity, Some("/etc/ark/identity.key".into()));
    assert!(cli.command.is_none());
}
