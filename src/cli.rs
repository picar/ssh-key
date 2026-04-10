use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ssh-key")]
#[command(about = "CLI and API server to manage ssh-agent and ssh keys")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Manage ssh-agent processes
    Agent {
        #[command(subcommand)]
        command: AgentCommands,
    },
    /// Create a new SSH key pair
    Create {
        /// Output file path (without extension; .pub is added for the public key)
        #[arg(short, long)]
        output: Option<String>,
        /// Key type
        #[arg(short = 't', long = "type", default_value = "ed25519")]
        key_type: crate::key::KeyType,
        /// Comment to embed in the key
        #[arg(short = 'C', long)]
        comment: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum KeyCommands {
    /// List keys loaded in the agent
    List {
        /// PID of the agent to query (defaults to $SSH_AUTH_SOCK)
        #[arg(long)]
        pid: Option<u32>,
    },
    /// Add a private key file to the agent
    Add {
        /// Path to the private key file
        #[arg(long)]
        key: String,
        /// PID of the agent to target (auto-detected if only one is running)
        #[arg(long)]
        pid: Option<u32>,
    },
    /// Remove a private key from the agent
    Remove {
        /// Path to the private key file to remove
        #[arg(long)]
        key: String,
        /// PID of the agent to target (auto-detected if only one is running)
        #[arg(long)]
        pid: Option<u32>,
    },
}

#[derive(Subcommand)]
pub enum AgentCommands {
    /// List all running ssh-agent processes
    List,
    /// Start a new ssh-agent process
    Start {
        /// Suppress output after starting the agent
        #[arg(long)]
        quiet: bool,
    },
    /// Manage keys in a running ssh-agent
    Key {
        #[command(subcommand)]
        command: KeyCommands,
    },
    /// Stop one or all ssh-agent processes
    Stop {
        /// PID of the ssh-agent process to stop
        #[arg(long, conflicts_with = "all", required_unless_present = "all")]
        pid: Option<u32>,
        /// Stop all running ssh-agent processes
        #[arg(long, conflicts_with = "pid")]
        all: bool,
    },
}
