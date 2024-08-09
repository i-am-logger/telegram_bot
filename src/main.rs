use anyhow::{Context, Result};
use clap::{command, Parser, Subcommand};
use dotenv::dotenv;
use env_logger::Builder;
use grammers_client::types::User;
use grammers_client::{Client, Config, SignInError};
use grammers_session::Session;
use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use log::*;
use directories::ProjectDirs;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Authenticate with Telegram")]
    Auth,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init();
    let client = connect().await?;
    info!("Connected to Telegram!");

    match &cli.command {
        Some(Commands::Auth) => {
            authenticate(&client).await?;
        }
        None => {
            let user = logged_in(&client).await?;
            start(&client, &user).await?;
        }
    }

    Ok(())
}

fn init() {
    dotenv().ok(); // This will load the .env file if it exists
    // Set up logging
    Builder::new()
        .filter(None, LevelFilter::Warn) // default log level
        .filter(Some("telegram_bot"), LevelFilter::Info)
        .init();
}

async fn connect() -> Result<Client> {
    let (api_id, api_hash) = get_api_credentials()?;
    debug!("API ID: {}", api_id);
    debug!("API Hash: {}", api_hash);
    info!("Starting Telegram client...");
    let session_file = get_session_file_path()?;
    debug!("Using session file: {:?}", session_file);

    // Create a new client
    let client = Client::connect(Config {
        api_id,
        api_hash: api_hash.clone(),
        session: Session::load_file_or_create(&session_file)?,
        params: Default::default(),
    })
    .await?;

    Ok(client)
}

async fn authenticate(client: &Client) -> Result<()> {
    let phone = read_line("Please enter your phone number (international format): ")?;
    let token = client.request_login_code(&phone).await?;
    let code = read_line("Please enter the code you received: ")?;
    
    match client.sign_in(&token, &code).await {
        Err(SignInError::PasswordRequired(password_token)) => {
            // 2FA is enabled, we need to provide the password
            let password = read_line("Please enter your 2FA password: ")?;
            client.check_password(password_token, password).await?;
            println!("Signed in successfully (with 2FA)!");
        }
        Err(e) => return Err(e.into()),
        Ok(_) => {
            println!("Signed in successfully!");
        }
    }
    let session_file = get_session_file_path()?;
    client.session().save_to_file(&session_file)?;
    println!("Session saved to: {:?}", session_file);
    Ok(())
}

async fn logged_in(client: &Client) -> Result<User> {
    if !client.is_authorized().await? {
        error!("Not authorized. Please run the authentication process first.");
        return Err(anyhow::anyhow!("Not Authorized"));
    }

    info!("Authorization confirmed. Proceeding with client operations.");

    let me = client.get_me().await?;
    info!("Logged in as: {}", me.username().unwrap_or("No username"));

    Ok(me)
}

async fn start(_client: &Client, me: &User) -> Result<()> {
    info!("I am : {}", me.full_name());
    Ok(())
}

fn get_session_file_path() -> Result<PathBuf> {
    let proj_dirs = ProjectDirs::from("com", "Logger", "Telegram_Bot")
        .context("Failed to get project directories")?;
    let data_dir = proj_dirs.data_dir();
    std::fs::create_dir_all(data_dir)?;
    Ok(data_dir.join("telegram.session"))
}

fn read_line(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

// Read API credentials from environment variables
fn get_api_credentials() -> Result<(i32, String)> {
    let api_id: i32 = env::var("API_ID")
        .context("API_ID not set")?
        .parse()
        .context("Failed to parse API_ID")?;
    let api_hash = env::var("API_HASH").context("API_HASH not set")?;

    Ok((api_id, api_hash))
}
