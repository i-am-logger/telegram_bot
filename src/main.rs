use anyhow::{Context, Result};
use clap::{command, Parser, Subcommand};
use dotenv::dotenv;
use env_logger::Builder;
use grammers_client::types::media::Document;
use grammers_client::types::{Chat, Downloadable, Media, User};
use grammers_client::{Client, Config, SignInError};
use grammers_session::Session;
use tokio::fs;
use tokio::time::sleep;
use std::io::{self, Write};
use std::path::PathBuf;
use log::*;
use directories::ProjectDirs;
use serde::Deserialize;

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
#[derive(Deserialize, Debug)]
struct EnvConfig {
    api_id: i32,
    api_hash: String,
    save_dir: String,
    channel_name: String,
}


const TELEGRAM_SESSION_FILENAME: &str = "telegram.session";
const CHANNEL_STATE_FILENAME_SUFFIX: &str = "state.txt";

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = init()?;
    let client = connect(&config).await?;
    info!("Connected to Telegram!");

    match &cli.command {
        Some(Commands::Auth) => {
            authenticate(&client).await?;
        }
        None => {
            let user = logged_in(&client).await?;
            start(config, &client, &user).await?;
        }
    }

    Ok(())
}

fn init() -> Result<EnvConfig> { 
    dotenv().ok(); // This will load the .env file if it exists
    // Set up logging
    Builder::new()
        .filter(None, LevelFilter::Warn) // default log level
        .filter(Some("telegram_bot"), LevelFilter::Info)
        .init();

    let config = envy::from_env::<EnvConfig>()?;
    Ok(config)
}

async fn connect(config: &EnvConfig) -> Result<Client> {
    debug!("API ID: {}", config.api_id);
    debug!("API Hash: {}", config.api_hash);
    info!("Starting Telegram client...");
    let session_file = get_data_file_path(TELEGRAM_SESSION_FILENAME)?;
    debug!("Using session file: {:?}", session_file);

    // Create a new client
    let client = Client::connect(Config {
        api_id: config.api_id,
        api_hash: config.api_hash.clone(),
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
    let session_file = get_data_file_path(TELEGRAM_SESSION_FILENAME)?;
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

async fn start(config: EnvConfig, client: &Client, me: &User) -> Result<()> {
    info!("I am : {}", me.full_name());
    let channel_name = config.channel_name.as_str();
    let chat = client.resolve_username(channel_name).await?
        .context(format!("Failed to resolve channel: {}", channel_name))?;
    process_messages(client, &chat ,channel_name, config.save_dir ).await?;
    Ok(())
}

async fn process_messages(client: &Client, channel: &Chat, channel_name: &str, save_dir: String) -> Result<()> {
    info!("Monitoring chat: {}", channel_name);
    let mut offset_id:i32 = read_channel_state(&channel_name).await?;
    loop {
        
        let mut messages = client.iter_messages(channel).limit(50);
        let mut new_messages = Vec::new();
        
        while let Some(message) = messages.next().await? {
            if message.id() <= offset_id {
                debug!("read it all... {}", offset_id);
                break;
            }

            new_messages.push(message);
        }
        for message in new_messages.into_iter().rev() {
            
            message.mark_as_read().await?;
            match message.media() {
                Some(Media::Document(document)) => {
                    info!("File received - Type: {}, Name: {}, Size: {} bytes, ID: {}", 
                        document.mime_type().unwrap_or("Unknown"),
                        document.name(),
                        document.size(),
                        message.id());

                    save_file(client, &document,&save_dir).await?;
                    info!("File saved...") 
                }
                _ => {
                    info!("Type: {:?}, Message: {}, id: {}", message.media(), message.text(), message.id());
                },
            }
            offset_id = message.id();
        }
        write_channel_state(channel_name,offset_id).await?;
        sleep(std::time::Duration::from_secs(5)).await;
    }
}
fn get_data_file_path(filename: &str) -> Result<PathBuf> {
    let proj_dirs = ProjectDirs::from("com", "Logger", "Telegram_Bot")
        .context("Failed to get project directories")?;
    let data_dir = proj_dirs.data_dir();
    std::fs::create_dir_all(data_dir)?;
    Ok(data_dir.join(filename))
}

async fn read_channel_state(channel_name: &str) -> Result<i32> {
    let filename  = format!("{}{}",CHANNEL_STATE_FILENAME_SUFFIX, channel_name);
    let path = get_data_file_path(&filename)?;
    if !path.exists() {
        return Ok(0);
    }

    let content = fs::read_to_string(path).await?;
    Ok(content.trim().parse()?)
}

async fn write_channel_state(channel_name: &str, state: i32) -> Result<()> {
    let filename  = format!("{}{}",CHANNEL_STATE_FILENAME_SUFFIX, channel_name);
    let path = get_data_file_path(&filename)?;
    fs::write(path, state.to_string()).await?;
    Ok(())
}

fn read_line(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

async fn save_file(client: &Client, document: &Document, save_dir: &String) -> Result<()> {
    let save_path = PathBuf::from(save_dir).join(&document.name());

    if let Some(parent) = save_path.parent() {
        fs::create_dir_all(parent).await?;
    }

    let media = Media::Document(document.clone());
    let download_file = Downloadable::Media(media);
    client.download_media(&download_file, save_path).await?;

    Ok(())
}
