mod auth;
mod config;
mod protocol;

use bytes::BytesMut;
use config::CONFIG;
use protocol::{
    build_auth_ok, build_auth_request, build_error, build_password_message, is_ssl_request,
    parse_password, Message, StartupMessage, AUTH_CLEARTEXT, MSG_AUTH_REQUEST, MSG_ERROR, MSG_READY,
};
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn, Level};

fn main() {
    // Initialize tracing first
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_target(false)
        .with_ansi(false)
        .init();

    println!("Starting ECDSA Postgres Proxy...");

    // Build runtime and run
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime");

    rt.block_on(async_main()).expect("Server error");
}

async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    // Force config initialization
    let _ = &*CONFIG;

    info!(
        "ECDSA Postgres Proxy starting on {}",
        CONFIG.proxy_addr
    );
    info!(
        "Upstream Postgres: {}:{}",
        CONFIG.pg_host, CONFIG.pg_port
    );
    info!(
        "Allowed address: 0x{}",
        hex::encode(CONFIG.allowed_address)
    );

    let listener = TcpListener::bind(CONFIG.proxy_addr).await?;

    loop {
        let (socket, addr) = listener.accept().await?;
        info!("New connection from {}", addr);
        
        tokio::spawn(async move {
            if let Err(e) = handle_client(socket).await {
                error!("Connection error from {}: {}", addr, e);
            }
            info!("Connection closed for {}", addr);
        });
    }
}

async fn handle_client(mut client: TcpStream) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = vec![0u8; 8192];

    // Read startup message
    let n = client.read(&mut buf).await?;
    if n < 8 {
        return Err("Invalid startup message".into());
    }

    // Check for SSL request
    let startup_data = if is_ssl_request(&buf[..n]) {
        // Reject SSL
        client.write_all(b"N").await?;
        // Read actual startup message
        let n = client.read(&mut buf).await?;
        &buf[..n]
    } else {
        &buf[..n]
    };

    // Parse startup message
    let startup = StartupMessage::parse(startup_data)?;
    let user = startup.params.get("user").cloned().unwrap_or_default();
    let database = startup
        .params
        .get("database")
        .cloned()
        .unwrap_or_else(|| CONFIG.pg_database.clone());

    info!("Auth attempt: user={}, database={}", user, database);

    // Request password
    client.write_all(&build_auth_request(AUTH_CLEARTEXT)).await?;

    // Read password message
    let n = client.read(&mut buf).await?;
    let password = parse_password(&buf[..n])?;

    // Verify ECDSA signature
    if let Err(e) = auth::verify_signature(&user, &password) {
        warn!("Auth failed for {}: {}", user, e);
        client.write_all(&build_error(&e.to_string(), "28P01")).await?;
        return Ok(());
    }

    info!("Auth succeeded for {}, connecting to Postgres...", user);

    // Send auth OK to client
    client.write_all(&build_auth_ok()).await?;

    // Connect to real Postgres
    let pg_addr = format!("{}:{}", CONFIG.pg_host, CONFIG.pg_port);
    let mut pg_conn = TcpStream::connect(&pg_addr).await?;

    // Build startup message for Postgres with service account
    let mut params = HashMap::new();
    params.insert("user", CONFIG.pg_user.as_str());
    params.insert("database", database.as_str());
    let app_name = format!("ecdsa-proxy:{}", user);
    params.insert("application_name", app_name.as_str());

    pg_conn.write_all(&StartupMessage::build(&params)).await?;

    // Handle Postgres auth
    loop {
        let msg = read_message(&mut pg_conn).await?;
        
        if msg.msg_type == MSG_AUTH_REQUEST {
            if let Some(auth_type) = msg.auth_type() {
                match auth_type {
                    0 => break, // Auth OK
                    3 => {
                        // Cleartext password
                        pg_conn
                            .write_all(&build_password_message(&CONFIG.pg_password))
                            .await?;
                    }
                    5 => {
                        error!("MD5 auth not supported, configure Postgres with trust auth");
                        return Err("MD5 auth not supported".into());
                    }
                    _ => {
                        error!("Unsupported auth type: {}", auth_type);
                        return Err(format!("Unsupported auth type: {}", auth_type).into());
                    }
                }
            }
        } else if msg.msg_type == MSG_ERROR {
            error!("Postgres auth error");
            // Forward error to client
            let mut response = BytesMut::with_capacity(1 + 4 + msg.data.len());
            response.extend_from_slice(&[msg.msg_type]);
            response.extend_from_slice(&((4 + msg.data.len()) as i32).to_be_bytes());
            response.extend_from_slice(&msg.data);
            client.write_all(&response).await?;
            return Ok(());
        }
    }

    // Forward parameter status and other messages until ReadyForQuery
    loop {
        let msg = read_message(&mut pg_conn).await?;
        
        // Forward to client
        let mut response = BytesMut::with_capacity(1 + 4 + msg.data.len());
        response.extend_from_slice(&[msg.msg_type]);
        response.extend_from_slice(&((4 + msg.data.len()) as i32).to_be_bytes());
        response.extend_from_slice(&msg.data);
        client.write_all(&response).await?;

        if msg.msg_type == MSG_READY {
            break;
        }
    }

    info!("Connection established for {}", user);

    // Split streams for bidirectional proxy
    let (mut client_read, mut client_write) = client.into_split();
    let (mut pg_read, mut pg_write) = pg_conn.into_split();

    // Proxy bidirectionally
    let client_to_pg = async move {
        let mut buf = vec![0u8; 32768];
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if pg_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    };

    let pg_to_client = async move {
        let mut buf = vec![0u8; 32768];
        loop {
            match pg_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if client_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    };

    tokio::select! {
        _ = client_to_pg => {},
        _ = pg_to_client => {},
    }

    Ok(())
}

async fn read_message(stream: &mut TcpStream) -> Result<Message, Box<dyn std::error::Error + Send + Sync>> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;

    let msg_type = header[0];
    let length = i32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;

    let data_len = length - 4;
    let mut data = BytesMut::with_capacity(data_len);
    data.resize(data_len, 0);
    
    if data_len > 0 {
        stream.read_exact(&mut data).await?;
    }

    Ok(Message { msg_type, data })
}
