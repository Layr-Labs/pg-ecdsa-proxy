use std::env;
use std::net::SocketAddr;
use std::sync::LazyLock;

pub static CONFIG: LazyLock<Config> = LazyLock::new(Config::from_env);

#[derive(Debug, Clone)]
pub struct Config {
    pub proxy_addr: SocketAddr,
    pub pg_host: String,
    pub pg_port: u16,
    pub pg_user: String,
    pub pg_password: String,
    pub pg_database: String,
    pub allowed_address: [u8; 20],
    pub signature_window_secs: u64,
    pub pool_size: u32,
}

impl Config {
    pub fn from_env() -> Self {
        let proxy_host = env::var("PROXY_HOST").unwrap_or_else(|_| "0.0.0.0".into());
        let proxy_port: u16 = env::var("PROXY_PORT")
            .unwrap_or_else(|_| "5433".into())
            .parse()
            .expect("PROXY_PORT must be a number");

        let allowed_hex = env::var("ALLOWED_ADDRESS")
            .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".into());
        
        let allowed_address = parse_eth_address(&allowed_hex)
            .expect("ALLOWED_ADDRESS must be a valid Ethereum address");

        Self {
            proxy_addr: format!("{}:{}", proxy_host, proxy_port)
                .parse()
                .expect("Invalid proxy address"),
            pg_host: env::var("PG_HOST").unwrap_or_else(|_| "postgres".into()),
            pg_port: env::var("PG_PORT")
                .unwrap_or_else(|_| "5432".into())
                .parse()
                .expect("PG_PORT must be a number"),
            pg_user: env::var("PG_USER").unwrap_or_else(|_| "postgres".into()),
            pg_password: env::var("PG_PASSWORD").unwrap_or_else(|_| "postgres".into()),
            pg_database: env::var("PG_DATABASE").unwrap_or_else(|_| "postgres".into()),
            allowed_address,
            signature_window_secs: env::var("SIGNATURE_WINDOW_SECS")
                .unwrap_or_else(|_| "300".into())
                .parse()
                .expect("SIGNATURE_WINDOW_SECS must be a number"),
            pool_size: env::var("POOL_SIZE")
                .unwrap_or_else(|_| "20".into())
                .parse()
                .expect("POOL_SIZE must be a number"),
        }
    }
}

fn parse_eth_address(s: &str) -> Option<[u8; 20]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 40 {
        return None;
    }
    let bytes = hex::decode(s).ok()?;
    bytes.try_into().ok()
}

