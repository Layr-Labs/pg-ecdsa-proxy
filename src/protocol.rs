use bytes::{Buf, BufMut, BytesMut};
use std::collections::HashMap;
use thiserror::Error;

// Postgres wire protocol constants
pub const SSL_REQUEST_CODE: i32 = 80877103;
pub const PROTOCOL_VERSION: i32 = 196608; // 3.0

// Message types
pub const MSG_PASSWORD: u8 = b'p';
pub const MSG_AUTH_REQUEST: u8 = b'R';
pub const MSG_ERROR: u8 = b'E';
pub const MSG_READY: u8 = b'Z';
pub const MSG_PARAM_STATUS: u8 = b'S';
pub const MSG_BACKEND_KEY: u8 = b'K';

// Auth types
pub const AUTH_OK: i32 = 0;
pub const AUTH_CLEARTEXT: i32 = 3;

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("Message too short: expected at least {expected}, got {actual}")]
    MessageTooShort { expected: usize, actual: usize },
    #[error("Invalid message type: expected {expected}, got {actual}")]
    InvalidMessageType { expected: char, actual: char },
    #[error("Invalid UTF-8 in message")]
    InvalidUtf8,
    #[error("Invalid startup message format")]
    InvalidStartup,
}

#[derive(Debug)]
pub struct StartupMessage {
    pub protocol: i32,
    pub params: HashMap<String, String>,
}

impl StartupMessage {
    pub fn parse(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 8 {
            return Err(ProtocolError::MessageTooShort {
                expected: 8,
                actual: data.len(),
            });
        }

        let mut buf = data;
        let length = buf.get_i32() as usize;
        let protocol = buf.get_i32();

        if data.len() < length {
            return Err(ProtocolError::MessageTooShort {
                expected: length,
                actual: data.len(),
            });
        }

        let mut params = HashMap::new();
        let param_data = &data[8..length];
        let mut pos = 0;

        while pos < param_data.len() {
            // Find key null terminator
            let key_end = param_data[pos..]
                .iter()
                .position(|&b| b == 0)
                .ok_or(ProtocolError::InvalidStartup)?;
            
            let key = std::str::from_utf8(&param_data[pos..pos + key_end])
                .map_err(|_| ProtocolError::InvalidUtf8)?;
            
            if key.is_empty() {
                break;
            }
            
            pos += key_end + 1;

            // Find value null terminator
            let val_end = param_data[pos..]
                .iter()
                .position(|&b| b == 0)
                .ok_or(ProtocolError::InvalidStartup)?;
            
            let value = std::str::from_utf8(&param_data[pos..pos + val_end])
                .map_err(|_| ProtocolError::InvalidUtf8)?;
            
            pos += val_end + 1;
            params.insert(key.to_string(), value.to_string());
        }

        Ok(Self { protocol, params })
    }

    pub fn build(params: &HashMap<&str, &str>) -> BytesMut {
        let mut param_bytes = BytesMut::new();
        for (key, value) in params {
            param_bytes.put_slice(key.as_bytes());
            param_bytes.put_u8(0);
            param_bytes.put_slice(value.as_bytes());
            param_bytes.put_u8(0);
        }
        param_bytes.put_u8(0); // Final null

        let length = 4 + 4 + param_bytes.len(); // length field + protocol + params
        let mut buf = BytesMut::with_capacity(length);
        buf.put_i32(length as i32);
        buf.put_i32(PROTOCOL_VERSION);
        buf.put_slice(&param_bytes);
        buf
    }
}

pub fn parse_password(data: &[u8]) -> Result<String, ProtocolError> {
    if data.len() < 5 {
        return Err(ProtocolError::MessageTooShort {
            expected: 5,
            actual: data.len(),
        });
    }

    if data[0] != MSG_PASSWORD {
        return Err(ProtocolError::InvalidMessageType {
            expected: 'p',
            actual: data[0] as char,
        });
    }

    let mut buf = &data[1..];
    let length = buf.get_i32() as usize;
    
    // Password is null-terminated, length includes the 4-byte length field
    // So actual password data is at data[5..5 + length - 4 - 1] (excluding null)
    let end = 5 + length - 4;
    if end > data.len() {
        return Err(ProtocolError::MessageTooShort {
            expected: end,
            actual: data.len(),
        });
    }
    let password_data = &data[5..end];
    std::str::from_utf8(password_data)
        .map(|s| s.trim_end_matches('\0').to_string())
        .map_err(|_| ProtocolError::InvalidUtf8)
}

pub fn build_auth_request(auth_type: i32) -> BytesMut {
    let mut buf = BytesMut::with_capacity(9);
    buf.put_u8(MSG_AUTH_REQUEST);
    buf.put_i32(8); // length
    buf.put_i32(auth_type);
    buf
}

pub fn build_auth_ok() -> BytesMut {
    build_auth_request(AUTH_OK)
}

pub fn build_error(message: &str, code: &str) -> BytesMut {
    // Error format: 'E' + length + fields (S=Severity, C=Code, M=Message)
    let fields = format!("SERROR\0C{}\0M{}\0\0", code, message);
    let length = 4 + fields.len();
    
    let mut buf = BytesMut::with_capacity(1 + length);
    buf.put_u8(MSG_ERROR);
    buf.put_i32(length as i32);
    buf.put_slice(fields.as_bytes());
    buf
}

pub fn build_password_message(password: &str) -> BytesMut {
    let password_bytes = password.as_bytes();
    let length = 4 + password_bytes.len() + 1; // length + password + null
    
    let mut buf = BytesMut::with_capacity(1 + length);
    buf.put_u8(MSG_PASSWORD);
    buf.put_i32(length as i32);
    buf.put_slice(password_bytes);
    buf.put_u8(0);
    buf
}

pub fn is_ssl_request(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }
    let code = i32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    code == SSL_REQUEST_CODE
}

#[derive(Debug)]
pub struct Message {
    pub msg_type: u8,
    pub data: BytesMut,
}

impl Message {
    pub fn auth_type(&self) -> Option<i32> {
        if self.msg_type != MSG_AUTH_REQUEST || self.data.len() < 4 {
            return None;
        }
        Some(i32::from_be_bytes([
            self.data[0],
            self.data[1],
            self.data[2],
            self.data[3],
        ]))
    }
}

