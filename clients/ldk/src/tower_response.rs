//! Bounded body reading and rejection parsing shared by tower HTTP methods.

use reqwest::{Response, StatusCode};

pub(crate) const MAX_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_REJECTION_MESSAGE_BYTES: usize = 4 * 1024;
const TRUNCATION_MARKER: &str = " [truncated]";

pub(crate) enum ResponseError {
    Read {
        status: StatusCode,
        source: reqwest::Error,
    },
    TooLarge {
        status: StatusCode,
        limit: usize,
    },
    Rejected {
        status: StatusCode,
        error_code: Option<u32>,
        message: String,
    },
}

pub(crate) async fn read_success(
    mut response: Response,
    success_limit: usize,
) -> Result<Vec<u8>, ResponseError> {
    let status = response.status();
    // A large locator-list allowance must not also enlarge proxy/error bodies.
    let limit = if status == StatusCode::OK {
        success_limit
    } else {
        MAX_REJECTION_MESSAGE_BYTES
    };
    let mut body = Vec::new();
    let mut truncated = false;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|source| ResponseError::Read { status, source })?
    {
        let remaining = limit - body.len();
        if chunk.len() > remaining {
            body.extend_from_slice(&chunk[..remaining]);
            truncated = true;
            break;
        }
        body.extend_from_slice(&chunk);
    }
    if status != StatusCode::OK {
        let details = serde_json::from_slice::<serde_json::Value>(&body).ok();
        let error_code = details
            .as_ref()
            .and_then(|v| v.get("error_code"))
            .and_then(serde_json::Value::as_u64)
            .and_then(|code| u32::try_from(code).ok());
        let message = details
            .as_ref()
            .and_then(|v| v.get("error"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| String::from_utf8_lossy(&body).into_owned());
        return Err(ResponseError::Rejected {
            status,
            error_code,
            message: bounded_message(message, truncated),
        });
    }
    if truncated {
        return Err(ResponseError::TooLarge { status, limit });
    }
    Ok(body)
}

fn bounded_message(mut message: String, body_truncated: bool) -> String {
    if body_truncated || message.len() > MAX_REJECTION_MESSAGE_BYTES {
        let mut end = message
            .len()
            .min(MAX_REJECTION_MESSAGE_BYTES - TRUNCATION_MARKER.len());
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
        message.push_str(TRUNCATION_MARKER);
    }
    message
}
