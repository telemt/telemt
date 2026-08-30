use super::*;

pub(super) fn classify_conntrack_close_reason(result: &Result<()>) -> ConntrackCloseReason {
    match result {
        Ok(()) => ConntrackCloseReason::NormalEof,
        Err(ProxyError::Io(error)) if matches!(error.kind(), std::io::ErrorKind::TimedOut) => {
            ConntrackCloseReason::Timeout
        }
        Err(ProxyError::Io(error))
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::UnexpectedEof
            ) =>
        {
            ConntrackCloseReason::Reset
        }
        Err(ProxyError::Proxy(message))
            if message.contains("pressure") || message.contains("evicted") =>
        {
            ConntrackCloseReason::Pressure
        }
        Err(_) => ConntrackCloseReason::Other,
    }
}
