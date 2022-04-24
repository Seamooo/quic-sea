#[derive(Debug, Clone)]
pub enum Error {
    NoError,
    InternalError(&'static str),
    ConnectionRefused,
    FlowControlError,
    StreamLimitError,
    StreamStateError,
    FinalSizeError,
    FrameEncodingError,
    TransportParameterError,
    ConnectionIdLimitError,
    ProtocolViolation,
    InvalidToken,
    ApplicationError,
    CryptoBufferExceeded,
    KeyUpdateError,
    AeadLimitReached,
    NoViablePath,
    // TODO implement crypto errors (www.rfc-editor.org/rfc/rfc8446#section-6)
}

impl Error {
    pub fn to_error_byte(&self) -> u8 {
        match self {
            Error::NoError => 0x00,
            Error::InternalError(_) => 0x01,
            Error::ConnectionRefused => 0x02,
            Error::FlowControlError => 0x03,
            Error::StreamLimitError => 0x04,
            Error::StreamStateError => 0x05,
            Error::FinalSizeError => 0x06,
            Error::FrameEncodingError => 0x07,
            Error::TransportParameterError => 0x08,
            Error::ConnectionIdLimitError => 0x09,
            Error::ProtocolViolation => 0x0a,
            Error::InvalidToken => 0x0b,
            Error::ApplicationError => 0x0c,
            Error::CryptoBufferExceeded => 0x0d,
            Error::KeyUpdateError => 0x0e,
            Error::AeadLimitReached => 0x0f,
            Error::NoViablePath => 0x10,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
