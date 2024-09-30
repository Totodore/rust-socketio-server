//! Contains all the parser implementations for the socket.io protocol.
//!
//! The default parser is the [`CommonParser`]

use bytes::Bytes;

use socketioxide_core::{
    packet::Packet,
    parser::{Parse, ParserState},
    Str, Value,
};

use serde::{Deserialize, Serialize};
use socketioxide_parser_common::CommonParser;
use socketioxide_parser_msgpack::MsgPackParser;

/// All the parser available.
/// It also implements the [`Parse`] trait and therefore the
/// parser implementation is done over enum delegation.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub enum Parser {
    /// The default parser
    Common(CommonParser),
    /// The MsgPack parser
    MsgPack(MsgPackParser),
}

impl Default for Parser {
    fn default() -> Self {
        Parser::Common(CommonParser)
    }
}

/// Errors that can occur during value encoding
#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    /// Common parser error
    #[error("common parser: {0}")]
    Common(<CommonParser as Parse>::EncodeError),
    /// MsgPack parser error
    #[error("msgpack parser: {0}")]
    MsgPack(<MsgPackParser as Parse>::EncodeError),
}

/// Errors that can occur during packet decoding or value decoding
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    /// Common parser error
    #[error("common parser: {0}")]
    Common(<CommonParser as Parse>::DecodeError),
    /// MsgPack parser error
    #[error("msgpack parser: {0}")]
    MsgPack(<MsgPackParser as Parse>::DecodeError),
}

/// Parse errors occurring during packet parsing
pub type ParseError = socketioxide_core::parser::ParseError<DecodeError>;

impl Parse for Parser {
    type EncodeError = EncodeError;
    type DecodeError = DecodeError;

    fn encode(self, packet: Packet) -> Value {
        let value = match self {
            Parser::Common(p) => p.encode(packet),
            Parser::MsgPack(p) => p.encode(packet),
        };
        #[cfg(feature = "tracing")]
        match &value {
            Value::Str(value, bins) => tracing::trace!(?value, ?bins, "packet encoded:"),
            Value::Bytes(value) => tracing::trace!("packet encoded: {:X}", value),
        }

        value
    }

    fn decode_bin(self, state: &ParserState, bin: Bytes) -> Result<Packet, ParseError> {
        #[cfg(feature = "tracing")]
        tracing::trace!(?state, "decoding bin payload: {:X}", bin);

        let packet = match self {
            Parser::Common(p) => p
                .decode_bin(state, bin)
                .map_err(|e| e.wrap_err(DecodeError::Common)),
            Parser::MsgPack(p) => p
                .decode_bin(state, bin)
                .map_err(|e| e.wrap_err(DecodeError::MsgPack)),
        }?;

        #[cfg(feature = "tracing")]
        tracing::trace!(?packet, "bin payload decoded:");
        Ok(packet)
    }
    fn decode_str(self, state: &ParserState, data: Str) -> Result<Packet, ParseError> {
        #[cfg(feature = "tracing")]
        tracing::trace!(?data, ?state, "decoding str payload:");

        let packet = match self {
            Parser::Common(p) => p
                .decode_str(state, data)
                .map_err(|e| e.wrap_err(DecodeError::Common)),
            Parser::MsgPack(p) => p
                .decode_str(state, data)
                .map_err(|e| e.wrap_err(DecodeError::MsgPack)),
        }?;

        #[cfg(feature = "tracing")]
        tracing::trace!(?packet, "str payload decoded:");
        Ok(packet)
    }

    fn encode_value<T: ?Sized + Serialize>(
        self,
        data: &T,
        event: Option<&str>,
    ) -> Result<Value, EncodeError> {
        let value = match self {
            Parser::Common(p) => p.encode_value(data, event).map_err(EncodeError::Common),
            Parser::MsgPack(p) => p.encode_value(data, event).map_err(EncodeError::MsgPack),
        };
        #[cfg(feature = "tracing")]
        tracing::trace!(?value, "value encoded:");
        value
    }

    fn decode_value<'de, T: Deserialize<'de>>(
        self,
        value: &'de Value,
        with_event: bool,
    ) -> Result<T, DecodeError> {
        #[cfg(feature = "tracing")]
        tracing::trace!(?value, "decoding value:");
        match self {
            Parser::Common(p) => p
                .decode_value(value, with_event)
                .map_err(DecodeError::Common),
            Parser::MsgPack(p) => p
                .decode_value(value, with_event)
                .map_err(DecodeError::MsgPack),
        }
    }

    fn decode_default<'de, T: Deserialize<'de>>(
        self,
        value: Option<&'de Value>,
    ) -> Result<T, Self::DecodeError> {
        match self {
            Parser::Common(p) => p.decode_default(value).map_err(DecodeError::Common),
            Parser::MsgPack(p) => p.decode_default(value).map_err(DecodeError::MsgPack),
        }
    }

    fn encode_default<T: ?Sized + Serialize>(self, data: &T) -> Result<Value, Self::EncodeError> {
        match self {
            Parser::Common(p) => p.encode_default(data).map_err(EncodeError::Common),
            Parser::MsgPack(p) => p.encode_default(data).map_err(EncodeError::MsgPack),
        }
    }

    fn read_event(self, value: &Value) -> Result<&str, Self::DecodeError> {
        match self {
            Parser::Common(p) => p.read_event(value).map_err(DecodeError::Common),
            Parser::MsgPack(p) => p.read_event(value).map_err(DecodeError::MsgPack),
        }
    }
}
