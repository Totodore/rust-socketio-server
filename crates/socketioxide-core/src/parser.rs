use std::{
    fmt,
    sync::{atomic::AtomicUsize, Mutex},
};

use bytes::Bytes;
use engineioxide::Str;
use serde::{
    de::Visitor,
    ser::{Impossible, SerializeStruct},
    Deserialize, Serialize,
};

use crate::{packet::Packet, Value};

#[derive(Debug, Default)]
pub struct ParserState {
    /// Partial binary packet that is being received
    /// Stored here until all the binary payloads are received for common parser
    pub partial_bin_packet: Mutex<Option<Packet>>,

    /// The number of expected binary attachments (used when receiving data for common parser)
    pub incoming_binary_cnt: AtomicUsize,
}

/// All socket.io parser should implement this trait
/// Parsers should be stateless
pub trait Parse: Default + Copy {
    type EncodeError: std::error::Error;
    type DecodeError: std::error::Error;
    /// Convert a packet into multiple payloads to be sent
    fn encode(self, packet: Packet) -> Value;

    /// Parse a given input string. If the payload needs more adjacent binary packet,
    /// the partial packet will be kept and a [`Error::NeedsMoreBinaryData`] will be returned
    fn decode_str(
        self,
        state: &ParserState,
        data: Str,
    ) -> Result<Packet, ParseError<Self::DecodeError>>;

    /// Parse a given input binary.
    fn decode_bin(
        self,
        state: &ParserState,
        bin: Bytes,
    ) -> Result<Packet, ParseError<Self::DecodeError>>;

    /// Convert any serializable data to a generic [`Bytes`]
    fn encode_value<T: ?Sized + Serialize>(
        self,
        data: &T,
        event: Option<&str>,
    ) -> Result<Value, Self::EncodeError>;

    /// Convert any generic [`Bytes`] to deserializable data.
    ///
    /// The parser will be determined from the value given to deserialize.
    fn decode_value<'de, T: Deserialize<'de>>(
        self,
        value: &'de Value,
        with_event: bool,
    ) -> Result<T, Self::DecodeError>;

    /// Convert any raw data to a type with the default serde impl without binary + event tricks.
    /// This is mainly used for connect payloads.
    fn decode_default<'de, T: Deserialize<'de>>(
        self,
        value: Option<&'de Value>,
    ) -> Result<T, Self::DecodeError>;
    /// Convert any type to raw data Str/Bytes with the default serde impl without binary + event tricks.
    /// This is mainly used for connect payloads.
    fn encode_default<T: ?Sized + Serialize>(self, data: &T) -> Result<Value, Self::EncodeError>;

    /// Try to read the event name from the given payload data
    fn read_event(self, value: &Value) -> Result<&str, Self::DecodeError>;
}

/// Errors when parsing/serializing socket.io packets
#[derive(thiserror::Error, Debug)]
pub enum ParseError<E: std::error::Error> {
    /// Invalid packet type
    #[error("invalid packet type")]
    InvalidPacketType,

    /// Invalid ack id
    #[error("invalid ack id")]
    InvalidAckId,

    /// Invalid event name
    #[error("invalid event name")]
    InvalidEventName,

    /// Invalid data
    #[error("invalid data")]
    InvalidData,

    /// Invalid namespace
    #[error("invalid namespace")]
    InvalidNamespace,

    /// Invalid attachments
    #[error("invalid attachments")]
    InvalidAttachments,

    /// Received unexpected binary data
    #[error(
        "received unexpected binary data. Make sure you are using the same parser on both ends."
    )]
    UnexpectedBinaryPacket,

    /// Received unexpected string data
    #[error(
        "received unexpected string data. Make sure you are using the same parser on both ends."
    )]
    UnexpectedStringPacket,

    /// Needs more binary data before deserialization. It is not exactly an error, it is used for control flow,
    /// e.g the common parser needs adjacent binary packets and therefore will returns [`NeedsMoreBinaryData`] n times for n adjacent binary packet expected.
    /// In this case the user should call again the parser with the next binary payload.
    #[error("needs more binary data before deserialization")]
    NeedsMoreBinaryData,

    #[error("parser error: {0:?}")]
    ParserError(#[from] E),
}
impl<E: std::error::Error> ParseError<E> {
    /// Wrap the [`ParseError::ParserError`] variant with a new error type
    pub fn wrap_err<E1: std::error::Error>(self, f: impl FnOnce(E) -> E1) -> ParseError<E1> {
        match self {
            Self::ParserError(e) => ParseError::ParserError(f(e)),
            ParseError::InvalidPacketType => ParseError::InvalidPacketType,
            ParseError::InvalidAckId => ParseError::InvalidAckId,
            ParseError::InvalidEventName => ParseError::InvalidEventName,
            ParseError::InvalidData => ParseError::InvalidData,
            ParseError::InvalidNamespace => ParseError::InvalidNamespace,
            ParseError::InvalidAttachments => ParseError::InvalidAttachments,
            ParseError::UnexpectedBinaryPacket => ParseError::UnexpectedBinaryPacket,
            ParseError::UnexpectedStringPacket => ParseError::UnexpectedStringPacket,
            ParseError::NeedsMoreBinaryData => ParseError::NeedsMoreBinaryData,
        }
    }
}

/// A seed that can be used to deserialize only the 1st element of a sequence
pub struct FirstElement<T>(std::marker::PhantomData<T>);
impl<T> Default for FirstElement<T> {
    fn default() -> Self {
        Self(Default::default())
    }
}
impl<'de, T> serde::de::Visitor<'de> for FirstElement<T>
where
    T: serde::Deserialize<'de>,
{
    type Value = T;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "a sequence in which we care about first element",)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        use serde::de::Error;
        let data = seq
            .next_element::<T>()?
            .ok_or(A::Error::custom("first element not found"));

        // Consume the rest of the sequence
        while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}

        data
    }
}

impl<'de, T> serde::de::DeserializeSeed<'de> for FirstElement<T>
where
    T: serde::Deserialize<'de>,
{
    type Value = T;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}

const TOKEN: &str = "$socketioxide_core::parser::Value";

impl Serialize for Value {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_unit_struct(TOKEN)
    }
}
impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RawValueVisitor;
        impl<'de> serde::de::Visitor<'de> for RawValueVisitor {
            type Value = Value;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "any valid RawValue")
            }
        }
        deserializer.deserialize_unit_struct(TOKEN, RawValueVisitor)
    }
}

/// Serializer and deserializer that simply return metdata informations about the root Type.
/// It is used with [`get_de_obj_type`] and [`get_ser_obj_type`].
/// Thanks to this information we can :
/// * expand tuple data into multiple arguments while serializing vectors as a single value.
/// * skip ser/de with [`RawValue`]
struct GetRootObjType;
#[derive(Debug, PartialEq, Eq)]
pub enum CustomType {
    Tuple,
    RawVal,
    Other,
}
#[derive(Debug)]
struct GetCustomTypeError(CustomType);
impl fmt::Display for GetCustomTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IsTupleSerializerError: {:?}", self.0)
    }
}
impl std::error::Error for GetCustomTypeError {}
impl serde::ser::Error for GetCustomTypeError {
    fn custom<T: fmt::Display>(_msg: T) -> Self {
        GetCustomTypeError(CustomType::Other)
    }
}
impl serde::de::Error for GetCustomTypeError {
    fn custom<T: fmt::Display>(_msg: T) -> Self {
        GetCustomTypeError(CustomType::Other)
    }
}

impl<'de> serde::Deserializer<'de> for GetRootObjType {
    type Error = GetCustomTypeError;

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str
        string unit seq  map
        struct enum identifier ignored_any bytes byte_buf option
    }

    fn deserialize_unit_struct<V>(
        self,
        name: &'static str,
        _visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match name {
            TOKEN => Err(GetCustomTypeError(CustomType::RawVal)),
            _ => Err(GetCustomTypeError(CustomType::Other)),
        }
    }
    fn deserialize_any<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
        Err(GetCustomTypeError(CustomType::Other))
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        _len: usize,
        _visitor: V,
    ) -> Result<V::Value, Self::Error> {
        Err(GetCustomTypeError(CustomType::Tuple))
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _len: usize,
        _visitor: V,
    ) -> Result<V::Value, Self::Error> {
        Err(GetCustomTypeError(CustomType::Tuple))
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _visitor: V,
    ) -> Result<V::Value, Self::Error> {
        Err(GetCustomTypeError(CustomType::Tuple))
    }
}

impl serde::Serializer for GetRootObjType {
    type Ok = CustomType;
    type Error = GetCustomTypeError;
    type SerializeSeq = Impossible<CustomType, GetCustomTypeError>;
    type SerializeTuple = Impossible<CustomType, GetCustomTypeError>;
    type SerializeTupleStruct = Impossible<CustomType, GetCustomTypeError>;
    type SerializeTupleVariant = Impossible<CustomType, GetCustomTypeError>;
    type SerializeMap = Impossible<CustomType, GetCustomTypeError>;
    type SerializeStruct = Impossible<CustomType, GetCustomTypeError>;
    type SerializeStructVariant = Impossible<CustomType, GetCustomTypeError>;

    fn serialize_bool(self, _v: bool) -> Result<Self::Ok, Self::Error> {
        Ok(CustomType::Other)
    }

    fn serialize_i8(self, _v: i8) -> Result<Self::Ok, Self::Error> {
        Ok(CustomType::Other)
    }

    fn serialize_i16(self, _v: i16) -> Result<Self::Ok, Self::Error> {
        Ok(CustomType::Other)
    }

    fn serialize_i32(self, _v: i32) -> Result<Self::Ok, Self::Error> {
        Ok(CustomType::Other)
    }

    fn serialize_i64(self, _v: i64) -> Result<Self::Ok, Self::Error> {
        Ok(CustomType::Other)
    }

    fn serialize_u8(self, _v: u8) -> Result<Self::Ok, Self::Error> {
        Ok(CustomType::Other)
    }

    fn serialize_u16(self, _v: u16) -> Result<Self::Ok, Self::Error> {
        Ok(CustomType::Other)
    }

    fn serialize_u32(self, _v: u32) -> Result<Self::Ok, Self::Error> {
        Ok(CustomType::Other)
    }

    fn serialize_u64(self, _v: u64) -> Result<Self::Ok, Self::Error> {
        Ok(CustomType::Other)
    }

    fn serialize_f32(self, _v: f32) -> Result<Self::Ok, Self::Error> {
        Ok(CustomType::Other)
    }

    fn serialize_f64(self, _v: f64) -> Result<Self::Ok, Self::Error> {
        Ok(CustomType::Other)
    }

    fn serialize_char(self, _v: char) -> Result<Self::Ok, Self::Error> {
        Ok(CustomType::Other)
    }

    fn serialize_str(self, _v: &str) -> Result<Self::Ok, Self::Error> {
        Ok(CustomType::Other)
    }

    fn serialize_bytes(self, _v: &[u8]) -> Result<Self::Ok, Self::Error> {
        Ok(CustomType::Other)
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        Ok(CustomType::Other)
    }

    fn serialize_some<T>(self, _value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + serde::Serialize,
    {
        Ok(CustomType::Other)
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Ok(CustomType::Other)
    }

    fn serialize_unit_struct(self, name: &'static str) -> Result<Self::Ok, Self::Error> {
        match name {
            TOKEN => Ok(CustomType::RawVal),
            _ => Ok(CustomType::Other),
        }
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        Ok(CustomType::Other)
    }

    fn serialize_newtype_struct<T>(
        self,
        _name: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + serde::Serialize,
    {
        Ok(CustomType::Tuple)
    }

    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + serde::Serialize,
    {
        Ok(CustomType::Other)
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Err(GetCustomTypeError(CustomType::Other))
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Err(GetCustomTypeError(CustomType::Tuple))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Err(GetCustomTypeError(CustomType::Tuple))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Err(GetCustomTypeError(CustomType::Other))
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Err(GetCustomTypeError(CustomType::Other))
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Err(GetCustomTypeError(CustomType::Other))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Err(GetCustomTypeError(CustomType::Other))
    }
}

pub fn get_ser_obj_type<T: ?Sized + serde::Serialize>(value: &T) -> CustomType {
    match value.serialize(GetRootObjType) {
        Ok(v) | Err(GetCustomTypeError(v)) => v,
    }
}

pub fn get_de_obj_type<'de, T: serde::Deserialize<'de>>() -> CustomType {
    match T::deserialize(GetRootObjType) {
        Ok(_) => unreachable!(),
        Err(GetCustomTypeError(v)) => v,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[test]
    fn get_obj_type() {
        assert_eq!(get_ser_obj_type(&(1, 2, 3)), CustomType::Tuple);
        assert_eq!(
            get_de_obj_type::<(usize, usize, usize)>(),
            CustomType::Tuple
        );

        assert_eq!(get_ser_obj_type(&[1, 2, 3]), CustomType::Tuple);
        assert_eq!(get_de_obj_type::<[usize; 3]>(), CustomType::Tuple);

        #[derive(Serialize, Deserialize)]
        struct TupleStruct<'a>(&'a str);
        assert_eq!(get_ser_obj_type(&TupleStruct("test")), CustomType::Tuple);
        assert_eq!(get_de_obj_type::<TupleStruct>(), CustomType::Tuple);

        let value = Value::Bytes(Bytes::new());
        assert_eq!(get_ser_obj_type(&value), CustomType::RawVal);
        assert_eq!(get_de_obj_type::<Value>(), CustomType::RawVal);

        assert_eq!(get_ser_obj_type(&vec![1, 2, 3]), CustomType::Other);
        assert_eq!(get_de_obj_type::<Vec<usize>>(), CustomType::Other);

        #[derive(Serialize, Deserialize)]
        struct UnitStruct;
        assert_eq!(get_ser_obj_type(&UnitStruct), CustomType::Other);
        assert_eq!(get_de_obj_type::<UnitStruct>(), CustomType::Other);
    }
}
