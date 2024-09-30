use std::convert::Infallible;
use std::sync::Arc;

use crate::handler::{FromConnectParts, FromMessage, FromMessageParts};
use crate::parser::{DecodeError, Parser};
use crate::{adapter::Adapter, socket::Socket};
use bytes::Bytes;
use serde::de::{Deserialize, DeserializeOwned};
use serde::ser::SerializeStruct;
use socketioxide_core::parser::Parse;
use socketioxide_core::Value;

/// An Extractor that returns the deserialized data without checking errors.
/// If a deserialization error occurs, the handler won't be called
/// and an error log will be print if the `tracing` feature is enabled.
pub struct Data<T>(pub T);
impl<T, A> FromConnectParts<A> for Data<T>
where
    T: DeserializeOwned,
    A: Adapter,
{
    type Error = DecodeError;
    fn from_connect_parts(s: &Arc<Socket<A>>, auth: &Option<Value>) -> Result<Self, Self::Error> {
        let parser = s.parser();
        parser.decode_default(auth.as_ref()).map(Data)
    }
}

impl<T, A> FromMessageParts<A> for Data<T>
where
    T: DeserializeOwned,
    A: Adapter,
{
    type Error = DecodeError;
    fn from_message_parts(
        s: &Arc<Socket<A>>,
        v: &mut Value,
        _: &mut Vec<Bytes>,
        _: &Option<i64>,
    ) -> Result<Self, Self::Error> {
        let parser = s.parser();
        parser.decode_value(v, true).map(Data)
    }
}

/// An Extractor that returns the deserialized data related to the event.
pub struct TryData<T>(pub Result<T, DecodeError>);

impl<T, A> FromConnectParts<A> for TryData<T>
where
    T: DeserializeOwned,
    A: Adapter,
{
    type Error = Infallible;
    fn from_connect_parts(s: &Arc<Socket<A>>, auth: &Option<Value>) -> Result<Self, Infallible> {
        let parser = s.parser();
        Ok(TryData(parser.decode_default(auth.as_ref())))
    }
}
impl<T, A> FromMessageParts<A> for TryData<T>
where
    T: DeserializeOwned,
    A: Adapter,
{
    type Error = Infallible;
    fn from_message_parts(
        s: &Arc<Socket<A>>,
        v: &mut Value,
        _: &mut Vec<Bytes>,
        _: &Option<i64>,
    ) -> Result<Self, Infallible> {
        let parser = s.parser();
        Ok(TryData(parser.decode_value(v, true)))
    }
}

/// An extractor that returns the incoming value without deserializing it.
/// You can then call [`RawValue::deserialize`] to deserialize with a borrowed value.
#[derive(Debug)]
pub struct RawValue {
    inner: Value,
    parser: Parser,
}

impl RawValue {
    /// Deserialize the raw value to any type. Contrary to the [`Data`] extractor the type
    /// can be unsized such as `&str` or `&[u8]`.
    pub fn deserialize<'de, T: Deserialize<'de> + ?Sized>(&'de self) -> Result<T, DecodeError> {
        self.parser.decode_value(&self.inner, true)
    }
}

impl serde::Serialize for RawValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        const TOKEN: &str = "$socketioxide::private::RawValue";
        const TOKEN_BIN: &str = "$socketioxide::private::RawValueBin";
        let mut s = serializer.serialize_struct(TOKEN, 1)?;
        //TODO: Determine before serialization that it is this kind of type.
        //Make a RawDeserialization that will be able to build a Value Payload from this data.
        match &self.inner {
            Value::Str(d, bins) => {
                s.serialize_field(TOKEN, d)?;
                s.serialize_field(TOKEN_BIN, bins)?;
            }
            Value::Bytes(d) => s.serialize_field(TOKEN, d)?,
        };
        s.end()
    }
}

impl<A: Adapter> FromMessage<A> for RawValue {
    type Error = Infallible;

    fn from_message(
        s: Arc<Socket<A>>,
        v: Value,
        _: Vec<Bytes>,
        _: Option<i64>,
    ) -> Result<Self, Self::Error> {
        Ok(RawValue {
            inner: v,
            parser: s.parser(),
        })
    }
}

super::__impl_deref!(TryData<T>: Result<T, DecodeError>);
super::__impl_deref!(Data);
