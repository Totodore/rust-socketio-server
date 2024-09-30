//! This module contains a specialized JSON serializer wrapper that can serialize binary payloads as placeholders.
use std::cell::UnsafeCell;

use bytes::Bytes;
use serde::ser::{
    self, SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
    SerializeTupleStruct, SerializeTupleVariant,
};

/// Serialize the given data into a JSON string.
///
/// The resulting JSON object will may have a event field serialized as the first element of the top level array:
/// `[event, ...data]`.
///
/// Any binary payload will be replaced with a placeholder object: `{"_placeholder": true, "index": 0}`.
pub fn into_str<T: ?Sized + ser::Serialize>(
    data: &T,
    event: Option<&str>,
) -> Result<(Vec<u8>, Vec<Bytes>), serde_json::Error> {
    let mut writer = Vec::new();
    let binary_payloads = UnsafeCell::new(Vec::new());
    let ser = &mut serde_json::Serializer::new(&mut writer);
    let ser = Serializer {
        event,
        ser,
        binary_payloads: &binary_payloads,
        is_root: true,
    };
    data.serialize(ser)?;
    Ok((writer, binary_payloads.into_inner()))
}

struct Serializer<'a, S> {
    event: Option<&'a str>,
    ser: S,
    /// This field requires UnsafeCell because we need to mutate the vector of binary payloads.
    /// However we can't move &mut around because we need to pass by value every [`Serializer`] when we
    /// instantiate them for new [`Compound`] types.
    binary_payloads: &'a UnsafeCell<Vec<Bytes>>,
    is_root: bool,
}

/// The Compound type is used to serialize map-like or vec-like structures.
/// It is used to wrap the inner serde compound type so we are able to continue to use the current serializer.
struct Compound<'a, I> {
    inner: I,
    event: Option<&'a str>,
    binary_payloads: &'a UnsafeCell<Vec<Bytes>>,
}

/// A wrapper around a value that is being serialized.
struct CompoundWrapper<'a, T> {
    value: T,
    event: Option<&'a str>,
    binary_payloads: &'a UnsafeCell<Vec<Bytes>>,
}

impl<T: ser::Serialize> ser::Serialize for CompoundWrapper<'_, T> {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.value.serialize(Serializer {
            event: self.event,
            ser: serializer,
            binary_payloads: self.binary_payloads,
            is_root: false,
        })
    }
}

impl<'a, I: SerializeSeq> SerializeSeq for Compound<'a, I> {
    type Ok = I::Ok;
    type Error = I::Error;

    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + serde::Serialize,
    {
        self.inner.serialize_element(&CompoundWrapper {
            value,
            event: self.event,
            binary_payloads: self.binary_payloads,
        })
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        SerializeSeq::end(self.inner)
    }
}
impl<'a, I: SerializeTuple> SerializeTuple for Compound<'a, I> {
    type Ok = I::Ok;
    type Error = I::Error;
    fn serialize_element<T: ?Sized + serde::Serialize>(
        &mut self,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.inner.serialize_element(&CompoundWrapper {
            value,
            event: self.event,
            binary_payloads: self.binary_payloads,
        })
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        SerializeTuple::end(self.inner)
    }
}
impl<I: SerializeTupleStruct> SerializeTupleStruct for Compound<'_, I> {
    type Ok = I::Ok;
    type Error = I::Error;
    fn serialize_field<T: ?Sized + serde::Serialize>(
        &mut self,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.inner.serialize_field(&CompoundWrapper {
            value,
            event: self.event,
            binary_payloads: self.binary_payloads,
        })
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        SerializeTupleStruct::end(self.inner)
    }
}
impl<I: SerializeTupleVariant> SerializeTupleVariant for Compound<'_, I> {
    type Ok = I::Ok;
    type Error = I::Error;
    fn serialize_field<T: ?Sized + serde::Serialize>(
        &mut self,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.inner.serialize_field(&CompoundWrapper {
            value,
            event: self.event,
            binary_payloads: self.binary_payloads,
        })
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        SerializeTupleVariant::end(self.inner)
    }
}
impl<I: SerializeMap> SerializeMap for Compound<'_, I> {
    type Ok = I::Ok;
    type Error = I::Error;
    #[inline]
    fn serialize_key<T: ?Sized + serde::Serialize>(&mut self, key: &T) -> Result<(), Self::Error> {
        // We defer the serialization of the key to the inner `JsonCompound`
        // as we don't need to handle binary payloads for struct/map keys.
        SerializeMap::serialize_key(&mut self.inner, key)
    }

    #[inline]
    fn serialize_value<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + serde::Serialize,
    {
        self.inner.serialize_value(&CompoundWrapper {
            value,
            event: self.event,
            binary_payloads: self.binary_payloads,
        })
    }

    #[inline]
    fn end(self) -> Result<Self::Ok, Self::Error> {
        SerializeMap::end(self.inner)
    }
}
impl<I: SerializeStruct> SerializeStruct for Compound<'_, I> {
    type Ok = I::Ok;
    type Error = I::Error;

    #[inline]
    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + serde::Serialize,
    {
        self.inner.serialize_field(
            key,
            &CompoundWrapper {
                value,
                event: self.event,
                binary_payloads: self.binary_payloads,
            },
        )
    }

    #[inline]
    fn end(self) -> Result<Self::Ok, Self::Error> {
        SerializeStruct::end(self.inner)
    }
}
impl<I: SerializeStructVariant> SerializeStructVariant for Compound<'_, I> {
    type Ok = I::Ok;
    type Error = I::Error;

    #[inline]
    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + serde::Serialize,
    {
        self.inner.serialize_field(
            key,
            &CompoundWrapper {
                value,
                event: self.event,
                binary_payloads: self.binary_payloads,
            },
        )
    }

    #[inline]
    fn end(self) -> Result<Self::Ok, Self::Error> {
        SerializeStructVariant::end(self.inner)
    }
}

impl<'a, S: ser::Serializer> Serializer<'a, S> {
    /// Converts this serializer into a compound serializer.
    fn into_compound<I>(
        self,
        f: impl FnOnce(S) -> Result<I, S::Error>,
    ) -> Result<Compound<'a, I>, S::Error> {
        Ok(Compound {
            inner: f(self.ser)?,
            event: self.event,
            binary_payloads: self.binary_payloads,
        })
    }
}
impl<'a, S: ser::Serializer> serde::Serializer for Serializer<'a, S> {
    type Ok = S::Ok;

    type Error = S::Error;

    type SerializeSeq = Compound<'a, S::SerializeSeq>;

    type SerializeTuple = Compound<'a, S::SerializeTuple>;

    type SerializeTupleStruct = Compound<'a, S::SerializeTupleStruct>;

    type SerializeTupleVariant = Compound<'a, S::SerializeTupleVariant>;

    type SerializeMap = Compound<'a, S::SerializeMap>;

    type SerializeStruct = Compound<'a, S::SerializeStruct>;

    type SerializeStructVariant = Compound<'a, S::SerializeStructVariant>;

    fn serialize_bool(self, v: bool) -> Result<Self::Ok, Self::Error> {
        self.ser.serialize_bool(v)
    }

    fn serialize_i8(self, v: i8) -> Result<Self::Ok, Self::Error> {
        self.ser.serialize_i8(v)
    }

    fn serialize_i16(self, v: i16) -> Result<Self::Ok, Self::Error> {
        self.ser.serialize_i16(v)
    }

    fn serialize_i32(self, v: i32) -> Result<Self::Ok, Self::Error> {
        self.ser.serialize_i32(v)
    }

    fn serialize_i64(self, v: i64) -> Result<Self::Ok, Self::Error> {
        self.ser.serialize_i64(v)
    }

    fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error> {
        self.ser.serialize_u8(v)
    }

    fn serialize_u16(self, v: u16) -> Result<Self::Ok, Self::Error> {
        self.ser.serialize_u16(v)
    }

    fn serialize_u32(self, v: u32) -> Result<Self::Ok, Self::Error> {
        self.ser.serialize_u32(v)
    }

    fn serialize_u64(self, v: u64) -> Result<Self::Ok, Self::Error> {
        self.ser.serialize_u64(v)
    }

    fn serialize_f32(self, v: f32) -> Result<Self::Ok, Self::Error> {
        self.ser.serialize_f32(v)
    }

    fn serialize_f64(self, v: f64) -> Result<Self::Ok, Self::Error> {
        self.ser.serialize_f64(v)
    }

    fn serialize_char(self, v: char) -> Result<Self::Ok, Self::Error> {
        self.ser.serialize_char(v)
    }

    fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
        self.ser.serialize_str(v)
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        use serde::ser::SerializeMap;
        let num = {
            let bins = unsafe { self.binary_payloads.get().as_mut().unwrap() };
            bins.push(Bytes::copy_from_slice(v));
            bins.len() - 1
        };

        let mut map = self.ser.serialize_map(Some(2))?;
        map.serialize_entry("_placeholder", &true)?;
        map.serialize_entry("num", &num)?;
        SerializeMap::end(map)
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        self.ser.serialize_none()
    }

    fn serialize_some<T>(self, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + serde::Serialize,
    {
        self.ser.serialize_some(value)
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        self.ser.serialize_unit()
    }

    fn serialize_unit_struct(self, name: &'static str) -> Result<Self::Ok, Self::Error> {
        self.ser.serialize_unit_struct(name)
    }

    fn serialize_unit_variant(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        self.ser
            .serialize_unit_variant(name, variant_index, variant)
    }

    fn serialize_newtype_struct<T>(
        self,
        name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + serde::Serialize,
    {
        self.ser.serialize_newtype_struct(name, value)
    }

    fn serialize_newtype_variant<T>(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + serde::Serialize,
    {
        self.ser
            .serialize_newtype_variant(name, variant_index, variant, value)
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        self.into_compound(move |ser| ser.serialize_seq(len))
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        match self.event {
            Some(e) if self.is_root => {
                let mut inner = self.ser.serialize_tuple(len + 1)?;
                SerializeTuple::serialize_element(&mut inner, &e)?;
                Ok(Compound {
                    inner,
                    event: self.event,
                    binary_payloads: self.binary_payloads,
                })
            }
            _ => self.into_compound(move |ser| ser.serialize_tuple(len)),
        }
    }

    fn serialize_tuple_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        match self.event {
            Some(e) if self.is_root => {
                let mut inner = self.ser.serialize_tuple_struct(name, len + 1)?;
                SerializeTupleStruct::serialize_field(&mut inner, &e)?;
                Ok(Compound {
                    inner,
                    event: self.event,
                    binary_payloads: self.binary_payloads,
                })
            }
            _ => self.into_compound(move |ser| ser.serialize_tuple_struct(name, len)),
        }
    }

    fn serialize_tuple_variant(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        self.into_compound(move |ser| {
            ser.serialize_tuple_variant(name, variant_index, variant, len)
        })
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        self.into_compound(move |ser| ser.serialize_map(len))
    }

    fn serialize_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        self.into_compound(move |ser| ser.serialize_struct(name, len))
    }

    fn serialize_struct_variant(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        self.into_compound(move |ser| {
            ser.serialize_struct_variant(name, variant_index, variant, len)
        })
    }
}
