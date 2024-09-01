use std::fmt;

use bytes::Bytes;
use serde::{de::DeserializeOwned, Serialize};
use socketioxide_core::{SocketIoValue, Str};

use crate::de::FirstElement;

mod de;
mod ser;

/// Deserialize any deserializable data from a generic [`SocketIoValue`] data with this form:
/// `[event, ...data`].
/// * If T is a tuple or a tuple struct, the end of the array will be parsed as the data: `T = (..data)`.
/// * If T is something else, the first element of the array will be parsed as the data: `T = data[0]`.
///
/// All adjacent binary data will be inserted into the output data.
pub fn from_value<T: DeserializeOwned>(
    value: SocketIoValue,
    with_event: bool,
) -> serde_json::Result<T> {
    let (value, bins) = match value {
        SocketIoValue::Str(v) => v,
        SocketIoValue::Bytes(_) => panic!("unexpected binary data"),
    };
    let is_tuple = de::is_tuple::<T>();
    if is_tuple {
        de::from_str(value.as_str(), &bins.unwrap_or_default(), with_event)
    } else {
        de::from_str_seed(
            value.as_str(),
            &bins.unwrap_or_default(),
            FirstElement::default(),
            with_event,
        )
    }
}

/// Serialize any serializable data and an event to a generic [`SocketIoValue`] data.
pub fn to_value<T: Serialize>(data: &T, event: Option<&str>) -> serde_json::Result<SocketIoValue> {
    let (writer, binary) = if ser::is_tuple(data) {
        ser::into_str(data, event)?
    } else {
        ser::into_str(&(data,), event)?
    };
    let data = unsafe { Str::from_bytes_unchecked(Bytes::from(writer)) };
    Ok(SocketIoValue::Str((
        data,
        (!binary.is_empty()).then_some(binary),
    )))
}

/// Serializer and deserializer that simply return if the root object is a tuple or not.
/// It is used with [`de::is_tuple`] and [`ser::is_tuple`].
/// Thanks to this information we can expand tuple data into multiple arguments
/// while serializing vectors as a single value.
struct IsTupleSerde;
#[derive(Debug)]
struct IsTupleSerdeError(bool);
impl fmt::Display for IsTupleSerdeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IsTupleSerializerError: {}", self.0)
    }
}
impl std::error::Error for IsTupleSerdeError {}
impl serde::ser::Error for IsTupleSerdeError {
    fn custom<T: fmt::Display>(_msg: T) -> Self {
        IsTupleSerdeError(false)
    }
}
impl serde::de::Error for IsTupleSerdeError {
    fn custom<T: fmt::Display>(_msg: T) -> Self {
        IsTupleSerdeError(false)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use serde_json::json;

    fn to_str(data: impl Serialize, event: Option<&str>) -> Str {
        to_value(&data, event).unwrap().as_str().unwrap().clone()
    }
    fn from_str_event<T: DeserializeOwned>(data: impl Serialize) -> T {
        from_value::<T>(
            SocketIoValue::Str((serde_json::to_string(&data).unwrap().into(), None)),
            true,
        )
        .unwrap()
    }
    fn from_str_ack<T: DeserializeOwned>(data: impl Serialize) -> T {
        from_value::<T>(
            SocketIoValue::Str((serde_json::to_string(&data).unwrap().into(), None)),
            false,
        )
        .unwrap()
    }
    fn to_str_bin(data: impl Serialize, event: Option<&str>) -> (Str, Option<Vec<Bytes>>) {
        match to_value(&data, event).unwrap() {
            SocketIoValue::Str(data) => data,
            SocketIoValue::Bytes(_) => unreachable!(),
        }
    }
    fn from_str_event_bin<T: DeserializeOwned>(data: impl Serialize, bins: Vec<Bytes>) -> T {
        from_value::<T>(
            SocketIoValue::Str((serde_json::to_string(&data).unwrap().into(), Some(bins))),
            true,
        )
        .unwrap()
    }
    fn from_str_ack_bin<T: DeserializeOwned>(data: impl Serialize, bins: Vec<Bytes>) -> T {
        from_value::<T>(
            SocketIoValue::Str((serde_json::to_string(&data).unwrap().into(), Some(bins))),
            false,
        )
        .unwrap()
    }

    fn placeholder(i: usize) -> serde_json::Value {
        json!({ "_placeholder": true, "num": i })
    }

    const BIN: Bytes = Bytes::from_static(&[1, 2, 3, 4]);
    #[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
    struct Data {
        data: Bytes,
    }
    #[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
    struct Data2 {
        data: Vec<Bytes>,
        test: String,
    }

    #[test]
    fn to_value_event() {
        assert_eq!(
            to_str("hello", Some("event")).as_str(),
            json!(["event", "hello"]).to_string().as_str()
        );
        assert_eq!(
            to_str(("hello", 1, 2, 3), Some("event")).as_str(),
            json!(["event", "hello", 1, 2, 3]).to_string().as_str()
        );
        assert_eq!(
            to_str(vec![1, 2, 3], Some("event")).as_str(),
            json!(["event", vec![1, 2, 3]]).to_string().as_str()
        );
        assert_eq!(
            to_str(json!({ "test": "null" }), Some("event")).as_str(),
            json!(["event", { "test": "null" }]).to_string().as_str()
        );
    }

    #[test]
    fn from_value_event() {
        assert_eq!(from_str_event::<String>(json!(["event", "hello"])), "hello");
        assert_eq!(
            from_str_event::<(String, usize, usize, usize)>(json!(["event", "hello", 1, 2, 3])),
            ("hello".into(), 1, 2, 3)
        );
        assert_eq!(
            from_str_event::<Vec<usize>>(json!(["event", vec![1, 2, 3]])),
            vec![1, 2, 3]
        );
        #[derive(serde::Deserialize, Debug, PartialEq)]
        struct Test {
            test: String,
        }
        assert_eq!(
            from_str_event::<Test>(json!(["event", { "test": "null" }])),
            Test {
                test: "null".into()
            }
        );
    }

    #[test]
    fn to_value_binary() {
        assert_eq!(
            to_str_bin(("hello", &BIN), Some("event")),
            (
                json!(["event", "hello", {"_placeholder": true, "num": 0}])
                    .to_string()
                    .into(),
                Some(vec![BIN])
            )
        );

        assert_eq!(
            to_str_bin(("hello", 1, 2, 3, Data { data: BIN }), Some("event")),
            (
                json!(["event", "hello", 1, 2, 3, {"data": placeholder(0)}])
                    .to_string()
                    .into(),
                Some(vec![BIN])
            )
        );
        assert_eq!(
            to_str_bin(vec![Data { data: BIN }; 3], Some("event")),
            (
                json!(["event", [
                    {"data": placeholder(0)},
                    {"data": placeholder(1)},
                    {"data": placeholder(2)}
                ]])
                .to_string()
                .into(),
                Some(vec![BIN; 3])
            )
        );

        assert_eq!(
            to_str_bin(
                Data2 {
                    data: vec![BIN; 5],
                    test: "null".to_string()
                },
                Some("event")
            ),
            (
                json!(["event", { "data": [
                    placeholder(0),
                    placeholder(1),
                    placeholder(2),
                    placeholder(3),
                    placeholder(4)
                ], "test": "null" }])
                .to_string()
                .into(),
                Some(vec![BIN; 5])
            )
        );
    }

    #[test]
    fn from_value_binary() {
        assert_eq!(
            from_str_event_bin::<Bytes>(json!(["event", placeholder(0)]), vec![BIN]),
            BIN
        );
        assert_eq!(
            from_str_event_bin::<(String, Bytes)>(
                json!(["event", "hello", placeholder(0)]),
                vec![BIN]
            ),
            ("hello".into(), BIN)
        );
        assert_eq!(
            from_str_event_bin::<(String, usize, usize, usize, Data)>(
                json!(["event", "hello", 1, 2, 3, {"data": placeholder(0)}]),
                vec![BIN]
            ),
            ("hello".to_string(), 1, 2, 3, Data { data: BIN }),
        );
        assert_eq!(
            from_str_event_bin::<Vec<Data>>(
                json!(["event", [
                    {"data": placeholder(0)},
                    {"data": placeholder(1)},
                    {"data": placeholder(2)}
                ]]),
                vec![BIN; 3]
            ),
            vec![Data { data: BIN }; 3]
        );
        assert_eq!(
            from_str_event_bin::<Data2>(
                json!(["event", { "data": [
                    placeholder(0),
                    placeholder(1),
                    placeholder(2),
                    placeholder(3),
                    placeholder(4)
                ], "test": "null" }]),
                vec![BIN; 5]
            ),
            Data2 {
                data: vec![BIN; 5],
                test: "null".to_string()
            }
        );
    }

    #[test]
    fn to_value_binary_ack() {
        assert_eq!(
            to_str_bin(BIN, None),
            (json!([placeholder(0)]).to_string().into(), Some(vec![BIN]))
        );
        assert_eq!(
            to_str_bin(("hello", 1, 2, 3, BIN), None),
            (
                json!(["hello", 1, 2, 3, placeholder(0)]).to_string().into(),
                Some(vec![BIN])
            )
        );
    }

    #[test]
    fn from_value_binary_ack() {
        assert_eq!(
            from_str_ack_bin::<Bytes>(json!([placeholder(0)]), vec![BIN]),
            BIN
        );
        assert_eq!(
            from_str_ack_bin::<(String, usize, usize, usize, Bytes)>(
                json!(["hello", 1, 2, 3, placeholder(0)]),
                vec![BIN]
            ),
            ("hello".to_string(), 1, 2, 3, BIN)
        );
    }

    #[test]
    fn to_value_ack() {
        assert_eq!(
            to_str("hello", None).as_str(),
            json!(["hello"]).to_string().as_str()
        );
        assert_eq!(
            to_str(("hello", 1, 2, 3), None).as_str(),
            json!(["hello", 1, 2, 3]).to_string().as_str()
        );
    }

    #[test]
    fn from_value_ack() {
        assert_eq!(
            from_str_ack::<String>(json!(["hello"])),
            "hello".to_string()
        );
        assert_eq!(
            from_str_ack::<(String, usize, usize, usize)>(json!(["hello", 1, 2, 3])),
            ("hello".to_string(), 1, 2, 3)
        );
    }

    #[test]
    fn is_tuple() {
        assert!(ser::is_tuple(&(1, 2, 3)));
        assert!(de::is_tuple::<(usize, usize, usize)>());

        assert!(ser::is_tuple(&[1, 2, 3]));
        assert!(de::is_tuple::<[usize; 3]>());

        #[derive(Serialize, Deserialize)]
        struct TupleStruct<'a>(&'a str);
        assert!(ser::is_tuple(&TupleStruct("test")));
        assert!(de::is_tuple::<TupleStruct>());

        assert!(!ser::is_tuple(&vec![1, 2, 3]));
        assert!(!de::is_tuple::<Vec<usize>>());

        #[derive(Serialize, Deserialize)]
        struct UnitStruct;
        assert!(!ser::is_tuple(&UnitStruct));
        assert!(!de::is_tuple::<UnitStruct>());
    }
}
