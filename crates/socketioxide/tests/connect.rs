mod utils;

use bytes::Bytes;
use engineioxide::Packet::*;
use serde::Serialize;
use socketioxide::{
    extract::SocketRef, handler::ConnectHandler, packet::Packet, SendError, SocketError, SocketIo,
};
use socketioxide_core::{parser::Parse, Value};
use socketioxide_parser_common::CommonParser;
use tokio::sync::mpsc;

fn create_msg(ns: &'static str, event: &str, data: impl Serialize) -> engineioxide::Packet {
    let parser = CommonParser::default();
    let packet = Packet::event(ns, parser.encode_value(&data, Some(event)).unwrap());
    match parser.encode(packet) {
        Value::Str(data, _) => Message(data),
        Value::Bytes(_) => unreachable!(),
    }
}
async fn timeout_rcv<T: std::fmt::Debug>(srx: &mut tokio::sync::mpsc::Receiver<T>) -> T {
    tokio::time::timeout(std::time::Duration::from_millis(10), srx.recv())
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
pub async fn connect_middleware() {
    let (_svc, io) = SocketIo::new_svc();
    let (tx, mut rx) = mpsc::channel::<usize>(100);

    let handler = |i: usize| {
        let tx1 = tx.clone();
        move |s: SocketRef| {
            // Socket should be closed for all emit methods on it

            assert!(matches!(
                s.emit("test", &()),
                Err(SendError::Socket(SocketError::Closed))
            ));

            assert!(matches!(
                s.emit_with_ack::<_, ()>("test", &()),
                Err(SendError::Socket(SocketError::Closed))
            ));

            assert!(matches!(
                s.emit("test", &(0, 1, 2, 3)),
                Err(SendError::Socket(SocketError::Closed))
            ));
            assert!(matches!(
                s.emit_with_ack::<_, ()>("test", &Bytes::from_static(&[0, 1, 2, 3])),
                Err(SendError::Socket(SocketError::Closed))
            ));

            tx1.try_send(i).unwrap();
            Ok::<_, std::convert::Infallible>(())
        }
    };
    io.ns(
        "/",
        { || {} }.with(handler(3)).with(handler(2)).with(handler(1)),
    );

    let (_, mut srx) = io.new_dummy_sock("/", ()).await;
    assert_eq!(rx.recv().await.unwrap(), 1);
    assert_eq!(rx.recv().await.unwrap(), 2);
    assert_eq!(rx.recv().await.unwrap(), 3);

    let p = assert_some!(srx.recv().await);
    assert!(matches!(p, Message(s) if s.starts_with('0')));

    assert_err!(rx.try_recv());
}

#[tokio::test]
pub async fn connect_middleware_error() {
    let (_svc, io) = SocketIo::new_svc();
    let (tx, mut rx) = mpsc::channel::<usize>(100);
    #[derive(Debug)]
    struct MyError;

    impl std::fmt::Display for MyError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "MyError")
        }
    }

    let handler = |i: usize, e: bool| {
        let tx1 = tx.clone();
        move || {
            tx1.try_send(i).unwrap();
            if e {
                Err(MyError)
            } else {
                Ok(())
            }
        }
    };

    io.ns(
        "/",
        { || {} }
            .with(handler(3, false))
            .with(handler(2, true))
            .with(handler(1, false)),
    );

    let (_, mut srx) = io.new_dummy_sock("/", ()).await;

    let p = assert_some!(srx.recv().await);
    assert_eq!(p, Message("4{\"message\":\"MyError\"}".into()));
    rx.recv().await.unwrap();
    rx.recv().await.unwrap();
    assert_err!(rx.try_recv());
}

#[tokio::test]
async fn ns_dyn_connect() {
    let (_svc, io) = SocketIo::new_svc();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(1);

    io.dyn_ns("/admin/{id}/board", move |s: SocketRef| {
        tx.try_send(s.ns().to_string()).unwrap();
    })
    .unwrap();

    let (_stx, mut _srx) = io.new_dummy_sock("/admin/132/board", ()).await;
    assert_eq!(timeout_rcv(&mut rx).await, "/admin/132/board");
}
#[tokio::test]
async fn ns_dyn_connect_precedence() {
    let (_svc, io) = SocketIo::new_svc();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<bool>(1);
    let tx_clone = tx.clone();

    io.dyn_ns("/admin/{id}/board", move || {
        tx.try_send(false).unwrap();
    })
    .unwrap();
    io.ns("/admin/test/board", move || {
        tx_clone.try_send(true).unwrap();
    });

    let (_stx, mut _srx) = io.new_dummy_sock("/admin/test/board", ()).await;
    assert!(timeout_rcv(&mut rx).await);
}

#[tokio::test]
async fn remove_ns_from_connect_handler() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(2);
    let (_svc, io) = SocketIo::new_svc();

    io.ns("/test1", move |io: SocketIo| {
        tx.try_send(()).unwrap();
        io.delete_ns("/test1");
    });

    let (stx, mut srx) = io.new_dummy_sock("/test1", ()).await;
    timeout_rcv(&mut srx).await;
    assert_ok!(stx.try_send(create_msg("/test1", "delete_ns", ())));
    timeout_rcv(&mut rx).await;
    assert_ok!(stx.try_send(create_msg("/test1", "delete_ns", ())));
    // No response since ns is already deleted
    let elapsed = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await;
    assert!(elapsed.is_err() || elapsed.unwrap().is_none());
}

#[tokio::test]
async fn remove_ns_from_middleware() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(2);
    let (_svc, io) = SocketIo::new_svc();

    let middleware = move |io: SocketIo| {
        tx.try_send(()).unwrap();
        io.delete_ns("/test1");
        Ok::<(), std::convert::Infallible>(())
    };
    fn handler() {}
    io.ns("/test1", handler.with(middleware));

    let (stx, mut srx) = io.new_dummy_sock("/test1", ()).await;
    timeout_rcv(&mut srx).await;
    assert_ok!(stx.try_send(create_msg("/test1", "delete_ns", ())));
    timeout_rcv(&mut rx).await;
    assert_ok!(stx.try_send(create_msg("/test1", "delete_ns", ())));
    // No response since ns is already deleted
    let elapsed = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await;
    assert!(elapsed.is_err() || elapsed.unwrap().is_none());
}

#[tokio::test]
async fn remove_ns_from_event_handler() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(2);
    let (_svc, io) = SocketIo::new_svc();

    io.ns("/test1", move |s: SocketRef, io: SocketIo| {
        s.on("delete_ns", move || {
            io.delete_ns("/test1");
            tx.try_send(()).unwrap();
        });
    });

    let (stx, mut srx) = io.new_dummy_sock("/test1", ()).await;
    timeout_rcv(&mut srx).await;
    assert_ok!(stx.try_send(create_msg("/test1", "delete_ns", ())));
    timeout_rcv(&mut rx).await;
    assert_ok!(stx.try_send(create_msg("/test1", "delete_ns", ())));
    // No response since ns is already deleted
    let elapsed = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await;
    assert!(elapsed.is_err() || elapsed.unwrap().is_none());
}

#[tokio::test]
async fn remove_ns_from_disconnect_handler() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<&'static str>(2);
    let (_svc, io) = SocketIo::new_svc();

    io.ns("/test2", move |s: SocketRef, io: SocketIo| {
        tx.try_send("connect").unwrap();
        s.on_disconnect(move || {
            io.delete_ns("/test2");
            tx.try_send("disconnect").unwrap();
        })
    });

    let (stx, mut srx) = io.new_dummy_sock("/test2", ()).await;
    assert_eq!(timeout_rcv(&mut rx).await, "connect");
    timeout_rcv(&mut srx).await;
    assert_ok!(stx.try_send(Close));
    assert_eq!(timeout_rcv(&mut rx).await, "disconnect");

    let (_stx, mut _srx) = io.new_dummy_sock("/test2", ()).await;
    let elapsed = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await;
    assert!(elapsed.is_err() || elapsed.unwrap().is_none());
}
