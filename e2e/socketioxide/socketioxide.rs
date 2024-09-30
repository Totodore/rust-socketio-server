//! This a end to end test server used with this [test suite](https://github.com/socketio/socket.io-protocol)

use std::time::Duration;

use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use rmpv::Value;
use socketioxide::{
    extract::{AckSender, Data, RawValue, SocketRef},
    SocketIo,
};
use tokio::net::TcpListener;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

fn on_connect(socket: SocketRef, Data(data): Data<Value>) {
    info!(?data, ns = socket.ns(), ?socket.id, "Socket.IO connected:");
    socket.emit("auth", &data).ok();

    socket.on("test", move |raw: RawValue| {
        let data: &str = raw.deserialize().unwrap();
    });

    socket.on("message", |socket: SocketRef, Data::<[Value; 3]>(data)| {
        info!(?data, "Received event:");
        socket.emit("message-back", &data).unwrap();
    });

    // keep this handler async to test async message handlers
    socket.on(
        "message-with-ack",
        |Data::<[Value; 3]>(data), ack: AckSender| async move {
            info!(?data, "Received event:");
            ack.send(&data).unwrap();
        },
    );

    socket.on(
        "emit-with-ack",
        |s: SocketRef, Data::<[Value; 3]>(data)| async move {
            info!(?data, "Received event:");
            let ack: [Value; 3] = s
                .emit_with_ack("emit-with-ack", &data)
                .unwrap()
                .await
                .unwrap();
            s.emit("emit-with-ack", &ack).unwrap();
        },
    );
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = FmtSubscriber::builder()
        .with_line_number(true)
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    #[allow(unused_mut)]
    let mut builder = SocketIo::builder()
        .ping_interval(Duration::from_millis(300))
        .ping_timeout(Duration::from_millis(200))
        .ack_timeout(Duration::from_millis(200))
        .connect_timeout(Duration::from_millis(1000))
        .max_payload(1e6 as u64);

    #[cfg(feature = "msgpack")]
    {
        builder = builder.with_parser(socketioxide::parser::Parser::MsgPack(Default::default()));
    };

    let (svc, io) = builder.build_svc();

    io.ns("/", on_connect);
    io.ns("/custom", on_connect);

    #[cfg(all(feature = "v5", feature = "msgpack"))]
    info!("Starting server with v5 protocol and msgpack parser");
    #[cfg(all(feature = "v5", not(feature = "msgpack")))]
    info!("Starting server with v5 protocol and common parser");
    #[cfg(all(feature = "v4", feature = "msgpack"))]
    info!("Starting server with v4 protocol and msgpack parser");
    #[cfg(all(feature = "v4", not(feature = "msgpack")))]
    info!("Starting server with v4 protocol and common parser");

    let listener = TcpListener::bind("127.0.0.1:3000").await?;

    // We start a loop to continuously accept incoming connections
    loop {
        let (stream, _) = listener.accept().await?;

        // Use an adapter to access something implementing `tokio::io` traits as if they implement
        // `hyper::rt` IO traits.
        let io = TokioIo::new(stream);
        let svc = svc.clone();

        // Spawn a tokio task to serve multiple connections concurrently
        tokio::task::spawn(async move {
            // Finally, we bind the incoming connection to our `hello` service
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, svc)
                .with_upgrades()
                .await
            {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}
