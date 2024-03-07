use std::{net::SocketAddr, path::PathBuf};

use axum::routing::get;
use axum_server::tls_rustls::RustlsConfig;
use socketioxide::{
    extract::{AckSender, Data, SocketRef},
    PayloadValue, SocketIo,
};
use tracing::info;
use tracing_subscriber::FmtSubscriber;

fn on_connect(socket: SocketRef, Data(data): Data<PayloadValue>) {
    info!("Socket.IO connected: {:?} {:?}", socket.ns(), socket.id);
    socket.emit("auth", data).ok();

    socket.on(
        "message",
        |socket: SocketRef, Data::<PayloadValue>(data)| {
            info!("Received event: {:?}", data);
            socket.emit("message-back", data).ok();
        },
    );

    socket.on(
        "message-with-ack",
        |ack: AckSender, Data::<PayloadValue>(data)| {
            info!("Received event: {:?}", data);
            ack.send(data).ok();
        },
    );
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing::subscriber::set_global_default(FmtSubscriber::default())?;

    // configure certificate and private key used by https
    let config = RustlsConfig::from_pem_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("self_signed_certs")
            .join("cert.pem"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("self_signed_certs")
            .join("key.pem"),
    )
    .await
    .unwrap();

    let (layer, io) = SocketIo::new_layer();

    io.ns("/", on_connect);
    io.ns("/custom", on_connect);

    let app = axum::Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .layer(layer);

    info!("Starting server");

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}
