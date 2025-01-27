use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use bytes::Bytes;
use engineioxide::handler::EngineIoHandler;
use engineioxide::socket::{DisconnectReason as EIoDisconnectReason, Socket as EIoSocket};
use engineioxide::Str;
use futures_util::{FutureExt, TryFutureExt};

use engineioxide::sid::Sid;
use matchit::{Match, Router};
use socketioxide_core::packet::{Packet, PacketData};
use socketioxide_core::parser::{Parse, ParserState};
use socketioxide_core::Value;
use tokio::sync::oneshot;

use crate::{
    adapter::Adapter,
    errors::Error,
    handler::ConnectHandler,
    ns::{Namespace, NamespaceCtr},
    parser::{ParseError, Parser},
    socket::DisconnectReason,
    ProtocolVersion, SocketIo, SocketIoConfig,
};

pub struct Client<A: Adapter> {
    pub(crate) config: SocketIoConfig,
    nsps: RwLock<HashMap<Str, Arc<Namespace<A>>>>,
    router: RwLock<Router<NamespaceCtr<A>>>,
    adapter_state: A::State,

    #[cfg(feature = "state")]
    pub(crate) state: state::TypeMap![Send + Sync],
}

// ==== impl Client ====

impl<A: Adapter> Client<A> {
    pub fn new(
        config: SocketIoConfig,
        adapter_state: A::State,
        #[cfg(feature = "state")] mut state: state::TypeMap![Send + Sync],
    ) -> Self {
        #[cfg(feature = "state")]
        state.freeze();

        Self {
            config,
            nsps: RwLock::new(HashMap::new()),
            router: RwLock::new(Router::new()),
            adapter_state,
            #[cfg(feature = "state")]
            state,
        }
    }

    /// Called when a socket connects to a new namespace.
    ///
    /// We take the namespace path by reference to avoid holding the connect packet for the
    /// lifetime of the connect packet
    fn sock_connect(
        self: &Arc<Self>,
        auth: Option<Value>,
        ns_path: &str,
        esocket: &Arc<engineioxide::Socket<SocketData<A>>>,
    ) {
        #[cfg(feature = "tracing")]
        tracing::debug!("auth: {:?}", auth);
        let protocol: ProtocolVersion = esocket.protocol.into();
        let connect =
            move |ns: Arc<Namespace<A>>, esocket: Arc<engineioxide::Socket<SocketData<A>>>| async move {
                if ns.connect(esocket.id, esocket.clone(), auth).await.is_ok() {
                    // cancel the connect timeout task for v5
                    if let Some(tx) = esocket.data.connect_recv_tx.lock().unwrap().take() {
                        tx.send(()).ok();
                    }
                }
            };

        if let Some(ns) = self.get_ns(&ns_path) {
            tokio::spawn(connect(ns, esocket.clone()));
        } else if let Ok(Match { value: ns_ctr, .. }) = self.router.read().unwrap().at(&ns_path) {
            let path = Str::copy_from_slice(ns_path);
            let ns = ns_ctr.get_new_ns(path.clone(), &self.adapter_state, &self.config);
            let this = self.clone();
            let esocket = esocket.clone();
            let adapter = ns.adapter.clone();
            let on_success = move || {
                this.nsps.write().unwrap().insert(path, ns.clone());
                tokio::spawn(connect(ns, esocket));
            };
            // We "ask" the adapter implementation to manage the init response itself
            socketioxide_core::adapter::Spawnable::spawn(adapter.init(on_success));
        } else if protocol == ProtocolVersion::V4 && ns_path == "/" {
            #[cfg(feature = "tracing")]
            tracing::error!(
                "the root namespace \"/\" must be defined before any connection for protocol V4 (legacy)!"
            );
            esocket.close(EIoDisconnectReason::TransportClose);
        } else {
            let path = Str::copy_from_slice(ns_path);
            let packet = self
                .parser()
                .encode(Packet::connect_error(path, "Invalid namespace"));
            let _ = match packet {
                Value::Str(p, _) => esocket.emit(p).map_err(|_e| {
                    #[cfg(feature = "tracing")]
                    tracing::error!("error while sending invalid namespace packet: {}", _e);
                }),
                Value::Bytes(p) => esocket.emit_binary(p).map_err(|_e| {
                    #[cfg(feature = "tracing")]
                    tracing::error!("error while sending invalid namespace packet: {}", _e);
                }),
            };
        }
    }

    /// Propagate a packet to its target namespace
    fn sock_propagate_packet(&self, packet: Packet, sid: Sid) -> Result<(), Error> {
        if let Some(ns) = self.get_ns(&packet.ns) {
            ns.recv(sid, packet.inner)
        } else {
            #[cfg(feature = "tracing")]
            tracing::debug!(?sid, "invalid namespace requested: {}", packet.ns);
            Ok(())
        }
    }

    /// Spawn a task that will close the socket if it is not connected to a namespace
    /// after the [`SocketIoConfig::connect_timeout`] duration
    fn spawn_connect_timeout_task(&self, socket: Arc<EIoSocket<SocketData<A>>>) {
        #[cfg(feature = "tracing")]
        tracing::debug!("spawning connect timeout task");
        let (tx, rx) = oneshot::channel();
        socket.data.connect_recv_tx.lock().unwrap().replace(tx);

        tokio::spawn(
            tokio::time::timeout(self.config.connect_timeout, rx).map_err(move |_| {
                #[cfg(feature = "tracing")]
                tracing::debug!("connect timeout for socket {}", socket.id);
                socket.close(EIoDisconnectReason::TransportClose);
            }),
        );
    }

    /// Adds a new namespace handler
    pub fn add_ns<C, T>(self: Arc<Self>, path: Cow<'static, str>, callback: C) -> A::InitRes
    where
        C: ConnectHandler<A, T>,
        T: Send + Sync + 'static,
    {
        #[cfg(feature = "tracing")]
        tracing::debug!("adding namespace {}", path);

        let ns_path = Str::from(&path);
        let ns = Namespace::new(ns_path.clone(), callback, &self.adapter_state, &self.config);
        let adapter = ns.adapter.clone();
        let on_success = move || {
            self.nsps.write().unwrap().insert(ns_path, ns);
        };
        adapter.init(on_success)
    }

    pub fn add_dyn_ns<C, T>(&self, path: String, callback: C) -> Result<(), matchit::InsertError>
    where
        C: ConnectHandler<A, T>,
        T: Send + Sync + 'static,
    {
        #[cfg(feature = "tracing")]
        tracing::debug!("adding dynamic namespace {}", &path);

        let ns = NamespaceCtr::new(callback);
        self.router.write().unwrap().insert(path, ns)
    }

    /// Deletes a namespace handler and closes all the connections to it
    pub fn delete_ns(&self, path: &str) {
        #[cfg(feature = "v4")]
        if path == "/" {
            panic!("the root namespace \"/\" cannot be deleted for the socket.io v4 protocol. See https://socket.io/docs/v3/namespaces/#main-namespace for more info");
        }

        #[cfg(feature = "tracing")]
        tracing::debug!("deleting namespace {}", path);
        if let Some(ns) = self.nsps.write().unwrap().remove(path) {
            ns.close(DisconnectReason::ServerNSDisconnect)
                .now_or_never();
        }
    }

    pub fn get_ns(&self, path: &str) -> Option<Arc<Namespace<A>>> {
        self.nsps.read().unwrap().get(path).cloned()
    }

    /// Closes all engine.io connections and all clients
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub(crate) async fn close(&self) {
        #[cfg(feature = "tracing")]
        tracing::debug!("closing all namespaces");
        let ns = { std::mem::take(&mut *self.nsps.write().unwrap()) };
        futures_util::future::join_all(
            ns.values()
                .map(|ns| ns.close(DisconnectReason::ClosingServer)),
        )
        .await;
        #[cfg(feature = "tracing")]
        tracing::debug!("all namespaces closed");
    }

    pub(crate) fn parser(&self) -> Parser {
        self.config.parser
    }
}

#[derive(Debug)]
pub struct SocketData<A: Adapter> {
    pub parser_state: ParserState,
    /// Channel used to notify the socket that it has been connected to a namespace for v5
    pub connect_recv_tx: Mutex<Option<oneshot::Sender<()>>>,

    /// Used to store the [`SocketIo`] instance so it can be accessed by any sockets
    pub io: OnceLock<SocketIo<A>>,
}
impl<A: Adapter> Default for SocketData<A> {
    fn default() -> Self {
        Self {
            parser_state: ParserState::default(),
            connect_recv_tx: Mutex::new(None),
            io: OnceLock::new(),
        }
    }
}

impl<A: Adapter> EngineIoHandler for Client<A> {
    type Data = SocketData<A>;

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, socket), fields(sid = socket.id.to_string())))]
    fn on_connect(self: Arc<Self>, socket: Arc<EIoSocket<SocketData<A>>>) {
        socket.data.io.set(SocketIo::from(self.clone())).ok();

        #[cfg(feature = "tracing")]
        tracing::debug!("eio socket connect");

        let protocol: ProtocolVersion = socket.protocol.into();

        // Connecting the client to the default namespace is mandatory if the SocketIO protocol is v4.
        // Because we connect by default to the root namespace, we should ensure before that the root namespace is defined
        match protocol {
            ProtocolVersion::V4 => {
                #[cfg(feature = "tracing")]
                tracing::debug!("connecting to default namespace for v4");
                self.sock_connect(None, "/", &socket);
            }
            ProtocolVersion::V5 => self.spawn_connect_timeout_task(socket),
        }
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, socket), fields(sid = socket.id.to_string())))]
    fn on_disconnect(&self, socket: Arc<EIoSocket<SocketData<A>>>, reason: EIoDisconnectReason) {
        #[cfg(feature = "tracing")]
        tracing::debug!("eio socket disconnected");
        let socks: Vec<_> = self
            .nsps
            .read()
            .unwrap()
            .values()
            .filter_map(|ns| ns.get_socket(socket.id).ok())
            .collect();

        let _cnt = socks
            .into_iter()
            .map(|s| s.close(reason.clone().into()))
            .count();

        #[cfg(feature = "tracing")]
        tracing::debug!("disconnect handle spawned for {_cnt} namespaces");
    }

    fn on_message(self: &Arc<Self>, msg: Str, socket: Arc<EIoSocket<SocketData<A>>>) {
        let msg = Str::copy_from_slice(&msg);

        #[cfg(feature = "tracing")]
        tracing::debug!("received message: {:?}", msg);
        let packet = match self.parser().decode_str(&socket.data.parser_state, msg) {
            Ok(packet) => packet,
            Err(ParseError::NeedsMoreBinaryData) => return,
            Err(_e) => {
                #[cfg(feature = "tracing")]
                tracing::debug!("socket deserialization error: {}", _e);
                socket.close(EIoDisconnectReason::PacketParsingError);
                return;
            }
        };
        #[cfg(feature = "tracing")]
        tracing::debug!("Packet: {:?}", packet);

        let res: Result<(), Error> = match packet.inner {
            PacketData::Connect(auth) => {
                self.sock_connect(auth, &packet.ns, &socket);
                Ok(())
            }
            _ => self.sock_propagate_packet(packet, socket.id),
        };
        if let Err(ref err) = res {
            #[cfg(feature = "tracing")]
            tracing::debug!(
                "error while processing packet to socket {}: {}",
                socket.id,
                err
            );
            if let Some(reason) = err.into() {
                socket.close(reason);
            }
        }
    }

    /// When a binary payload is received from a socket, it is applied to the partial binary packet
    ///
    /// If the packet is complete, it is propagated to the namespace
    fn on_binary(self: &Arc<Self>, data: Bytes, socket: Arc<EIoSocket<SocketData<A>>>) {
        let data = Bytes::copy_from_slice(&data);
        #[cfg(feature = "tracing")]
        tracing::debug!("received binary: {:?}", &data);
        let packet = match self.parser().decode_bin(&socket.data.parser_state, data) {
            Ok(packet) => packet,
            Err(ParseError::NeedsMoreBinaryData) => return,
            Err(_e) => {
                #[cfg(feature = "tracing")]
                tracing::debug!("socket deserialization error: {}", _e);
                socket.close(EIoDisconnectReason::PacketParsingError);
                return;
            }
        };

        let res: Result<(), Error> = match packet.inner {
            PacketData::Connect(auth) => {
                self.sock_connect(auth, &packet.ns, &socket);
                Ok(())
            }
            _ => self.sock_propagate_packet(packet, socket.id),
        };
        if let Err(ref err) = res {
            #[cfg(feature = "tracing")]
            tracing::debug!(
                "error while propagating packet to socket {}: {}",
                socket.id,
                err
            );
            if let Some(reason) = err.into() {
                socket.close(reason);
            }
        }
    }
}
impl<A: Adapter> std::fmt::Debug for Client<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut f = f.debug_struct("Client");
        f.field("config", &self.config).field("nsps", &self.nsps);
        #[cfg(feature = "state")]
        let f = f.field("state", &self.state);
        f.finish()
    }
}

#[doc(hidden)]
#[cfg(feature = "__test_harness")]
impl<A: Adapter> Client<A> {
    pub async fn new_dummy_sock(
        self: Arc<Self>,
        ns: &'static str,
        auth: impl serde::Serialize,
    ) -> (
        tokio::sync::mpsc::Sender<engineioxide::Packet>,
        tokio::sync::mpsc::Receiver<engineioxide::Packet>,
    ) {
        let buffer_size = self.config.engine_config.max_buffer_size;
        let sid = Sid::new();
        let (esock, rx) =
            EIoSocket::<SocketData<A>>::new_dummy_piped(sid, Box::new(|_, _| {}), buffer_size);
        esock.data.io.set(SocketIo::from(self.clone())).ok();
        let (tx1, mut rx1) = tokio::sync::mpsc::channel(buffer_size);
        tokio::spawn({
            let esock = esock.clone();
            let client = self.clone();
            async move {
                while let Some(packet) = rx1.recv().await {
                    match packet {
                        engineioxide::Packet::Message(msg) => {
                            client.on_message(msg, esock.clone());
                        }
                        engineioxide::Packet::Close => {
                            client
                                .on_disconnect(esock.clone(), EIoDisconnectReason::TransportClose);
                        }
                        engineioxide::Packet::Binary(bin) => {
                            client.on_binary(bin, esock.clone());
                        }
                        _ => {}
                    }
                }
            }
        });
        let parser = crate::parser::Parser::default();
        let val = parser.encode(Packet {
            ns: ns.into(),
            inner: PacketData::Connect(Some(parser.encode_default(&auth).unwrap())),
        });
        if let Value::Str(s, _) = val {
            self.on_message(s, esock.clone());
        }

        // wait for the socket to be connected to the namespace
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        (tx1, rx)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use tokio::sync::mpsc;

    use crate::adapter::LocalAdapter;
    const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(50);

    fn create_client() -> Arc<super::Client<LocalAdapter>> {
        let config = crate::SocketIoConfig {
            connect_timeout: CONNECT_TIMEOUT,
            ..Default::default()
        };
        let client = Client::new(
            config,
            (),
            #[cfg(feature = "state")]
            Default::default(),
        );
        let client = Arc::new(client);
        client.clone().add_ns("/".into(), || {});
        client
    }

    #[tokio::test]
    async fn get_ns() {
        let client = create_client();
        let ns = Namespace::new(Str::from("/"), || {}, &client.adapter_state, &client.config);
        client.nsps.write().unwrap().insert(Str::from("/"), ns);
        assert!(client.get_ns("/").is_some());
    }

    #[tokio::test]
    async fn io_should_always_be_set() {
        let client = create_client();
        let close_fn = Box::new(move |_, _| {});
        let sock = EIoSocket::new_dummy(Sid::new(), close_fn);
        client.on_connect(sock.clone());
        assert!(sock.data.io.get().is_some());
    }

    #[tokio::test]
    async fn connect_timeout_fail() {
        let client = create_client();
        let (close_tx, mut close_rx) = mpsc::channel(1);
        let close_fn = Box::new(move |_, reason| close_tx.try_send(reason).unwrap());
        let sock = EIoSocket::new_dummy(Sid::new(), close_fn);
        client.on_connect(sock.clone());
        // The socket is closed
        let res = tokio::time::timeout(CONNECT_TIMEOUT * 2, close_rx.recv())
            .await
            .unwrap();
        // applied in case of ns timeout
        assert_eq!(res, Some(EIoDisconnectReason::TransportClose));
    }

    #[tokio::test]
    async fn connect_timeout() {
        let client = create_client();
        let (close_tx, mut close_rx) = mpsc::channel(1);
        let close_fn = Box::new(move |_, reason| close_tx.try_send(reason).unwrap());
        let sock = EIoSocket::new_dummy(Sid::new(), close_fn);
        client.clone().on_connect(sock.clone());
        client.on_message("0".into(), sock.clone());
        // The socket is not closed.
        tokio::time::timeout(CONNECT_TIMEOUT * 2, close_rx.recv())
            .await
            .unwrap_err();
    }
}
