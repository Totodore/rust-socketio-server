use std::{
    collections::HashMap,
    sync::{Arc, RwLock, Weak},
    time::Duration,
};

use crate::{
    ack::AckInnerStream,
    adapter::Adapter,
    client::SocketData,
    errors::{ConnectFail, Error},
    handler::{BoxedConnectHandler, ConnectHandler, MakeErasedHandler},
    packet::{ConnectPacket, Packet, PacketData},
    parser::Parser,
    socket::{DisconnectReason, Socket},
    ProtocolVersion,
};
use engineioxide::{sid::Sid, Str};
use socketioxide_core::{
    adapter::{CoreLocalAdapter, SocketEmitter},
    errors::SocketError,
    parser::Parse,
    Value,
};

/// A [`Namespace`] constructor used for dynamic namespaces
/// A namespace constructor only hold a common handler that will be cloned
/// to the instantiated namespaces.
pub struct NamespaceCtr<A: Adapter> {
    handler: BoxedConnectHandler<A>,
}
pub struct Namespace<A: Adapter> {
    pub path: Str,
    pub(crate) adapter: Arc<A>,
    parser: Parser,
    handler: BoxedConnectHandler<A>,
    sockets: RwLock<HashMap<Sid, Arc<Socket<A>>>>,
}

/// ===== impl NamespaceCtr =====
impl<A: Adapter> NamespaceCtr<A> {
    pub fn new<C, T>(handler: C) -> Self
    where
        C: ConnectHandler<A, T> + Send + Sync + 'static,
        T: Send + Sync + 'static,
    {
        Self {
            handler: MakeErasedHandler::new_ns_boxed(handler),
        }
    }
    pub fn get_new_ns(
        &self,
        path: Str,
        adapter_state: &A::State,
        parser: Parser,
    ) -> Arc<Namespace<A>> {
        Namespace::new_boxed(path, self.handler.boxed_clone(), adapter_state, parser)
    }
}

impl<A: Adapter> Namespace<A> {
    pub(crate) fn new<C, T>(
        path: Str,
        handler: C,
        adapter_state: &A::State,
        parser: Parser,
    ) -> Arc<Self>
    where
        C: ConnectHandler<A, T> + Send + Sync + 'static,
        T: Send + Sync + 'static,
    {
        let handler = MakeErasedHandler::new_ns_boxed(handler);
        Self::new_boxed(path, handler, adapter_state, parser)
    }

    fn new_boxed(
        path: Str,
        handler: BoxedConnectHandler<A>,
        adapter_state: &A::State,
        parser: Parser,
    ) -> Arc<Self> {
        Arc::new_cyclic(|ns| Self {
            path: path.clone(),
            handler,
            parser,
            sockets: HashMap::new().into(),
            adapter: Arc::new(A::new(
                adapter_state,
                CoreLocalAdapter::new(Emitter::new(ns.clone(), parser, path)),
            )),
        })
    }

    /// Connects a socket to a namespace.
    ///
    /// Middlewares are first called to check if the connection is allowed.
    /// * If the handler returns an error, a connect_error packet is sent to the client.
    /// * If the handler returns Ok, a connect packet is sent to the client
    ///   and the handler is called.
    pub(crate) async fn connect(
        self: Arc<Self>,
        sid: Sid,
        esocket: Arc<engineioxide::Socket<SocketData<A>>>,
        auth: Option<Value>,
    ) -> Result<(), ConnectFail> {
        let socket: Arc<Socket<A>> =
            Socket::new(sid, self.clone(), esocket.clone(), self.parser).into();

        if let Err(e) = self.handler.call_middleware(socket.clone(), &auth).await {
            #[cfg(feature = "tracing")]
            tracing::trace!(ns = self.path.as_str(), ?socket.id, "emitting connect_error packet");

            let data = e.to_string();
            if let Err(_e) = socket.send(Packet::connect_error(self.path.clone(), data)) {
                #[cfg(feature = "tracing")]
                tracing::debug!("error sending connect_error packet: {:?}, closing conn", _e);
                esocket.close(engineioxide::DisconnectReason::PacketParsingError);
            }
            return Err(ConnectFail);
        }

        self.sockets.write().unwrap().insert(sid, socket.clone());
        #[cfg(feature = "tracing")]
        tracing::trace!(?socket.id, ?self.path, "socket added to namespace");

        let protocol = esocket.protocol.into();
        let payload = ConnectPacket { sid: socket.id };
        let payload = match protocol {
            ProtocolVersion::V5 => Some(self.parser.encode_default(&payload).unwrap()),
            ProtocolVersion::V4 => None,
        };
        if let Err(_e) = socket.send(Packet::connect(self.path.clone(), payload)) {
            #[cfg(feature = "tracing")]
            tracing::debug!("error sending connect packet: {:?}, closing conn", _e);
            esocket.close(engineioxide::DisconnectReason::PacketParsingError);
            return Err(ConnectFail);
        }

        socket.set_connected(true);
        self.handler.call(socket, auth);

        Ok(())
    }

    /// Removes a socket from a namespace
    pub fn remove_socket(&self, sid: Sid) {
        #[cfg(feature = "tracing")]
        tracing::trace!(?sid, ?self.path, "removing socket from namespace");

        self.sockets.write().unwrap().remove(&sid);
        self.adapter.get_local().del_all(sid);
    }

    pub fn has(&self, sid: Sid) -> bool {
        self.sockets.read().unwrap().values().any(|s| s.id == sid)
    }

    pub fn recv(&self, sid: Sid, packet: PacketData) -> Result<(), Error> {
        match packet {
            PacketData::Connect(_) => unreachable!("connect packets should be handled before"),
            PacketData::ConnectError(_) => Err(Error::InvalidPacketType),
            packet => self.get_socket(sid)?.recv(packet),
        }
    }

    pub fn get_socket(&self, sid: Sid) -> Result<Arc<Socket<A>>, Error> {
        self.sockets
            .read()
            .unwrap()
            .get(&sid)
            .cloned()
            .ok_or(Error::SocketGone(sid))
    }

    pub fn get_sockets(&self) -> Vec<Arc<Socket<A>>> {
        self.sockets.read().unwrap().values().cloned().collect()
    }

    /// Closes the entire namespace :
    /// * Closes the adapter
    /// * Closes all the sockets and
    ///   their underlying connections in case of [`DisconnectReason::ClosingServer`]
    /// * Removes all the sockets from the namespace
    ///
    /// This function is using .await points only when called with [`DisconnectReason::ClosingServer`]
    pub async fn close(&self, reason: DisconnectReason) {
        use futures_util::future;
        let sockets = self.sockets.read().unwrap().clone();

        #[cfg(feature = "tracing")]
        tracing::debug!(?self.path, "closing {} sockets in namespace", sockets.len());

        if reason == DisconnectReason::ClosingServer {
            // When closing the underlying transport, this will indirectly close the socket
            // Therefore there is no need to manually call `s.close()`.
            future::join_all(sockets.values().map(|s| s.close_underlying_transport())).await;
        } else {
            for s in sockets.into_values() {
                let _sid = s.id;
                s.close(reason);
            }
        }
        #[cfg(feature = "tracing")]
        tracing::debug!(?self.path, "all sockets in namespace closed");

        let _err = self.adapter.close().await;
        #[cfg(feature = "tracing")]
        if let Err(err) = _err {
            tracing::debug!(?err, ?self.path, "could not close adapter");
        }
    }
}
/// A type erased emitter to discard the adapter type parameter `A`.
/// Otherwise it creates a cyclic dependency between the namespace, the emitter and the adapter.
trait InnerEmitter: Send + Sync + 'static {
    /// Get all the socket ids in the namespace.
    fn get_all_sids(&self) -> Vec<Sid>;
    /// Send data to the list of socket ids.
    fn send_many(&self, sids: Vec<Sid>, data: Value) -> Result<(), Vec<SocketError>>;
    /// Send data to the list of socket ids and get a stream of acks.
    fn send_many_with_ack(
        &self,
        sids: Vec<Sid>,
        packet: Packet,
        timeout: Option<Duration>,
    ) -> AckInnerStream;
    /// Disconnect all the sockets in the list.
    fn disconnect_many(&self, sid: Vec<Sid>) -> Result<(), Vec<SocketError>>;
}

impl<A: Adapter> InnerEmitter for Namespace<A> {
    fn get_all_sids(&self) -> Vec<Sid> {
        self.sockets.read().unwrap().keys().copied().collect()
    }

    fn send_many(&self, sids: Vec<Sid>, data: Value) -> Result<(), Vec<SocketError>> {
        let sockets = self.sockets.read().unwrap();
        let errs: Vec<crate::SocketError> = sids
            .iter()
            .filter_map(|sid| sockets.get(sid))
            .filter_map(|socket| socket.send_raw(data.clone()).err())
            .collect();
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs)
        }
    }

    fn send_many_with_ack(
        &self,
        sids: Vec<Sid>,
        packet: Packet,
        timeout: Option<Duration>,
    ) -> AckInnerStream {
        let sockets = self
            .sockets
            .read()
            .unwrap()
            .values()
            .filter(|s| sids.contains(&s.id))
            .cloned()
            .collect();
        AckInnerStream::broadcast(packet, sockets, timeout)
    }

    fn disconnect_many(&self, sids: Vec<Sid>) -> Result<(), Vec<SocketError>> {
        let sockets: Vec<Arc<Socket<A>>> = self
            .sockets
            .read()
            .unwrap()
            .values()
            .filter(|s| sids.contains(&s.id))
            .cloned()
            .collect();
        let errs = sockets
            .into_iter()
            .filter_map(|socket| socket.disconnect().err())
            .collect::<Vec<_>>();
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs)
        }
    }
}

/// Internal interface implementor to apply global operations on a namespace.
#[doc(hidden)]
pub struct Emitter {
    /// This `Weak<dyn>` allows to break the cyclic dependency between the namespace and the emitter.
    ns: Weak<dyn InnerEmitter>,
    parser: Parser,
    path: Str,
}

impl Emitter {
    fn new<A: Adapter>(ns: Weak<Namespace<A>>, parser: Parser, path: Str) -> Self {
        Self { ns, parser, path }
    }
}

impl SocketEmitter for Emitter {
    type AckError = crate::AckError;
    type AckStream = AckInnerStream;

    fn parser(&self) -> impl Parse {
        self.parser
    }

    fn send_many_with_ack(
        &self,
        sids: Vec<Sid>,
        packet: Packet,
        timeout: Option<Duration>,
    ) -> Self::AckStream {
        self.ns
            .upgrade()
            .map(|ns| ns.send_many_with_ack(sids, packet, timeout))
            .unwrap_or(AckInnerStream::empty())
    }

    fn send_many(&self, sids: Vec<Sid>, data: Value) -> Result<(), Vec<SocketError>> {
        match self.ns.upgrade() {
            Some(ns) => ns.send_many(sids, data),
            None => Ok(()),
        }
    }

    fn disconnect_many(&self, sids: Vec<Sid>) -> Result<(), Vec<SocketError>> {
        match self.ns.upgrade() {
            Some(ns) => ns.disconnect_many(sids),
            None => Ok(()),
        }
    }

    fn path(&self) -> &Str {
        &self.path
    }
    fn get_all_sids(&self) -> Vec<Sid> {
        self.ns
            .upgrade()
            .map(|ns| ns.get_all_sids())
            .unwrap_or_default()
    }
}

#[doc(hidden)]
#[cfg(feature = "__test_harness")]
impl Namespace<crate::adapter::LocalAdapter> {
    pub fn new_dummy<const S: usize>(sockets: [Sid; S]) -> Arc<Self> {
        let ns = Namespace::new("/".into(), || {}, &(), Parser::default());
        for sid in sockets {
            ns.sockets
                .write()
                .unwrap()
                .insert(sid, Socket::new_dummy(sid, ns.clone()).into());
        }
        ns
    }

    pub fn clean_dummy_sockets(&self) {
        self.sockets.write().unwrap().clear();
    }
}

impl<A: Adapter> std::fmt::Debug for Namespace<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Namespace")
            .field("path", &self.path)
            .field("sockets", &self.sockets)
            .finish()
    }
}

#[cfg(feature = "tracing")]
impl<A: Adapter> Drop for Namespace<A> {
    fn drop(&mut self) {
        #[cfg(feature = "tracing")]
        tracing::debug!("dropping namespace {}", self.path);
    }
}
