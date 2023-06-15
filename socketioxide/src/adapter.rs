use engineioxide::utils::{Generator, Sid};
use futures::{stream, StreamExt};
use futures_core::stream::BoxStream;
use itertools::Itertools;
use serde::de::DeserializeOwned;
use std::{
    fmt::{Debug},
    hash::Hash,
    str::FromStr,
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock, Weak},
    time::Duration
};

use crate::{
    errors::{AckError, Error},
    handler::AckResponse,
    ns::Namespace,
    operators::RoomParam,
    packet::Packet,
    socket::Socket,
};

pub type Room = String;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum BroadcastFlags {
    Local,
    Broadcast,
    Timeout(Duration),
}
#[derive(Clone, Debug)]
pub struct BroadcastOptions<S: FromStr> {
    pub flags: HashSet<BroadcastFlags>,
    pub rooms: Vec<Room>,
    pub except: Vec<Room>,
    pub sid: S,
}
impl<S: FromStr> BroadcastOptions<S> {
    pub fn new(sid: S) -> Self {
        Self {
            flags: HashSet::new(),
            rooms: Vec::new(),
            except: Vec::new(),
            sid,
        }
    }
}

//TODO: Make an AsyncAdapter trait
pub trait Adapter: std::fmt::Debug + Send + Sync + 'static {
    type Sid: Sid;
    type G: Generator<Sid = Self::Sid>;

    fn new(ns: Weak<Namespace<Self>>, g: Self::G) -> Self
    where
        Self: Sized;
    fn init(&self);
    fn close(&self);

    fn server_count(&self) -> u16;

    fn add_all(&self, sid: Self::Sid, rooms: impl RoomParam);
    fn del(&self, sid: Self::Sid, rooms: impl RoomParam);
    fn del_all(&self, sid: Self::Sid);

    fn broadcast(
        &self,
        packet: Packet,
        binary: Vec<Vec<u8>>,
        opts: BroadcastOptions<Self::Sid>,
    ) -> Result<(), Error>;

    fn broadcast_with_ack<V: DeserializeOwned>(
        &self,
        packet: Packet,
        binary: Vec<Vec<u8>>,
        opts: BroadcastOptions<Self::Sid>,
    ) -> BoxStream<'static, Result<AckResponse<V>, AckError>>;

    fn sockets(&self, rooms: impl RoomParam) -> Vec<Self::Sid>;
    fn socket_rooms(&self, sid: Self::Sid) -> Vec<Room>;

    fn fetch_sockets(&self, opts: BroadcastOptions<Self::Sid>) -> Vec<Arc<Socket<Self>>>
    where
        Self: Sized;
    fn add_sockets(&self, opts: BroadcastOptions<Self::Sid>, rooms: impl RoomParam);
    fn del_sockets(&self, opts: BroadcastOptions<Self::Sid>, rooms: impl RoomParam);
    fn disconnect_socket(&self, opts: BroadcastOptions<Self::Sid>) -> Result<(), Error>;

    //TODO: implement
    // fn server_side_emit(&self, packet: Packet, opts: BroadcastOptions) -> Result<u64, Error>;
    // fn persist_session(&self, sid: i64);
    // fn restore_session(&self, sid: i64) -> Session;
}

#[derive(Debug)]
pub struct LocalAdapter<G: Generator> {
    rooms: RwLock<HashMap<Room, HashSet<G::Sid>>>,
    ns: Weak<Namespace<Self>>,
    g: G,
}

impl<G: Generator> Adapter for LocalAdapter<G> {
    type Sid = G::Sid;
    type G = G;

    fn new(ns: Weak<Namespace<Self>>, g: G) -> Self {
        Self {
            rooms: HashMap::new().into(),
            ns,
            g,
        }
    }

    fn init(&self) {}

    fn close(&self) {}

    fn server_count(&self) -> u16 {
        1
    }

    fn add_all(&self, sid: Self::Sid, rooms: impl RoomParam) {
        let mut rooms_map = self.rooms.write().unwrap();
        for room in rooms.into_room_iter() {
            rooms_map
                .entry(room)
                .or_insert_with(HashSet::new)
                .insert(sid.clone());
        }
    }

    fn del(&self, sid: Self::Sid, rooms: impl RoomParam) {
        let mut rooms_map = self.rooms.write().unwrap();
        for room in rooms.into_room_iter() {
            if let Some(room) = rooms_map.get_mut(&room) {
                room.remove(&sid);
            }
        }
    }

    fn del_all(&self, sid: Self::Sid) {
        let mut rooms_map = self.rooms.write().unwrap();
        for room in rooms_map.values_mut() {
            room.remove(&sid);
        }
    }

    fn broadcast(
        &self,
        packet: Packet,
        binary: Vec<Vec<u8>>,
        opts: BroadcastOptions<Self::Sid>,
    ) -> Result<(), Error> {
        let sockets = self.apply_opts(opts);

        tracing::debug!("broadcasting packet to {} sockets", sockets.len());
        sockets
            .into_iter()
            .try_for_each(|socket| socket.send(packet.clone(), binary.clone()))
    }

    fn broadcast_with_ack<V: DeserializeOwned>(
        &self,
        packet: Packet,
        binary: Vec<Vec<u8>>,
        opts: BroadcastOptions<Self::Sid>,
    ) -> BoxStream<'static, Result<AckResponse<V>, AckError>> {
        let duration = opts.flags.iter().find_map(|flag| match flag {
            BroadcastFlags::Timeout(duration) => Some(*duration),
            _ => None,
        });
        let sockets = self.apply_opts(opts);
        // tracing::debug!(
        //     "broadcasting packet to {} sockets: {}",
        //     sockets.len(),
        //     sockets.iter().map(|s| s.sid).collect::<Vec<_>>()
        // );
        let count = sockets.len();
        let ack_futs = sockets.into_iter().map(move |socket| {
            let packet = packet.clone();
            let binary = binary.clone();
            async move { socket.clone().send_with_ack(packet, binary, duration).await }
        });
        stream::iter(ack_futs).buffer_unordered(count).boxed()
    }

    fn sockets(&self, rooms: impl RoomParam) -> Vec<Self::Sid> {
        // TODO: fix this depending on the utilisation of the function
        let mut opts = BroadcastOptions::new(self.g.generate_sid());
        opts.rooms.extend(rooms.into_room_iter());
        self.apply_opts(opts)
            .into_iter()
            .map(|socket| socket.sid.clone())
            .collect()
    }

    //TODO: make this operation O(1)
    fn socket_rooms(&self, sid: Self::Sid) -> Vec<Room> {
        let rooms_map = self.rooms.read().unwrap();
        rooms_map
            .iter()
            .filter(|(_, sockets)| sockets.contains(&sid))
            .map(|(room, _)| room.clone())
            .collect()
    }

    fn fetch_sockets(&self, opts: BroadcastOptions<Self::Sid>) -> Vec<Arc<Socket<Self>>> {
        self.apply_opts(opts)
    }

    fn add_sockets(&self, opts: BroadcastOptions<Self::Sid>, rooms: impl RoomParam) {
        let rooms: Vec<Room> = rooms.into_room_iter().collect();
        for socket in self.apply_opts(opts) {
            self.add_all(socket.sid.clone(), rooms.clone());
        }
    }

    fn del_sockets(&self, opts: BroadcastOptions<Self::Sid>, rooms: impl RoomParam) {
        let rooms: Vec<Room> = rooms.into_room_iter().collect();
        for socket in self.apply_opts(opts) {
            self.del(socket.sid.clone(), rooms.clone());
        }
    }

    fn disconnect_socket(&self, opts: BroadcastOptions<Self::Sid>) -> Result<(), Error> {
        self.apply_opts(opts)
            .into_iter()
            .try_for_each(|socket| socket.disconnect())
    }
}

impl<G: Generator> LocalAdapter<G> {
    /// Apply the given `opts` and return the sockets that match.
    fn apply_opts(&self, opts: BroadcastOptions<G::Sid>) -> Vec<Arc<Socket<Self>>> {
        let rooms = opts.rooms;

        let except = self.get_except_sids(&opts.except);
        let ns = self.ns.upgrade().unwrap();
        if !rooms.is_empty() {
            let rooms_map = self.rooms.read().unwrap();
            rooms
                .iter()
                .filter_map(|room| rooms_map.get(room))
                .flatten()
                .unique()
                .filter(|sid| {
                    !except.contains(*sid)
                        && (!opts.flags.contains(&BroadcastFlags::Broadcast) || **sid != opts.sid)
                })
                .filter_map(|sid| ns.get_socket(sid.clone()).ok())
                .collect()
        } else if opts.flags.contains(&BroadcastFlags::Broadcast) {
            let sockets = ns.get_sockets();
            sockets
                .into_iter()
                .filter(|socket| !except.contains(&socket.sid))
                .collect()
        } else if let Ok(sock) = ns.get_socket(opts.sid) {
            vec![sock]
        } else {
            vec![]
        }
    }

    fn get_except_sids(&self, except: &Vec<Room>) -> HashSet<G::Sid> {
        let mut except_sids = HashSet::new();
        let rooms_map = self.rooms.read().unwrap();
        for room in except {
            if let Some(sockets) = rooms_map.get(room) {
                except_sids.extend(sockets.clone());
            }
        }
        except_sids
    }
}

#[cfg(test)]
mod test {
    use engineioxide::utils::SnowflakeGenerator;
    use super::*;

    #[test]
    fn test_server_count() {
        let ns = Namespace::new_dummy([], SnowflakeGenerator::default());
        let adapter: LocalAdapter<_> = LocalAdapter::new(Arc::downgrade(&ns), Default::default());
        assert_eq!(adapter.server_count(), 1);
    }

    #[test]
    fn test_add_all() {
        const SOCKET: i64 = 1;
        let g = SnowflakeGenerator::default();
        let ns = Namespace::new_dummy([SOCKET], g.clone());
        let adapter = LocalAdapter::new(Arc::downgrade(&ns), g.clone());
        adapter.add_all(SOCKET, ["room1", "room2"]);
        let rooms_map = adapter.rooms.read().unwrap();
        assert_eq!(rooms_map.len(), 2);
        assert_eq!(rooms_map.get("room1").unwrap().len(), 1);
        assert_eq!(rooms_map.get("room2").unwrap().len(), 1);
    }

    #[test]
    fn test_del() {
        const SOCKET: i64 = 1;
        let g = SnowflakeGenerator::default();
        let ns = Namespace::new_dummy([SOCKET],g.clone());
        let adapter = LocalAdapter::new(Arc::downgrade(&ns),g);
        adapter.add_all(SOCKET, ["room1", "room2"]);
        adapter.del(SOCKET, "room1");
        let rooms_map = adapter.rooms.read().unwrap();
        assert_eq!(rooms_map.len(), 2);
        assert_eq!(rooms_map.get("room1").unwrap().len(), 0);
        assert_eq!(rooms_map.get("room2").unwrap().len(), 1);
    }

    #[test]
    fn test_del_all() {
        const SOCKET: i64 = 1;
        let g = SnowflakeGenerator::default();
        let ns = Namespace::new_dummy([SOCKET],g.clone());
        let adapter = LocalAdapter::new(Arc::downgrade(&ns),g);
        adapter.add_all(SOCKET, ["room1", "room2"]);
        adapter.del_all(SOCKET);
        let rooms_map = adapter.rooms.read().unwrap();
        assert_eq!(rooms_map.len(), 2);
        assert_eq!(rooms_map.get("room1").unwrap().len(), 0);
        assert_eq!(rooms_map.get("room2").unwrap().len(), 0);
    }

    #[test]
    fn test_socket_room() {
        let g = SnowflakeGenerator::default();
        let ns = Namespace::new_dummy([1, 2, 3],g.clone());
        let adapter = LocalAdapter::new(Arc::downgrade(&ns),g);
        adapter.add_all(1, ["room1", "room2"]);
        adapter.add_all(2, ["room1"]);
        adapter.add_all(3, ["room2"]);
        assert!(adapter.socket_rooms(1).contains(&"room1".into()));
        assert!(adapter.socket_rooms(1).contains(&"room2".into()));
        assert_eq!(adapter.socket_rooms(2), ["room1"]);
        assert_eq!(adapter.socket_rooms(3), ["room2"]);
    }

    #[test]
    fn test_add_socket() {
        const SOCKET: i64 = 0;
        let g = SnowflakeGenerator::default();
        let ns = Namespace::new_dummy([SOCKET], g.clone());
        let adapter = LocalAdapter::new(Arc::downgrade(&ns), g);
        adapter.add_all(SOCKET, ["room1"]);

        let mut opts = BroadcastOptions::new(SOCKET);
        opts.rooms = vec!["room1".to_string()];
        adapter.add_sockets(opts, "room2");
        let rooms_map = adapter.rooms.read().unwrap();

        assert_eq!(rooms_map.len(), 2);
        assert!(rooms_map.get("room1").unwrap().contains(&SOCKET));
        assert!(rooms_map.get("room2").unwrap().contains(&SOCKET));
    }

    #[test]
    fn test_del_socket() {
        const SOCKET: i64 = 0;
        let g = SnowflakeGenerator::default();

        let ns = Namespace::new_dummy([SOCKET], g.clone());
        let adapter = LocalAdapter::new(Arc::downgrade(&ns),g);
        adapter.add_all(SOCKET, ["room1"]);

        let mut opts = BroadcastOptions::new(SOCKET);
        opts.rooms = vec!["room1".to_string()];
        adapter.add_sockets(opts, "room2");

        {
            let rooms_map = adapter.rooms.read().unwrap();

            assert_eq!(rooms_map.len(), 2);
            assert!(rooms_map.get("room1").unwrap().contains(&SOCKET));
            assert!(rooms_map.get("room2").unwrap().contains(&SOCKET));
        }

        let mut opts = BroadcastOptions::new(SOCKET);
        opts.rooms = vec!["room1".to_string()];
        adapter.del_sockets(opts, "room2");

        {
            let rooms_map = adapter.rooms.read().unwrap();

            assert_eq!(rooms_map.len(), 2);
            assert!(rooms_map.get("room1").unwrap().contains(&SOCKET));
            assert!(rooms_map.get("room2").unwrap().is_empty());
        }
    }

    #[test]
    fn test_sockets() {
        const SOCKET0: i64 = 0;
        const SOCKET1: i64 = 1;
        const SOCKET2: i64 = 2;
        let g = SnowflakeGenerator::default();

        let ns = Namespace::new_dummy([SOCKET0, SOCKET1, SOCKET2], g.clone());
        let adapter = LocalAdapter::new(Arc::downgrade(&ns), g);
        adapter.add_all(SOCKET0, ["room1", "room2"]);
        adapter.add_all(SOCKET1, ["room1", "room3"]);
        adapter.add_all(SOCKET2, ["room2", "room3"]);

        let sockets = adapter.sockets("room1");
        assert_eq!(sockets.len(), 2);
        assert!(sockets.contains(&SOCKET0));
        assert!(sockets.contains(&SOCKET1));

        let sockets = adapter.sockets("room2");
        assert_eq!(sockets.len(), 2);
        assert!(sockets.contains(&SOCKET0));
        assert!(sockets.contains(&SOCKET2));

        let sockets = adapter.sockets("room3");
        assert_eq!(sockets.len(), 2);
        assert!(sockets.contains(&SOCKET1));
        assert!(sockets.contains(&SOCKET2));
    }

    #[test]
    fn test_disconnect_socket() {
        const SOCKET0: i64 = 0;
        const SOCKET1: i64 = 1;
        const SOCKET2: i64 = 2;
        let g = SnowflakeGenerator::default();

        let ns = Namespace::new_dummy([SOCKET0, SOCKET1, SOCKET2], g.clone());
        let adapter = LocalAdapter::new(Arc::downgrade(&ns),g);
        adapter.add_all(SOCKET0, ["room1", "room2", "room4"]);
        adapter.add_all(SOCKET1, ["room1", "room3", "room5"]);
        adapter.add_all(SOCKET2, ["room2", "room3", "room6"]);

        let mut opts = BroadcastOptions::new(SOCKET0);
        opts.rooms = vec!["room5".to_string()];
        match adapter.disconnect_socket(opts) {
            Err(Error::EngineGone) | Ok(_) => {}
            e => panic!(
                "should return an EngineGone error as it is a stub namespace: {:?}",
                e
            ),
        }

        let sockets = adapter.sockets("room2");
        assert_eq!(sockets.len(), 2);
        assert!(sockets.contains(&SOCKET2));
        assert!(sockets.contains(&SOCKET0));
    }
    #[test]
    fn test_apply_opts() {
        const SOCKET0: i64 = 0;
        const SOCKET1: i64 = 1;
        const SOCKET2: i64 = 2;
        let g = SnowflakeGenerator::default();

        let ns = Namespace::new_dummy([SOCKET0, SOCKET1, SOCKET2],g.clone());
        let adapter = LocalAdapter::new(Arc::downgrade(&ns),g);
        // Add socket 0 to room1 and room2
        adapter.add_all(SOCKET0, ["room1", "room2"]);
        // Add socket 1 to room1 and room3
        adapter.add_all(SOCKET1, ["room1", "room3"]);
        // Add socket 2 to room2 and room3
        adapter.add_all(SOCKET2, ["room1", "room2", "room3"]);

        // Socket 2 is the sender
        let mut opts = BroadcastOptions::new(SOCKET2);
        opts.rooms = vec!["room1".to_string()];
        opts.except = vec!["room2".to_string()];
        let sockets = adapter.fetch_sockets(opts);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].sid, SOCKET1);

        let mut opts = BroadcastOptions::new(SOCKET2);
        opts.flags.insert(BroadcastFlags::Broadcast);
        opts.except = vec!["room2".to_string()];
        let sockets = adapter.fetch_sockets(opts);
        assert_eq!(sockets.len(), 1);

        let opts = BroadcastOptions::new(SOCKET2);
        let sockets = adapter.fetch_sockets(opts);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].sid, SOCKET2);

        let opts = BroadcastOptions::new(10000);
        let sockets = adapter.fetch_sockets(opts);
        assert_eq!(sockets.len(), 0);
    }
}
