//! ### Extractors for [`ConnectHandler`], [`ConnectMiddleware`], [`MessageHandler`] and [`DisconnectHandler`](crate::handler::DisconnectHandler).
//!
//! They can be used to extract data from the context of the handler and get specific params. Here are some examples of extractors:
//! * [`Data`]: extracts and deserialize to json any data, if a deserialization error occurs the handler won't be called:
//!     - for [`ConnectHandler`]: extracts and deserialize to json the auth data
//!     - for [`ConnectMiddleware`]: extract and deserialize to json the auth data.
//! In case of error, the middleware chain stops and a `connect_error` event is sent.
//!     - for [`MessageHandler`]: extracts and deserialize to json the message data
//! * [`TryData`]: extracts and deserialize to json any data but with a `Result` type in case of error:
//!     - for [`ConnectHandler`] and [`ConnectMiddleware`]:
//! extracts and deserialize to json the auth data
//!     - for [`MessageHandler`]: extracts and deserialize to json the message data
//! * [`SocketRef`]: extracts a reference to the [`Socket`](crate::socket::Socket)
//! * [`Bin`]: extract a binary payload for a given message. Because it consumes the event it should be the last argument
//! * [`AckSender`]: Can be used to send an ack response to the current message event
//! * [`ProtocolVersion`](crate::ProtocolVersion): extracts the protocol version
//! * [`TransportType`](crate::TransportType): extracts the transport type
//! * [`DisconnectReason`](crate::socket::DisconnectReason): extracts the reason of the disconnection
//! * [`State`]: extracts a [`Clone`] of a state previously set with [`SocketIoBuilder::with_state`](crate::io::SocketIoBuilder).
//! * [`Extension`]: extracts an extension of the given type stored on the called socket by cloning it.
//! * [`MaybeExtension`]: extracts an extension of the given type if it exists or [`None`] otherwise
//! * [`HttpExtension`]: extracts an http extension of the given type coming from the request.
//! (Similar to axum's [`extract::Extension`](https://docs.rs/axum/latest/axum/struct.Extension.html)
//! * [`MaybeHttpExtension`]: extracts an http extension of the given type if it exists or [`None`] otherwise.
//! * [`NsParam`]: extracts and deserialize the namespace path parameters. Works only for the [`ConnectHandler`] and [`ConnectMiddleware`].
//!
//! ### You can also implement your own Extractor with the [`FromConnectParts`], [`FromMessageParts`] and [`FromDisconnectParts`] traits
//! When implementing these traits, if you clone the [`Arc<Socket>`](crate::socket::Socket) make sure that it is dropped at least when the socket is disconnected.
//! Otherwise it will create a memory leak. It is why the [`SocketRef`] extractor is used instead of cloning the socket for common usage.
//!
//! [`FromConnectParts`]: crate::handler::FromConnectParts
//! [`FromMessageParts`]: crate::handler::FromMessageParts
//! [`FromDisconnectParts`]: crate::handler::FromDisconnectParts
//! [`ConnectHandler`]: crate::handler::ConnectHandler
//! [`ConnectMiddleware`]: crate::handler::ConnectMiddleware
//! [`MessageHandler`]: crate::handler::MessageHandler
//! [`DisconnectHandler`]: crate::handler::DisconnectHandler
//!
//! #### Example that extracts a user id from the query params
//! ```rust
//! # use bytes::Bytes;
//! # use socketioxide::handler::{FromConnectParts, FromMessageParts};
//! # use socketioxide::adapter::Adapter;
//! # use socketioxide::socket::Socket;
//! # use std::sync::Arc;
//! # use std::convert::Infallible;
//! # use socketioxide::SocketIo;
//!
//! struct UserId(String);
//!
//! #[derive(Debug)]
//! struct UserIdNotFound;
//! impl std::fmt::Display for UserIdNotFound {
//!     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//!         write!(f, "User id not found")
//!     }
//! }
//! impl std::error::Error for UserIdNotFound {}
//!
//! impl<A: Adapter> FromConnectParts<A> for UserId {
//!     type Error = Infallible;
//!     fn from_connect_parts(s: &Arc<Socket<A>>, _: &Option<String>, _: &NsParamBuff<'_>) -> Result<Self, Self::Error> {
//!         // In a real app it would be better to parse the query params with a crate like `url`
//!         let uri = &s.req_parts().uri;
//!         let uid = uri
//!             .query()
//!             .and_then(|s| s.split('&').find(|s| s.starts_with("id=")).map(|s| &s[3..]))
//!             .unwrap_or_default();
//!         // Currently, it is not possible to have lifetime on the extracted data
//!         Ok(UserId(uid.to_string()))
//!     }
//! }
//!
//! // Here, if the user id is not found, the handler won't be called
//! // and a tracing `error` log will be emitted (if the `tracing` feature is enabled)
//! impl<A: Adapter> FromMessageParts<A> for UserId {
//!     type Error = UserIdNotFound;
//!
//!     fn from_message_parts(
//!         s: &Arc<Socket<A>>,
//!         _: &mut serde_json::Value,
//!         _: &mut Vec<Bytes>,
//!         _: &Option<i64>,
//!     ) -> Result<Self, UserIdNotFound> {
//!         // In a real app it would be better to parse the query params with a crate like `url`
//!         let uri = &s.req_parts().uri;
//!         let uid = uri
//!             .query()
//!             .and_then(|s| s.split('&').find(|s| s.starts_with("id=")).map(|s| &s[3..]))
//!             .ok_or(UserIdNotFound)?;
//!         // Currently, it is not possible to have lifetime on the extracted data
//!         Ok(UserId(uid.to_string()))
//!     }
//! }
//!
//! fn handler(user_id: UserId) {
//!     println!("User id: {}", user_id.0);
//! }
//! let (svc, io) = SocketIo::new_svc();
//! io.ns("/", handler);
//! // Use the service with your favorite http server

mod data;
mod extensions;
mod socket;

#[cfg(feature = "state")]
#[cfg_attr(docsrs, doc(cfg(feature = "state")))]
mod state;

pub use data::*;
pub use extensions::*;
pub use socket::*;
#[cfg(feature = "state")]
#[cfg_attr(docsrs, doc(cfg(feature = "state")))]
pub use state::*;

/// Private API.
#[doc(hidden)]
macro_rules! __impl_deref {
    ($ident:ident) => {
        impl<T> std::ops::Deref for $ident<T> {
            type Target = T;

            #[inline]
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl<T> std::ops::DerefMut for $ident<T> {
            #[inline]
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }
    };

	($ident:ident<$($gen:ident),+>) => {
		impl<$($gen),+> std::ops::Deref for $ident<$($gen),+> {
			type Target = $($gen),+;

			#[inline]
			fn deref(&self) -> &Self::Target {
				&self.0
			}
		}

		impl<$($gen),+> std::ops::DerefMut for $ident<$($gen),+> {
			#[inline]
			fn deref_mut(&mut self) -> &mut Self::Target {
				&mut self.0
			}
		}
	};

	($ident:ident<$($gen:ident),+>: $ty:ty) => {
		impl<$($gen),+> std::ops::Deref for $ident<$($gen),+> {
			type Target = $ty;

			#[inline]
			fn deref(&self) -> &Self::Target {
				&self.0
			}
		}

		impl<$($gen),+> std::ops::DerefMut for $ident<$($gen),+> {
			#[inline]
			fn deref_mut(&mut self) -> &mut Self::Target {
				&mut self.0
			}
		}
	};

    ($ident:ident: $ty:ty) => {
        impl std::ops::Deref for $ident {
            type Target = $ty;

            #[inline]
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl std::ops::DerefMut for $ident {
            #[inline]
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }
    };
}
pub(crate) use __impl_deref;
