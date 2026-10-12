use super::{HostNetwork, connect_tcp, connect_websocket};
use async_wsocket::message::CloseFrame;
use async_wsocket::{ConnectionMode, Message};
use futures::{Sink, StreamExt, TryStreamExt, stream::SplitSink};
use nostr_sdk::pool::transport::error::TransportError;
use nostr_sdk::pool::transport::websocket::{WebSocketSink, WebSocketStream, WebSocketTransport};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message as WireMessage;

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Nostr carrier connections using the same host protection as FIPS transports.
#[derive(Debug, Clone)]
pub struct NostrHostTransport(pub Arc<dyn HostNetwork>);

impl WebSocketTransport for NostrHostTransport {
    fn support_ping(&self) -> bool {
        true
    }

    fn connect<'a>(
        &'a self,
        url: &'a nostr::Url,
        mode: &'a ConnectionMode,
        timeout: Duration,
    ) -> nostr::util::BoxedFuture<'a, Result<(WebSocketSink, WebSocketStream), TransportError>>
    {
        Box::pin(async move {
            let connect = async {
                match mode {
                    ConnectionMode::Direct => {
                        connect_websocket(Some(&*self.0), url.as_str(), None, None).await
                    }
                    ConnectionMode::Proxy(proxy) => {
                        let stream = connect_tcp(Some(&*self.0), *proxy).await?;
                        let host = url
                            .host_str()
                            .ok_or_else(|| std::io::Error::other("relay URL has no host"))?;
                        let port = url
                            .port_or_known_default()
                            .ok_or_else(|| std::io::Error::other("relay URL has no port"))?;
                        let stream = tokio_socks::tcp::Socks5Stream::connect_with_socket(
                            stream,
                            (host, port),
                        )
                        .await
                        .map_err(|error| std::io::Error::other(error.to_string()))?;
                        tokio_tungstenite::client_async_tls_with_config(
                            url.as_str(),
                            stream.into_inner(),
                            None,
                            None,
                        )
                        .await
                    }
                    #[allow(unreachable_patterns)]
                    _ => Err(
                        std::io::Error::other("host-protected embedded Tor is not supported")
                            .into(),
                    ),
                }
            };
            let (socket, _) = tokio::time::timeout(timeout, connect)
                .await
                .map_err(TransportError::backend)?
                .map_err(TransportError::backend)?;
            let (sink, stream) = socket.split();
            Ok((
                Box::new(HostSink(sink)) as WebSocketSink,
                Box::pin(
                    stream
                        .map_err(TransportError::backend)
                        .and_then(|message| async move {
                            match message {
                                WireMessage::Text(text) => Ok(Message::Text(text.to_string())),
                                WireMessage::Binary(data) => Ok(Message::Binary(data.to_vec())),
                                WireMessage::Ping(data) => Ok(Message::Ping(data.to_vec())),
                                WireMessage::Pong(data) => Ok(Message::Pong(data.to_vec())),
                                WireMessage::Close(frame) => {
                                    Ok(Message::Close(frame.map(|frame| CloseFrame {
                                        code: frame.code.into(),
                                        reason: frame.reason.to_string(),
                                    })))
                                }
                                WireMessage::Frame(_) => Err(TransportError::backend(
                                    std::io::Error::other("unexpected raw WebSocket frame"),
                                )),
                            }
                        }),
                ) as WebSocketStream,
            ))
        })
    }
}

// Keep the upstream transport's explicit sink forwarding: its error adapter
// intentionally avoids SinkExt::sink_map_err after an error/close transition.
struct HostSink(SplitSink<Socket, WireMessage>);

impl Sink<Message> for HostSink {
    type Error = TransportError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0)
            .poll_ready(cx)
            .map_err(TransportError::backend)
    }

    fn start_send(mut self: Pin<&mut Self>, message: Message) -> Result<(), Self::Error> {
        let message = match message {
            Message::Text(text) => WireMessage::Text(text.into()),
            Message::Binary(data) => WireMessage::Binary(data.into()),
            Message::Ping(data) => WireMessage::Ping(data.into()),
            Message::Pong(data) => WireMessage::Pong(data.into()),
            Message::Close(frame) => WireMessage::Close(frame.map(|frame| {
                tokio_tungstenite::tungstenite::protocol::CloseFrame {
                    code: frame.code.into(),
                    reason: frame.reason.into(),
                }
            })),
        };
        Pin::new(&mut self.0)
            .start_send(message)
            .map_err(TransportError::backend)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0)
            .poll_flush(cx)
            .map_err(TransportError::backend)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0)
            .poll_close(cx)
            .map_err(TransportError::backend)
    }
}
