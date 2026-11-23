// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Socket-level HTTP capacity and stalled-write cleanup.

use std::future::Future;
use std::io::{self, IoSlice};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::serve::Listener;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, Sleep};

pub(super) struct HttpListener {
    listener: TcpListener,
    capacity: Arc<Semaphore>,
    write_timeout: Duration,
}

impl HttpListener {
    pub(super) fn new(listener: TcpListener, capacity: usize, write_timeout: Duration) -> Self {
        Self {
            listener,
            capacity: Arc::new(Semaphore::new(capacity)),
            write_timeout,
        }
    }
}

impl Listener for HttpListener {
    type Io = HttpConnection<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let permit = self
            .capacity
            .clone()
            .acquire_owned()
            .await
            .expect("HTTP listener capacity is never closed");
        let (stream, address) = Listener::accept(&mut self.listener).await;
        (
            HttpConnection::new(stream, permit, self.write_timeout),
            address,
        )
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}

pub(super) struct HttpConnection<T> {
    inner: T,
    _permit: OwnedSemaphorePermit,
    timeout: Duration,
    deadline: Pin<Box<Sleep>>,
    stalled: bool,
}

impl<T> HttpConnection<T> {
    fn new(inner: T, permit: OwnedSemaphorePermit, timeout: Duration) -> Self {
        Self {
            inner,
            _permit: permit,
            timeout,
            deadline: Box::pin(tokio::time::sleep(timeout)),
            stalled: false,
        }
    }

    fn check_write(
        &mut self,
        result: Poll<io::Result<usize>>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<usize>> {
        if result.is_ready() || self.timeout.is_zero() {
            self.stalled = false;
            return result;
        }
        // Arm only when the socket cannot accept bytes. Waiting for application
        // data, hashing, or governor permits is deliberately outside this timer.
        if !self.stalled {
            self.deadline.as_mut().reset(Instant::now() + self.timeout);
            self.stalled = true;
        }
        if self.deadline.as_mut().poll(cx).is_ready() {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP peer stopped accepting bytes",
            )))
        } else {
            Poll::Pending
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for HttpConnection<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for HttpConnection<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        self.check_write(result, cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        self.check_write(result, cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // TCP flush is a no-op and must not reset a stalled write's deadline.
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn listener_preserves_peer_identity_and_waits_for_connection_capacity() {
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let mut listener = HttpListener::new(socket, 1, Duration::from_secs(1));
        let first = TcpStream::connect(address).await.unwrap();
        let (connection, peer) = listener.accept().await;
        assert_eq!(peer, first.local_addr().unwrap());
        let second = TcpStream::connect(address).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), listener.accept())
                .await
                .is_err()
        );
        drop(connection);
        let (connection, peer) = tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .unwrap();
        assert_eq!(peer, second.local_addr().unwrap());
        drop(connection);
        assert_eq!(listener.capacity.available_permits(), 1);
    }

    #[tokio::test]
    async fn stalled_write_times_out_and_drop_releases_connection_capacity() {
        let capacity = Arc::new(Semaphore::new(1));
        let (stream, _peer) = tokio::io::duplex(1);
        let permit = capacity.clone().acquire_owned().await.unwrap();
        let mut connection = HttpConnection::new(stream, permit, Duration::from_millis(10));
        let error = connection.write_all(b"two").await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(capacity.available_permits(), 0);
        drop(connection);
        assert_eq!(capacity.available_permits(), 1);
    }

    #[tokio::test]
    async fn successful_flush_does_not_extend_a_stalled_write_deadline() {
        let (stream, _peer) = tokio::io::duplex(1);
        let permit = Arc::new(Semaphore::new(1)).acquire_owned().await.unwrap();
        let mut connection = HttpConnection::new(stream, permit, Duration::from_millis(10));
        connection.write_all(b"a").await.unwrap();
        let write = std::future::poll_fn(|cx| {
            let result = Pin::new(&mut connection).poll_write(cx, b"b");
            if result.is_pending() {
                assert!(matches!(
                    Pin::new(&mut connection).poll_flush(cx),
                    Poll::Ready(Ok(()))
                ));
            }
            result
        });
        let error = tokio::time::timeout(Duration::from_secs(1), write)
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn server_waits_do_not_consume_the_write_progress_deadline() {
        let (stream, mut peer) = tokio::io::duplex(1);
        let permit = Arc::new(Semaphore::new(1)).acquire_owned().await.unwrap();
        let mut connection = HttpConnection::new(stream, permit, Duration::from_millis(5));
        tokio::time::sleep(Duration::from_millis(15)).await;
        connection.write_all(b"a").await.unwrap();
        assert_eq!(peer.read_u8().await.unwrap(), b'a');
        tokio::time::sleep(Duration::from_millis(15)).await;
        connection.write_all(b"b").await.unwrap();
        assert_eq!(peer.read_u8().await.unwrap(), b'b');
    }
}
