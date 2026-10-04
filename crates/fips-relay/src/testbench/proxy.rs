//! Fixed test-mint upstream with bounded slots, buffers and inactivity.
use std::{io, net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Notify,
    task::{JoinHandle, JoinSet},
};

pub(crate) fn spawn(listener: TcpListener, backend: SocketAddr) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut jobs = JoinSet::new();
        loop {
            tokio::select! {
                connection = listener.accept(), if jobs.len() < 32 => {
                    let Ok((incoming, _)) = connection else { break; };
                    jobs.spawn(async move {
                        if let Ok(Ok(upstream)) = tokio::time::timeout(
                            Duration::from_secs(3), TcpStream::connect(backend),
                        ).await {
                            if let Err(error) = copy(incoming, upstream, Duration::from_secs(45)).await {
                                tracing::debug!(%error, "test mint proxy stream ended");
                            }
                        }
                    });
                }
                _ = jobs.join_next(), if !jobs.is_empty() => {}
            }
        }
    })
}

// A reused HTTP connection can carry many refund requests. Useful byte progress
// extends its idle deadline; a fixed lifetime would interrupt a later request.
async fn copy<A, B>(a: A, b: B, idle: Duration) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let activity = Notify::new();
    let (ar, aw) = tokio::io::split(a);
    let (br, bw) = tokio::io::split(b);
    let transfer = async {
        tokio::try_join!(direction(ar, bw, &activity), direction(br, aw, &activity))?;
        Ok(())
    };
    tokio::pin!(transfer);
    loop {
        tokio::select! {
            result = &mut transfer => return result,
            result = tokio::time::timeout(idle, activity.notified()) => {
                if result.is_err() {
                    return Err(io::ErrorKind::TimedOut.into());
                }
            }
        }
    }
}

async fn direction(
    mut input: impl AsyncRead + Unpin,
    mut output: impl AsyncWrite + Unpin,
    activity: &Notify,
) -> io::Result<()> {
    let mut buffer = [0; 8 * 1024];
    loop {
        let count = input.read(&mut buffer).await?;
        if count == 0 {
            return output.shutdown().await;
        }
        output.write_all(&buffer[..count]).await?;
        activity.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn half_closed_requests_keep_active_replies_and_idle_streams_expire() {
        let (mut client, incoming) = tokio::io::duplex(64);
        let (upstream, mut mint) = tokio::io::duplex(64);
        let task = tokio::spawn(copy(incoming, upstream, Duration::from_millis(250)));
        client.write_all(b"request").await.unwrap();
        client.shutdown().await.unwrap();
        let mut request = Vec::new();
        mint.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request");
        for _ in 0..6 {
            tokio::time::sleep(Duration::from_millis(75)).await;
            mint.write_all(b"x").await.unwrap();
            assert_eq!(client.read_u8().await.unwrap(), b'x');
        }
        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("an idle mint proxy must release its slot")
            .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }
}
