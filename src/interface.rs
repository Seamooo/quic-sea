use crate::routing::InternalQuicSocket;
use crate::utils::U160;
use std::net::ToSocketAddrs;
use std::sync::Arc;

#[derive(Debug)]
pub struct QuicSocket {
    socket: Arc<InternalQuicSocket>,
}

#[derive(Debug)]
pub struct QuicStream {
    socket: Arc<InternalQuicSocket>,
    connection_id: U160,
}

impl Drop for QuicStream {
    fn drop(&mut self) {
        // drop corresponding connection on drop
        self.socket.drop_connection(self.connection_id);
    }
}

impl QuicSocket {
    pub fn bind<A>(addresses: A) -> std::io::Result<Self>
    where
        A: ToSocketAddrs,
    {
        let socket = Arc::new(InternalQuicSocket::bind(addresses)?);
        Ok(Self { socket })
    }
    pub fn connect<A>(&self, addresses: A) -> std::io::Result<QuicStream>
    where
        A: ToSocketAddrs,
    {
        let connection_id = self.socket.connect(addresses)?;
        Ok(QuicStream {
            connection_id,
            socket: self.socket.clone(),
        })
    }
    pub fn accept<A>(&self) -> std::io::Result<QuicStream> {
        let connection_id = self.socket.accept()?;
        Ok(QuicStream {
            connection_id,
            socket: self.socket.clone(),
        })
    }
    pub fn set_log_traffic(&self, log_traffic_flag: bool) {}
}
