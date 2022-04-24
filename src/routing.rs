use crate::connection::Connection;
use crate::error::{self, Error};
use crate::packet::{decode_packets, next_header_from_stream, Packet, PacketHeader, PacketType};
use crate::tls;
use crate::utils::{self, U160};
use rustls::quic as quicls;
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Mutex, RwLock};

#[derive(Debug)]
pub(crate) struct InternalDatagram {
    pub data: Vec<u8>,
    pub addr: SocketAddr,
}

#[derive(Debug)]
pub(crate) struct InternalQuicStream {
    receiver: Receiver<InternalDatagram>,
    sender: Sender<InternalDatagram>,
    // connection behind a lock although teeeeeechnically not needed
    // as the implementation should only ever let a single thread access
    // connection
    connection: RwLock<Connection>,
}

#[derive(Debug)]
pub(crate) struct InternalQuicSocket {
    socket: Mutex<UdpSocket>,
    streams: RwLock<HashMap<U160, InternalQuicStream>>,
    log_traffic: RwLock<bool>,
}

impl InternalQuicStream {
    pub fn from_connection(connection: Connection) -> Self {
        let (sender, receiver) = channel::<InternalDatagram>();
        Self {
            receiver,
            sender,
            connection: RwLock::new(connection),
        }
    }
}

impl InternalQuicSocket {
    pub fn bind<A>(addresses: A) -> std::io::Result<Self>
    where
        A: ToSocketAddrs,
    {
        let socket = Mutex::new(UdpSocket::bind(addresses)?);
        let init_map = HashMap::<U160, InternalQuicStream>::new();
        let streams = RwLock::new(init_map);
        Ok(Self {
            socket,
            streams,
            log_traffic: RwLock::new(false),
        })
    }
    fn recv_datagram(&self) -> std::io::Result<InternalDatagram> {
        let socket = self.socket.lock().unwrap();
        // TODO investigate proper buffer size
        let mut buff = [0u8; 4096];
        let (amt, addr) = socket.recv_from(&mut buff)?;
        // to_vec used for length safety for allocated obj
        let data = buff[..amt].to_vec();
        if *self.log_traffic.read().unwrap() {
            let mut stream = utils::make_result_stream(&data);
            let header = next_header_from_stream(&mut stream);
            println!("{:?}", header);
        }
        Ok(InternalDatagram { data, addr })
    }
    fn recv_new_initial_datagram(&self) -> std::io::Result<InternalDatagram> {
        loop {
            let datagram = self.recv_datagram()?;
            let ret_datagram = {
                let mut stream = utils::make_result_stream(&datagram.data);
                match next_header_from_stream(&mut stream) {
                    Ok(x) => {
                        let packet_type = match x {
                            PacketHeader::Long(ref x) => x.packet_type(),
                            PacketHeader::Short(ref x) => x.packet_type(),
                        };
                        let dcid = match x {
                            PacketHeader::Long(ref x) => x.destination_connection_id,
                            PacketHeader::Short(ref x) => x.destination_connection_id,
                        };
                        match packet_type {
                            PacketType::Initial => {
                                !self.streams.read().unwrap().contains_key(&dcid)
                            }
                            // TODO ZeroRtt packets should be buffered from here
                            _ => false,
                        }
                    }
                    Err(x) => {
                        // TODO implement proper error handling
                        eprintln!("{:?}", x);
                        false
                    }
                }
            };
            if ret_datagram {
                return Ok(datagram);
            } else {
                self.route_datagram(datagram);
            }
        }
    }
    fn route_datagram(&self, datagram: InternalDatagram) -> error::Result<()> {
        let mut stream = datagram
            .data
            .iter()
            .map(|x| -> error::Result<u8> { Ok(x.clone()) });
        let route_header = next_header_from_stream(&mut stream)?;
        let connection_id = match route_header {
            PacketHeader::Short(ref x) => x.destination_connection_id,
            PacketHeader::Long(ref x) => x.destination_connection_id,
        };
        match self.streams.read().unwrap().get(&connection_id) {
            Some(x) => x
                .sender
                .send(datagram)
                .map_err(|_| Error::InternalError("error sending data to channel")),
            None => Err(Error::InternalError("missing connection")),
        }
    }

    fn packets_from_datagram(&self, datagram: &InternalDatagram) -> error::Result<Vec<Packet>> {
        // datagrams that get to this point are assumed to be for an existing connection
        let mut stream = utils::make_result_stream(&datagram.data);
        // get connection first
        let mut header_stream = stream.clone();
        let header = next_header_from_stream(&mut header_stream)?;
        let rv = {
            let streams_map = self.streams.read().unwrap();
            let route_stream = streams_map
                .get(&header.get_destination_id())
                .ok_or(Error::InternalError("connection not found"))?;
            let connection = route_stream.connection.read().unwrap();
            decode_packets(&mut stream, &connection)
        }?;
        if *self.log_traffic.read().unwrap() {
            println!("{:?}", rv);
        }
        Ok(rv)
    }

    pub fn connect<A>(&self, addresses: A) -> std::io::Result<U160>
    where
        A: ToSocketAddrs,
    {
        unimplemented!();
    }

    pub fn accept(&self) -> std::io::Result<U160> {
        let initial_datagram = self.recv_new_initial_datagram()?;
        let mut stream = utils::make_result_stream(&initial_datagram.data);
        // TODO handle errors below properly
        let header = next_header_from_stream(&mut stream).unwrap();
        let connection = Connection::new(
            true,
            tls::Version::V1,
            header.get_destination_id(),
            header.get_destination_id_length() as usize,
        )
        .unwrap();
        let stream = InternalQuicStream::from_connection(connection);
        let rv = || -> U160 {
            loop {
                let src_id = tls::get_connection_id();
                {
                    let mut streams = self.streams.write().unwrap();
                    if !streams.contains_key(&src_id) {
                        stream.connection.write().unwrap().set_scid(src_id);
                        streams.insert(src_id.clone(), stream);
                        return src_id;
                    }
                }
            }
        }();
        let connection_ref = self.streams.read().unwrap().get(&rv).unwrap();
        unimplemented!();
        Ok(rv)
    }

    pub fn set_log_traffic(&mut self, log_traffic_flag: bool) {
        let mut flag = self.log_traffic.write().unwrap();
        *flag = log_traffic_flag;
    }

    pub fn drop_connection(&self, cid: U160) {
        // TODO there should likely be some network interaction also here
        self.streams.write().unwrap().remove(&cid);
    }
}
