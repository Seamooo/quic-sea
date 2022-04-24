use quic_sea::QuicSocket;

// simple quic server bound to localhost:8080
fn main() {
    let socket = QuicSocket::bind("127.0.0.1:8000").unwrap();
    // match socket.log_packets() {
    //     Err(x) => println!("Error: {}", x),
    //     _ => {}
    // };
}
