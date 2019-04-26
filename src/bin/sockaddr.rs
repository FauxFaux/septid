use std::env;
use std::net;
use std::net::ToSocketAddrs;
use std::str::FromStr;

fn main() {
    let mut args = env::args();
    args.next();
    let addr = args.next().expect("usage: addr");
    println!("{:?}", net::SocketAddr::from_str(&addr));
    println!("{:?}", addr.to_socket_addrs());
}
