#[macro_use]
extern crate log;

use argh::FromArgs;
use bytes::BytesMut;
use futures::{future::Select, StreamExt};
use protosocks::{
    AuthReplyRepr, CmdRepr, Method::NoAuth, MethodPacket, MethodRepr, MethodsRepr, ProtocolDecoder,
    ProtocolEncoder, Rep::Success, RepPacket, RepRepr, Reply, Reply::Method, Request, SocksAddr,
};
use std::net::SocketAddr;
use tokio::{io, io::AsyncReadExt, io::AsyncWriteExt, io::ErrorKind, net::TcpStream};
use ustunet::{stream::TcpStream as u_TcpStream, TcpListener};

#[derive(FromArgs)]
/// Param
struct Param {
    #[argh(option, short = 'd', default = "String::from(\"172.20.96.1:10808\")")]
    /// dest socks5 server's ip and port
    socks5_addr: String,

    #[argh(option, short = 't', default = "String::from(\"tuna\")")]
    /// tun name
    tun: String,
}

#[tokio::main]
async fn main() {
    pretty_env_logger::init();
    let param: Param = argh::from_env();

    info!("dest socks5 address : {}", &param.socks5_addr);
    info!("tun name : {}", &param.tun);

    let socks5_addr: SocketAddr = param.socks5_addr.parse().expect("dest address parse fail");

    if socks5_addr.is_ipv6() {
        println!("Not support ivp6 yet");
        return;
    }

    let mut server = TcpListener::bind(param.tun).unwrap();
    while let Some(mut stream) = server.next().await {
        info!("accepted new tcp conn");
        tokio::spawn(async move {
            process(stream, &socks5_addr).await;
        });
    }
}

async fn process(mut stream: u_TcpStream, socks5_addr: &SocketAddr) {
    info!(
        "accepted new tcp stream from {:?} to {:?}",
        stream.peer_addr(),
        stream.local_addr()
    );

    // open a new socket to conn socks5 server
    if let Ok(socks5_stream) = get_socks5_stream(socks5_addr, stream.local_addr()).await {
        info!("conn to socks5 server({:?}) succeeded!", socks5_addr);

        tokio::spawn(async move {
            match copy_stream(stream, socks5_stream).await {
                Ok((s, r)) => info!("send: {} bytes , recv: {} bytes", s, r),
                Err(error) => error!("error while copying: {:?}", error),
            }
        });
    } else {
        // close this stream when cant connect socks5 server
        error!("can't connect socks5 server");
        stream.close().await;
    }
}

/// copy two tcp stream
/// send data : something -> client_reader -> socks5_reader -> your socks5 server
/// recv data : your socks5 server -> socks5_reader -> client_writer -> something
async fn copy_stream(
    client_stream: u_TcpStream,
    socks5_stream: TcpStream,
) -> io::Result<(u64, u64)> {
    let (mut socks5_reader, mut socks5_writer) = socks5_stream.into_split();
    let (mut client_reader, mut client_writer) = client_stream.split();

    let send = tokio::spawn(async move {
        let s = tokio::io::copy(&mut client_reader, &mut socks5_writer).await;
        s
    });
    let recv = tokio::spawn(async move {
        let r = tokio::io::copy(&mut socks5_reader, &mut client_writer).await;
        r
    });

    let (s, r) = tokio::join!(send, recv);

    Ok((s??, r??))
}

/// connect to socks5 server(NO AUTH) STEP BY STEP
async fn get_socks5_stream(
    socks5_addr: &SocketAddr,
    dest_addr: SocketAddr,
) -> io::Result<TcpStream> {
    let mut socks5_stream = TcpStream::connect(socks5_addr).await?;
    socks5_stream.set_nodelay(true);

    // 0. create a write buff
    let mut write_buf = BytesMut::with_capacity(256);

    // 1.1 create socks5 init packet and encode it into buff
    let req_init = protosocks::MethodsRepr::new(vec![NoAuth]);
    MethodsRepr::encode(&req_init, &mut write_buf);

    // 1.2 send to init packet socks5 server and get resp
    socks5_stream.write_all_buf(&mut write_buf).await?;
    write_buf.clear();

    // 1.3 recv data from sock5 server , but we dont care about this ~
    let mut resp_buf = [0u8; 2];
    socks5_stream.read_exact(&mut resp_buf).await?;
    let resp = MethodRepr::parse(&MethodPacket::new_checked(&resp_buf).unwrap())
        .expect("fail to parse init resp packet in socks5");
    if resp.method != NoAuth {
        // this should never happen
        error!("resp.method != NoAuth");
        return Err(io::Error::new(
            ErrorKind::ConnectionRefused,
            "resp.method != NoAuth",
        ));
    }

    // 2.1 create a cmd packet
    let req_conn = protosocks::CmdRepr::new_connect_std(dest_addr);
    CmdRepr::encode(&req_conn, &mut write_buf);

    // 2.2 send cmd packet to socks5 server
    socks5_stream.write_all_buf(&mut write_buf).await?;
    write_buf.clear();

    // 2.3 recv cmd resp data (not support ipv6)
    // if dest.addr is ipv4 addr , that resp packet length is 10 bytes
    let mut resp_buf = vec![0u8; 10];
    socks5_stream.read_exact(&mut resp_buf).await?;
    let resp = RepRepr::parse(&RepPacket::new_checked(&resp_buf).unwrap())
        .expect("fail to parse cmd resp packet in sock5");
    if resp.rep != Success {
        // this should never happen
        error!("resp.rep != Success , current rep {:?}", resp.rep);
        return Err(io::Error::new(
            ErrorKind::NotConnected,
            format!("resp.rep != Success , current rep {:?}", resp.rep),
        ));
    }

    info!("{:?}", &resp.rep);

    //conn succeeded!
    Ok(socks5_stream)
}
