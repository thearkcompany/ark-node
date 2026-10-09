use std::sync::Arc;
use tokio::time::Duration;
use ark_vpn::engine::{OutboundPacket, RouteMode};
use ark_vpn::transport::{ChannelTransportSink, VpnTransportSink};
use ark_vpn::error::VpnError;

#[tokio::test]
async fn test_channel_transport_sink_send_and_receive() {
    let sink = ChannelTransportSink::new(10);
    let mut rx = sink.take_receiver().expect("take_receiver should return Some on first call");

    let packet = OutboundPacket {
        recipient_id: [1u8; 32],
        target_endpoint: "127.0.0.1:8000".parse().unwrap(),
        route_mode: RouteMode::DirectP2p,
        payload: vec![1, 2, 3, 4],
    };

    sink.send_packet(packet.clone()).await.expect("send should succeed");

    let received = tokio::time::timeout(Duration::from_millis(100), rx.recv())
        .await
        .expect("did not timeout")
        .expect("received packet");

    assert_eq!(received, packet);
}

#[tokio::test]
async fn test_channel_transport_sink_take_receiver_once() {
    let sink = ChannelTransportSink::new(10);
    assert!(sink.take_receiver().is_some());
    assert!(sink.take_receiver().is_none());
}

#[tokio::test]
async fn test_channel_transport_sink_closed_channel_returns_error() {
    let sink = ChannelTransportSink::new(1);
    let rx = sink.take_receiver().unwrap();
    drop(rx); // Drop receiver so channel is closed

    let packet = OutboundPacket {
        recipient_id: [2u8; 32],
        target_endpoint: "127.0.0.1:8001".parse().unwrap(),
        route_mode: RouteMode::Relayed,
        payload: vec![5, 6, 7],
    };

    let result = sink.send_packet(packet).await;
    assert!(matches!(result, Err(VpnError::InterfaceClosed)));
}

#[tokio::test]
async fn test_channel_transport_sink_trait_object() {
    let sink: Arc<dyn VpnTransportSink> = Arc::new(ChannelTransportSink::default());
    let packet = OutboundPacket {
        recipient_id: [3u8; 32],
        target_endpoint: "127.0.0.1:8002".parse().unwrap(),
        route_mode: RouteMode::DirectP2p,
        payload: vec![9, 9, 9],
    };

    sink.send_packet(packet).await.expect("send via trait object");
}
