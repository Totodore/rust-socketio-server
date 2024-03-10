use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use engineioxide::sid::Sid;
use socketioxide::{
    packet::{Packet, PacketData},
    PayloadValue, ProtocolVersion,
};
fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("Encode packet connect on /", |b| {
        let packet = Packet::connect(black_box("/"), black_box(Sid::ZERO), ProtocolVersion::V5);
        b.iter(|| {
            let _: String = packet.clone().try_into().unwrap();
        })
    });
    c.bench_function("Encode packet connect on /custom_nsp", |b| {
        let packet = Packet::connect(
            black_box("/custom_nsp"),
            black_box(Sid::ZERO),
            ProtocolVersion::V5,
        );
        b.iter(|| {
            let _: String = packet.clone().try_into().unwrap();
        })
    });

    const DATA: &str = r#"{"_placeholder":true,"num":0}"#;
    const BINARY: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    c.bench_function("Encode packet event on /", |b| {
        let data = PayloadValue::from_data(DATA).unwrap();
        let packet = Packet::event(black_box("/"), black_box("event"), black_box(data.clone()));
        b.iter(|| {
            let _: String = packet.clone().try_into().unwrap();
        })
    });

    c.bench_function("Encode packet event on /custom_nsp", |b| {
        let data = PayloadValue::from_data(DATA).unwrap();
        let packet = Packet::event(
            black_box("custom_nsp"),
            black_box("event"),
            black_box(data.clone()),
        );
        b.iter(|| {
            let _: String = packet.clone().try_into().unwrap();
        })
    });

    c.bench_function("Encode packet event with ack on /", |b| {
        let data = PayloadValue::from_data(DATA).unwrap();
        let packet = Packet::event(black_box("/"), black_box("event"), black_box(data.clone()));
        match packet.inner {
            PacketData::Event(_, _, mut ack) => ack.insert(black_box(0)),
            _ => panic!("Wrong packet type"),
        };
        b.iter(|| {
            let _: String = packet.clone().try_into().unwrap();
        })
    });

    c.bench_function("Encode packet event with ack on /custom_nsp", |b| {
        let data = PayloadValue::from_data(DATA).unwrap();
        let packet = Packet::event(
            black_box("/custom_nsp"),
            black_box("event"),
            black_box(data.clone()),
        );
        match packet.inner {
            PacketData::Event(_, _, mut ack) => ack.insert(black_box(0)),
            _ => panic!("Wrong packet type"),
        };
        b.iter(|| {
            let _: String = packet.clone().try_into().unwrap();
        })
    });

    c.bench_function("Encode packet ack on /", |b| {
        let data = PayloadValue::from_data(DATA).unwrap();
        let packet = Packet::ack(black_box("/"), black_box(data.clone()), black_box(0));
        b.iter(|| {
            let _: String = packet.clone().try_into().unwrap();
        })
    });

    c.bench_function("Encode packet ack on /custom_nsp", |b| {
        let data = PayloadValue::from_data(DATA).unwrap();
        let packet = Packet::ack(
            black_box("/custom_nsp"),
            black_box(data.clone()),
            black_box(0),
        );
        b.iter(|| {
            let _: String = packet.clone().try_into().unwrap();
        })
    });

    c.bench_function("Encode packet binary event (b64) on /", |b| {
        let data = PayloadValue::from_data(DATA).unwrap();
        let packet = Packet::bin_event_with_payloads(
            black_box("/"),
            black_box("event"),
            black_box(data.clone()),
            black_box(vec![Bytes::from_static(&BINARY)]),
        );
        b.iter(|| {
            let _: String = packet.clone().try_into().unwrap();
        })
    });

    c.bench_function("Encode packet binary event (b64) on /custom_nsp", |b| {
        let data = PayloadValue::from_data(DATA).unwrap();
        let packet = Packet::bin_event_with_payloads(
            black_box("/custom_nsp"),
            black_box("event"),
            black_box(data.clone()),
            black_box(vec![Bytes::from_static(&BINARY)]),
        );
        b.iter(|| {
            let _: String = packet.clone().try_into().unwrap();
        })
    });

    c.bench_function("Encode packet binary ack (b64) on /", |b| {
        let data = PayloadValue::from_data(DATA).unwrap();
        let packet = Packet::bin_ack_with_payloads(
            black_box("/"),
            black_box(data.clone()),
            black_box(0),
            black_box(vec![Bytes::from_static(&BINARY)]),
        );
        b.iter(|| {
            let _: String = packet.clone().try_into().unwrap();
        })
    });

    c.bench_function("Encode packet binary ack (b64) on /custom_nsp", |b| {
        let data = PayloadValue::from_data(DATA).unwrap();
        let packet = Packet::bin_ack_with_payloads(
            black_box("/custom_nsp"),
            black_box(data.clone()),
            black_box(0),
            black_box(vec![Bytes::from_static(&BINARY)]),
        );
        b.iter(|| {
            let _: String = packet.clone().try_into().unwrap();
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
