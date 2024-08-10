use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use engineioxide::sid::Sid;
use serde_json::to_value;
use socketioxide::{
    packet::{Packet, PacketData},
    parser::{CommonParser, Parse, TransportPayload},
    ProtocolVersion,
};

fn encode(packet: Packet<'_>) -> String {
    match CommonParser::default().encode(black_box(packet)).0 {
        TransportPayload::Str(d) => d.into(),
        TransportPayload::Bytes(_) => panic!("testing only returns str"),
    }
}
fn decode(value: String) -> Option<Packet<'static>> {
    CommonParser::default()
        .decode_str(black_box(value.into()))
        .ok()
}
fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("socketio_packet/decode");
    group.bench_function("Decode packet connect on /", |b| {
        b.iter_batched(
            || encode(Packet::connect("/", Sid::ZERO, ProtocolVersion::V5)),
            decode,
            BatchSize::SmallInput,
        )
    });
    group.bench_function("Decode packet connect on /custom_nsp", |b| {
        b.iter_batched(
            || {
                encode(Packet::connect(
                    "/custom_nsp",
                    Sid::ZERO,
                    ProtocolVersion::V5,
                ))
            },
            decode,
            BatchSize::SmallInput,
        )
    });

    const DATA: &str = r#"{"_placeholder":true,"num":0}"#;
    const BINARY: Bytes = Bytes::from_static(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    group.bench_function("Decode packet event on /", |b| {
        b.iter_batched(
            || encode(Packet::event("/", "event", to_value(DATA).unwrap())),
            decode,
            BatchSize::SmallInput,
        )
    });

    group.bench_function("Decode packet event on /custom_nsp", |b| {
        b.iter_batched(
            || {
                encode(Packet::event(
                    "custom_nsp",
                    "event",
                    to_value(DATA).unwrap(),
                ))
            },
            decode,
            BatchSize::SmallInput,
        )
    });

    group.bench_function("Decode packet event with ack on /", |b| {
        b.iter_batched(
            || {
                let packet = Packet::event("/", "event", to_value(DATA).unwrap());
                match packet.inner {
                    PacketData::Event(_, _, mut ack) => ack.insert(black_box(0)),
                    _ => panic!("Wrong packet type"),
                };
                encode(packet)
            },
            decode,
            BatchSize::SmallInput,
        )
    });

    group.bench_function("Decode packet event with ack on /custom_nsp", |b| {
        b.iter_batched(
            || {
                let packet = Packet::event("/custom_nsp", "event", to_value(DATA).unwrap());
                match packet.inner {
                    PacketData::Event(_, _, mut ack) => ack.insert(black_box(0)),
                    _ => panic!("Wrong packet type"),
                };
                encode(packet)
            },
            decode,
            BatchSize::SmallInput,
        )
    });

    group.bench_function("Decode packet ack on /", |b| {
        b.iter_batched(
            || encode(Packet::ack("/", to_value(DATA).unwrap(), black_box(0))),
            decode,
            BatchSize::SmallInput,
        )
    });

    group.bench_function("Decode packet ack on /custom_nsp", |b| {
        b.iter_batched(
            || encode(Packet::ack("/custom_nsp", to_value(DATA).unwrap(), 0)),
            decode,
            BatchSize::SmallInput,
        )
    });

    group.bench_function("Decode packet binary event (b64) on /", |b| {
        b.iter_batched(
            || {
                encode(Packet::bin_event(
                    "/",
                    "event",
                    to_value(DATA).unwrap(),
                    vec![BINARY.clone()],
                ))
            },
            decode,
            BatchSize::SmallInput,
        )
    });

    group.bench_function("Decode packet binary event (b64) on /custom_nsp", |b| {
        b.iter_batched(
            || {
                encode(Packet::bin_event(
                    "/custom_nsp",
                    "event",
                    to_value(DATA).unwrap(),
                    vec![BINARY],
                ))
            },
            decode,
            BatchSize::SmallInput,
        )
    });

    group.bench_function("Decode packet binary ack (b64) on /", |b| {
        b.iter_batched(
            || {
                encode(Packet::bin_ack(
                    "/",
                    to_value(DATA).unwrap(),
                    vec![BINARY.clone()],
                    0,
                ))
            },
            decode,
            BatchSize::SmallInput,
        )
    });

    group.bench_function("Decode packet binary ack (b64) on /custom_nsp", |b| {
        b.iter_batched(
            || {
                encode(Packet::bin_ack(
                    "/custom_nsp",
                    to_value(DATA).unwrap(),
                    vec![BINARY.clone()],
                    0,
                ))
            },
            decode,
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
