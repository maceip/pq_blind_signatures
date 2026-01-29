use blind_signatures_conservative_deg16::{
    blind_sig_conservative_deg16::BlindSignatureConservativeDeg16, zk::ZKType,
};
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};

pub const VARIANTS: [ZKType; 1] = [
    ZKType::FV1_128,
    // ZKType::FV1_192,
    // ZKType::FV1_256,
    // ZKType::FV2_128,
    // ZKType::FV2_192,
    // ZKType::FV2_256,
    // ZKType::SV1_128,
    // ZKType::SV1_192,
    // ZKType::SV1_256,
    // ZKType::SV2_128,
    // ZKType::SV2_192,
    // ZKType::SV2_256,
];

fn bench_sign1(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_sign1_conservative_deg16");

    let m = b"Hello World!".to_vec();

    for zktype in VARIANTS {
        let id = BenchmarkId::from_parameter(format!(
            "Bench conservative deg 16 sign1 with parameters: {zktype:?}"
        ));

        group.bench_with_input(id, &zktype, |b, _| {
            b.iter_batched_ref(
                || BlindSignatureConservativeDeg16::setup(zktype), // setup runs once per iteration
                |state| state.sign_1(&m),                          // only this is timed
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_sign2(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_sign2_conservative_deg16");

    let m = b"Hello World!".to_vec();

    for zktype in VARIANTS {
        let id = BenchmarkId::from_parameter(format!(
            "Bench conservative deg 16 sign2 with parameters: {zktype:?}"
        ));

        group.bench_with_input(id, &zktype, |b, _| {
            b.iter_batched_ref(
                || {
                    let bs = BlindSignatureConservativeDeg16::setup(zktype);
                    let (_, sk) = bs.keygen();
                    let (s1, _) = bs.sign_1(&m);
                    (bs, sk, s1)
                }, // setup runs once per iteration
                |(bs, sk, s1)| bs.sign_2(sk, s1), // only this is timed
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_sign3(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_sign3_conservative_deg16");

    let m = b"Hello World!".to_vec();
    let mut additional_r: [u8; 32] = [0xff; 32];

    for zktype in VARIANTS {
        let id = BenchmarkId::from_parameter(format!(
            "Bench conservative deg 16 sign3 with parameters: {zktype:?}"
        ));

        group.sample_size(10);

        group.bench_with_input(id, &zktype, |b, _| {
            b.iter_batched_ref(
                || {
                    let bs = BlindSignatureConservativeDeg16::setup(zktype);
                    let (pk, sk) = bs.keygen();
                    let epk = bs.mayo.expand_pk(&pk);
                    let (s1, state) = bs.sign_1(&m);
                    let bsig = bs.sign_2(&sk, &s1);
                    (bs, pk, epk, bsig, state)
                }, // setup runs once per iteration
                |(bs, pk, epk, bsig, state)| {
                    bs.sign_3(pk, epk, bsig, &mut state.clone(), &mut additional_r)
                }, // only this is timed
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_verify_conservative_deg16");

    let m = b"Hello World!".to_vec();
    let additional_r: [u8; 32] = [0xff; 32];

    for zktype in VARIANTS {
        let id = BenchmarkId::from_parameter(format!(
            "Bench conservative deg 16 verify with parameters: {zktype:?}"
        ));

        group.sample_size(10);

        group.bench_with_input(id, &zktype, |b, _| {
            b.iter_batched_ref(
                || {
                    let bs = BlindSignatureConservativeDeg16::setup(zktype);
                    let (pk, sk) = bs.keygen();
                    let mut epk = bs.mayo.expand_pk(&pk);
                    let (s1, state) = bs.sign_1(&m);
                    let bsig = bs.sign_2(&sk, &s1);
                    let sig = bs.sign_3(
                        &pk,
                        &mut epk,
                        &bsig,
                        &mut state.clone(),
                        &mut additional_r.clone(),
                    );
                    (bs, epk, sig)
                }, // setup runs once per iteration
                |(bs, epk, sig)| bs.verify(epk, &m, sig, &mut additional_r.clone()), // only this is timed
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(
    bench_conservative_deg16,
    bench_sign1,
    bench_sign2,
    bench_sign3,
    bench_verify
);
criterion_main!(bench_conservative_deg16);
