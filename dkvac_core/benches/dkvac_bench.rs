use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use dkvac_core::instantiation1;
use dkvac_core::instantiation2;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::collections::BTreeSet;
use std::time::Duration;

const ATTR_COUNTS: &[usize] = &[4, 8, 32, 64];
const DELEGATION_LEVELS: &[usize] = &[0, 3, 6];

fn scalar_sequence_1(n: usize) -> Vec<dkvac_core::Scalar> {
    (1..=n).map(|i| dkvac_core::Scalar::from(i as u64)).collect()
}

fn inst2_message(n: usize) -> instantiation2::Message {
    instantiation2::Message {
        attributes: scalar_sequence_1(n),
        malleable_indices: (0..n).collect::<BTreeSet<_>>(),
    }
}

fn bench_inst1(c: &mut Criterion) {
    let mut group = c.benchmark_group("inst1");

    for &n in ATTR_COUNTS {
        let mut rng = ChaCha20Rng::from_seed([n as u8; 32]);
        let pp = instantiation1::setup(&mut rng);
        let (isk, ipar) = instantiation1::keygen(&mut rng, &pp).expect("keygen");
        let attrs = scalar_sequence_1(n);
        let disclosed = attrs.clone();
        let (cred, proof) =
            instantiation1::issue_cred(&mut rng, &pp, &isk, &ipar, &attrs).expect("issue");
        let obtained_cred =
            instantiation1::obtain_cred(&ipar, &attrs, cred.clone(), &proof).expect("obtain");
        let show =
            instantiation1::show_cred(&mut rng, &obtained_cred, &disclosed).expect("show");
        let (encdel, dk) =
            instantiation1::issue_del(&mut rng, &pp, &isk, &ipar, &attrs).expect("issue del");

        group.bench_with_input(BenchmarkId::new("issue_cred", n), &n, |b, _| {
            b.iter(|| {
                let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
                instantiation1::issue_cred(&mut rng, &pp, &isk, &ipar, &attrs).expect("issue")
            });
        });

        group.bench_with_input(BenchmarkId::new("obtain_cred", n), &n, |b, _| {
            b.iter(|| {
                instantiation1::obtain_cred(&ipar, &attrs, cred.clone(), &proof).expect("obtain")
            });
        });

        group.bench_with_input(BenchmarkId::new("show_cred", n), &n, |b, _| {
            b.iter(|| {
                let mut rng = ChaCha20Rng::from_seed([12u8; 32]);
                instantiation1::show_cred(&mut rng, &obtained_cred, &disclosed).expect("show")
            });
        });

        group.bench_with_input(BenchmarkId::new("verify_show", n), &n, |b, _| {
            b.iter(|| instantiation1::verify_show(&isk, &show).expect("verify"));
        });

        group.bench_with_input(BenchmarkId::new("issue_del", n), &n, |b, _| {
            b.iter(|| {
                let mut rng = ChaCha20Rng::from_seed([13u8; 32]);
                instantiation1::issue_del(&mut rng, &pp, &isk, &ipar, &attrs).expect("issue del")
            });
        });

        for &d in DELEGATION_LEVELS {
            let mut chain = encdel.clone();
            let mut chain_dk = dk;
            for _ in 0..d {
                let (next_chain, next_dk) =
                    instantiation1::delegate(&mut rng, &chain, &chain_dk, &attrs).expect("delegate");
                chain = next_chain;
                chain_dk = next_dk;
            }

            group.bench_with_input(
                BenchmarkId::new(format!("delegate_d{d}"), n),
                &n,
                |b, _| {
                    b.iter(|| {
                        let mut rng = ChaCha20Rng::from_seed([14u8; 32]);
                        instantiation1::delegate(&mut rng, &chain, &chain_dk, &attrs)
                            .expect("delegate")
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new(format!("obtain_del_d{d}"), n),
                &n,
                |b, _| {
                    b.iter(|| {
                        instantiation1::obtain_del(&pp, &ipar, &chain, &chain_dk)
                            .expect("obtain del")
                    });
                },
            );
        }
    }

    group.finish();
}

fn bench_inst2(c: &mut Criterion) {
    let mut group = c.benchmark_group("inst2");

    for &n in ATTR_COUNTS {
        let mut rng = ChaCha20Rng::from_seed([100u8.wrapping_add(n as u8); 32]);
        let pp = instantiation2::setup(&mut rng, n);
        let (isk, ipar) = instantiation2::keygen(&mut rng, &pp).expect("keygen");
        let message = inst2_message(n);
        let policy = instantiation2::DisclosurePolicy {
            disclosed_indices: (0..n).collect::<BTreeSet<_>>(),
        };
        let (cred, proof) =
            instantiation2::issue_cred(&mut rng, &pp, &isk, &ipar, &message).expect("issue");
        let obtained_cred =
            instantiation2::obtain_cred(&pp, &ipar, &message, cred.clone(), &proof).expect("obtain");
        let show =
            instantiation2::show_cred(&mut rng, &pp, &ipar, &message, &policy, &obtained_cred)
                .expect("show");
        let (encdel, dk) =
            instantiation2::issue_del(&mut rng, &pp, &isk, &ipar, &message).expect("issue del");

        group.bench_with_input(BenchmarkId::new("issue_cred", n), &n, |b, _| {
            b.iter(|| {
                let mut rng = ChaCha20Rng::from_seed([21u8; 32]);
                instantiation2::issue_cred(&mut rng, &pp, &isk, &ipar, &message).expect("issue")
            });
        });

        group.bench_with_input(BenchmarkId::new("obtain_cred", n), &n, |b, _| {
            b.iter(|| {
                instantiation2::obtain_cred(&pp, &ipar, &message, cred.clone(), &proof)
                    .expect("obtain")
            });
        });

        group.bench_with_input(BenchmarkId::new("show_cred", n), &n, |b, _| {
            b.iter(|| {
                let mut rng = ChaCha20Rng::from_seed([22u8; 32]);
                instantiation2::show_cred(&mut rng, &pp, &ipar, &message, &policy, &obtained_cred)
                    .expect("show")
            });
        });

        group.bench_with_input(BenchmarkId::new("verify_show", n), &n, |b, _| {
            b.iter(|| {
                instantiation2::verify_show(&pp, &ipar, &isk, &policy, &show).expect("verify")
            });
        });

        group.bench_with_input(BenchmarkId::new("issue_del", n), &n, |b, _| {
            b.iter(|| {
                let mut rng = ChaCha20Rng::from_seed([23u8; 32]);
                instantiation2::issue_del(&mut rng, &pp, &isk, &ipar, &message).expect("issue del")
            });
        });

        for &d in DELEGATION_LEVELS {
            let mut chain = encdel.clone();
            let mut chain_dk = dk;
            for _ in 0..d {
                let (next_chain, next_dk) =
                    instantiation2::delegate(&mut rng, &pp, &chain, &chain_dk, &message)
                        .expect("delegate");
                chain = next_chain;
                chain_dk = next_dk;
            }

            group.bench_with_input(
                BenchmarkId::new(format!("delegate_d{d}"), n),
                &n,
                |b, _| {
                    b.iter(|| {
                        let mut rng = ChaCha20Rng::from_seed([24u8; 32]);
                        instantiation2::delegate(&mut rng, &pp, &chain, &chain_dk, &message)
                            .expect("delegate")
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new(format!("obtain_del_d{d}"), n),
                &n,
                |b, _| {
                    b.iter(|| {
                        instantiation2::obtain_del(&pp, &ipar, &chain, &chain_dk)
                            .expect("obtain del")
                    });
                },
            );
        }
    }

    group.finish();
}

// criterion_group!(benches, bench_inst1, bench_inst2);
// criterion_main!(benches);

fn criterion_config() -> Criterion {
    Criterion::default()
        .sample_size(30)
        .measurement_time(Duration::from_secs(10))
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets = bench_inst1, bench_inst2
}

criterion_main!(benches);
