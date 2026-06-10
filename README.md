# DKVAC

Rust prototype implementations of two Delegatable Keyed-Verification Anonymous Credential constructions over Ristretto255.


## Crate Layout

- `dkvac_core`: core library code

## Build And Test

From the workspace root:

```bash
cargo test -p dkvac_core
```

## Benchmarking

Timing benchmarks use Criterion. Size reporting is handled separately by a CSV-producing binary.

Run the Criterion benchmark suite:

```bash
RUSTFLAGS="-C target-cpu=native"  cargo bench -p dkvac_core --bench dkvac_bench
```

Generate CSV size rows:

```bash
cargo run -p dkvac_core --bin size_report
```

The CSV format is:

```text
construction,n_attrs,delegation_level,function,output_size_bytes
```

## Library Usage

The examples below show the intended end-to-end flow for both constructions:

- `setup`
- `keygen`
- `issue_cred`
- `obtain_cred`
- `show_cred`
- `verify_show`
- `issue_del`
- `delegate`
- `obtain_del`

### Instantiation 1

Instantiation 1 authenticates an unordered subset of scalar attributes and supports delegation by removing attributes.

```rust
use dkvac_core::instantiation1;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);

    let pp = instantiation1::setup(&mut rng);
    let (isk, ipar) = instantiation1::keygen(&mut rng, &pp)?;

    let attributes = vec![
        dkvac_core::Scalar::from(10u64),
        dkvac_core::Scalar::from(20u64),
        dkvac_core::Scalar::from(30u64),
    ];

    let (cred, issue_proof) =
        instantiation1::issue_cred(&mut rng, &pp, &isk, &ipar, &attributes)?;

    let cred = instantiation1::obtain_cred(&ipar, &attributes, cred, &issue_proof)?;

    let disclosed = vec![
        dkvac_core::Scalar::from(10u64),
        dkvac_core::Scalar::from(30u64),
    ];

    let show = instantiation1::show_cred(&mut rng, &cred, &disclosed)?;
    let ok = instantiation1::verify_show(&isk, &show)?;
    assert!(ok);

    let (encdel, dk) =
        instantiation1::issue_del(&mut rng, &pp, &isk, &ipar, &attributes)?;

    let delegated_attributes = vec![
        dkvac_core::Scalar::from(10u64),
        dkvac_core::Scalar::from(30u64),
    ];

    let (encdel2, dk2) =
        instantiation1::delegate(&mut rng, &encdel, &dk, &delegated_attributes)?;

    let delegated_cred = instantiation1::obtain_del(&pp, &ipar, &encdel2, &dk2)?;

    let delegated_show =
        instantiation1::show_cred(&mut rng, &delegated_cred, &delegated_attributes)?;
    let delegated_ok = instantiation1::verify_show(&isk, &delegated_show)?;
    assert!(delegated_ok);

    Ok(())
}
```

Notes:

- `issue_cred` returns a direct credential and its issuance proof.
- `issue_del` returns an encrypted delegatable chain plus a decryption key scalar.
- `delegate` returns an updated chain and updated decryption key.
- `obtain_del` decrypts the final chain state into a normal credential.

### Instantiation 2

Instantiation 2 authenticates a fixed-length vector of scalar attributes together with a malleable-index set. Delegation can keep the same message, shrink the malleable set, or modify values only at currently malleable indices.

```rust
use dkvac_core::instantiation2;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::collections::BTreeSet;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = ChaCha20Rng::from_seed([2u8; 32]);

    let pp = instantiation2::setup(&mut rng, 4);
    let (isk, ipar) = instantiation2::keygen(&mut rng, &pp)?;

    let message = instantiation2::Message {
        attributes: vec![
            dkvac_core::Scalar::from(1u64),
            dkvac_core::Scalar::from(2u64),
            dkvac_core::Scalar::from(3u64),
            dkvac_core::Scalar::from(4u64),
        ],
        malleable_indices: BTreeSet::from([1usize, 2usize]),
    };

    let (cred, issue_proof) =
        instantiation2::issue_cred(&mut rng, &pp, &isk, &ipar, &message)?;

    let cred = instantiation2::obtain_cred(&pp, &ipar, &message, cred, &issue_proof)?;

    let policy = instantiation2::DisclosurePolicy {
        disclosed_indices: BTreeSet::from([0usize, 3usize]),
    };

    let show =
        instantiation2::show_cred(&mut rng, &pp, &ipar, &message, &policy, &cred)?;
    let ok =
        instantiation2::verify_show(&pp, &ipar, &isk, &policy, &show)?;
    assert!(ok);

    let (encdel, dk) =
        instantiation2::issue_del(&mut rng, &pp, &isk, &ipar, &message)?;

    let next_message = instantiation2::Message {
        attributes: vec![
            dkvac_core::Scalar::from(1u64),
            dkvac_core::Scalar::from(20u64),
            dkvac_core::Scalar::from(3u64),
            dkvac_core::Scalar::from(4u64),
        ],
        malleable_indices: BTreeSet::from([2usize]),
    };

    let (encdel2, dk2) =
        instantiation2::delegate(&mut rng, &pp, &encdel, &dk, &next_message)?;

    let delegated_cred =
        instantiation2::obtain_del(&pp, &ipar, &encdel2, &dk2)?;

    let delegated_policy = instantiation2::DisclosurePolicy {
        disclosed_indices: BTreeSet::from([0usize, 1usize, 2usize, 3usize]),
    };

    let delegated_show = instantiation2::show_cred(
        &mut rng,
        &pp,
        &ipar,
        &delegated_cred.message,
        &delegated_policy,
        &delegated_cred,
    )?;

    let delegated_ok = instantiation2::verify_show(
        &pp,
        &ipar,
        &isk,
        &delegated_policy,
        &delegated_show,
    )?;
    assert!(delegated_ok);

    Ok(())
}
```



## Disclaimer

This codebase is for research purpose. It is not production-ready cryptographic software.
