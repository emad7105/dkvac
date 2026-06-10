use dkvac_core::instantiation1;
use dkvac_core::instantiation2;
use dkvac_core::size;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::collections::BTreeSet;

const ATTR_COUNTS: &[usize] = &[4, 8, 32, 64];
const DELEGATION_LEVELS: &[usize] = &[0,3,6];

fn scalar_sequence_1(n: usize) -> Vec<dkvac_core::Scalar> {
    (1..=n).map(|i| dkvac_core::Scalar::from(i as u64)).collect()
}

fn print_row(construction: &str, n_attrs: usize, delegation_level: usize, function: &str, size_bytes: usize) {
    println!("{construction},{n_attrs},{delegation_level},{function},{size_bytes}");
}

fn main() {
    println!("construction,n_attrs,delegation_level,function,output_size_bytes");

    for &n in ATTR_COUNTS {
        let attrs = scalar_sequence_1(n);
        let disclosed = attrs.clone();

        for &d in DELEGATION_LEVELS {
            let mut rng = ChaCha20Rng::from_seed([n as u8; 32]);
            let pp = instantiation1::setup(&mut rng);
            let (isk, ipar) = instantiation1::keygen(&mut rng, &pp).expect("keygen");
            let (cred, proof) =
                instantiation1::issue_cred(&mut rng, &pp, &isk, &ipar, &attrs).expect("issue");
            let obtained_cred =
                instantiation1::obtain_cred(&ipar, &attrs, cred.clone(), &proof).expect("obtain");
            let show =
                instantiation1::show_cred(&mut rng, &obtained_cred, &disclosed).expect("show");
            let (encdel, dk) =
                instantiation1::issue_del(&mut rng, &pp, &isk, &ipar, &attrs).expect("issue del");

            let mut chain = encdel.clone();
            let mut chain_dk = dk;
            for _ in 0..d {
                let (next_chain, next_dk) =
                    instantiation1::delegate(&mut rng, &chain, &chain_dk, &attrs).expect("delegate");
                chain = next_chain;
                chain_dk = next_dk;
            }
            let obtained_del =
                instantiation1::obtain_del(&pp, &ipar, &chain, &chain_dk).expect("obtain del");

            print_row("inst1", n, d, "issue_cred", size::inst1_issue_cred_output_size(&cred, &proof));
            print_row("inst1", n, d, "obtain_cred", size::inst1_credential_size(&obtained_cred));
            print_row("inst1", n, d, "show_cred", size::inst1_show_size(&show));
            print_row("inst1", n, d, "issue_del", size::inst1_issue_del_output_size(&encdel));
            print_row("inst1", n, d, "delegate", size::inst1_delegate_output_size(&chain));
            print_row("inst1", n, d, "obtain_del", size::inst1_obtain_del_output_size(&obtained_del));
            println!("------");
        }
        println!("=================================");
    }

    for &n in ATTR_COUNTS {
        let message = instantiation2::Message {
            attributes: scalar_sequence_1(n),
            malleable_indices: (0..n).collect::<BTreeSet<_>>(),
        };
        let policy = instantiation2::DisclosurePolicy {
            disclosed_indices: (0..n).collect::<BTreeSet<_>>(),
        };

        for &d in DELEGATION_LEVELS {
            let mut rng = ChaCha20Rng::from_seed([100u8.wrapping_add(n as u8); 32]);
            let pp = instantiation2::setup(&mut rng, n);
            let (isk, ipar) = instantiation2::keygen(&mut rng, &pp).expect("keygen");
            let (cred, proof) =
                instantiation2::issue_cred(&mut rng, &pp, &isk, &ipar, &message).expect("issue");
            let obtained_cred =
                instantiation2::obtain_cred(&pp, &ipar, &message, cred.clone(), &proof).expect("obtain");
            let show =
                instantiation2::show_cred(&mut rng, &pp, &ipar, &message, &policy, &obtained_cred)
                    .expect("show");
            let (encdel, dk) =
                instantiation2::issue_del(&mut rng, &pp, &isk, &ipar, &message).expect("issue del");

            let mut chain = encdel.clone();
            let mut chain_dk = dk;
            for _ in 0..d {
                let (next_chain, next_dk) =
                    instantiation2::delegate(&mut rng, &pp, &chain, &chain_dk, &message)
                        .expect("delegate");
                chain = next_chain;
                chain_dk = next_dk;
            }
            let obtained_del =
                instantiation2::obtain_del(&pp, &ipar, &chain, &chain_dk).expect("obtain del");

            print_row("inst2", n, d, "issue_cred", size::inst2_issue_cred_output_size(&cred, &proof));
            print_row("inst2", n, d, "obtain_cred", size::inst2_credential_size(&obtained_cred));
            print_row("inst2", n, d, "show_cred", size::inst2_show_size(&show));
            print_row("inst2", n, d, "issue_del", size::inst2_issue_del_output_size(&encdel));
            print_row("inst2", n, d, "delegate", size::inst2_delegate_output_size(&chain));
            print_row("inst2", n, d, "obtain_del", size::inst2_obtain_del_output_size(&obtained_del));
            println!("------");
        }
        println!("=================================");
    }
}
