mod header;
mod proof;
mod utils;
use crate::{proof::get_storage_proof, utils::Block};
use sp1_core::{SP1Prover, SP1Stdin, SP1Verifier};
use jubjub::{Fr, SubgroupPoint};
use jubjub::group::{Group, GroupEncoding};

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    let eth_address = "0xb47e3cd837dDF8e4c57f05d70ab865de6e193bbb";
    let storage_key = "0xbbc70db1b6c7afd11e79c0fb0051300458f1a3acb8ee9789d9b6b26c61ad9bc7";
    let block_number = Block::Latest;

    let trie_proof = match get_storage_proof(eth_address, storage_key, block_number) {
        Ok(proof) => proof,
        Err(e) => panic!("Error getting storage proof: {}", e),
    };

    let amount: u64 = 10;
    let blinding = Fr::from(3u64);
    let g = SubgroupPoint::generator();
    let h = g.double();
    let commit = g * Fr::from(amount) + h * blinding;
    let commit_hex = hex::encode(commit.to_bytes());
    let blinding_hex = hex::encode(blinding.to_bytes());

    let mut stdin = SP1Stdin::new();
    let start = std::time::Instant::now();
    stdin.write(&trie_proof.0);
    stdin.write(&trie_proof.1);
    stdin.write(&commit_hex);
    stdin.write(&blinding_hex);

    let mut proof = SP1Prover::prove(ELF, stdin).expect("proving failed");
    let end = std::time::Instant::now();

    println!("Proof generation time: {:?}", end.duration_since(start));

    let state_root = proof.stdout.read::<String>();
    println!("state root: {}", state_root);

    let ok = proof.stdout.read::<bool>();
    assert_eq!(ok, true);

    let start = std::time::Instant::now();
    // Verify proof.
    SP1Verifier::verify(ELF, &proof).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-io.json")
        .expect("saving proof failed");
    let end = std::time::Instant::now();
    println!("Verification time: {:?}", end.duration_since(start));

    println!("succesfully generated and verified proof for the program!");
}
