use blst::min_pk::{SecretKey, PublicKey, Signature, AggregateSignature};
use rand::Rng;
use std::time::Instant;
use blst::BLST_ERROR;



/// Struct representing a validator with BLS key pair
#[derive(Clone)]
struct Validator {
    secret_key: SecretKey,
    public_key: PublicKey,
}

/// Generate a BLS key pair for a validator
fn generate_validator() -> Validator {
#![allow(deprecated)]

    let mut ikm = [0u8; 32];
    rand::thread_rng().fill(&mut ikm); // Random initialization key material (IKM)

    let secret_key = SecretKey::key_gen(&ikm, &[]).expect("Failed to generate key");
    let public_key = secret_key.sk_to_pk();

    Validator { secret_key, public_key }
}

/// Hash message using BLS domain separation
fn hash_message(msg: &str) -> [u8; 32] {
    let mut hash = [0u8; 32];
    let msg_bytes = msg.as_bytes();
    let len = std::cmp::min(32, msg_bytes.len());
    hash[..len].copy_from_slice(&msg_bytes[..len]);
    hash
}

/// Validator signs the block hash
fn sign_block(secret_key: &SecretKey, message: &[u8; 32]) -> Signature {
    //println!("Signing message: {:?}", message);
    secret_key.sign(message, &[], &[]) // Signing with domain separation tags set to empty
}

/// Verify an individual validator’s signature
fn verify_signature(public_key: &PublicKey, signature: &Signature, message: &[u8; 32]) -> bool {
    let flag = true;
    signature.verify(
        flag,      // Group check enabled
        message,   // Message being verified
        &[],       // Domain Separation Tag (DST)
        &[],       // Augmentation input
        public_key,
        flag
    ) == BLST_ERROR::BLST_SUCCESS
}

/// Aggregate multiple signatures based on bitlist filtering
fn aggregate_signatures(signatures: &[Signature], bitlist: &[bool]) -> Option<AggregateSignature> {
    let sig_refs: Vec<&Signature> = signatures
        .iter()
        .zip(bitlist)
        .filter_map(|(sig, &include)| if include { Some(sig) } else { None })
        .collect();

    if sig_refs.is_empty() {
        return None;
    }

    println!("🔗 Aggregating {} signatures", sig_refs.len());
    match AggregateSignature::aggregate(&sig_refs, true) {
        Ok(agg_sig) => Some(agg_sig),
        Err(_) => None,
    }
}

/// Verify aggregated signatures using bitlist filtering
fn verify_aggregated_signature(
    public_keys: &[PublicKey],
    aggregated_signature: &AggregateSignature,
    message: &[u8; 32],
    bitlist: &[bool],
) -> bool {
    let filtered_keys: Vec<&PublicKey> = public_keys
        .iter()
        .zip(bitlist)
        .filter_map(|(pk, &include)| if include { Some(pk) } else { None })
        .collect();

    println!("🔍 Verifying aggregated signature for {} public keys", filtered_keys.len());
    println!("📜 Message hash: {:?}", message);
    println!("🖊️ Aggregated Signature: {:?}", aggregated_signature);

    let result = aggregated_signature.validate() == Ok(());

    if result {
        println!("✅ Aggregated Signature Verification Passed!");
    } else {
        println!("❌ Aggregated Signature Verification Failed!");
    }

    result
}

/// Benchmark function to measure execution time
fn benchmark(label: &str, func: impl FnOnce()) {
    let start = Instant::now();
    func();
    let duration = start.elapsed();
    println!("{}: {:.3} ms", label, duration.as_secs_f64() * 1000.0);
}

/// Benchmark BLS signature verification
fn run_benchmark() {
    const NUM_VALIDATORS: usize = 10000;
    println!("🔐 Generating {} Validators...", NUM_VALIDATORS);

    let validators: Vec<Validator> = (0..NUM_VALIDATORS).map(|_| generate_validator()).collect();
    let block_hash = hash_message("benchmark-block-hash");

    println!("🖊️ Validators Signing the Block...");

    // Simulating a bitlist where some validators do not sign
    let bitlist: Vec<bool> = (0..NUM_VALIDATORS).map(|i| i % 50 != 0).collect();
    //println!("Bitlist: {:?}", bitlist);

    let signatures: Vec<Signature> = validators.iter()
        .enumerate()
        .filter_map(|(i, v)| if bitlist[i] { Some(sign_block(&v.secret_key, &block_hash)) } else { None })
        .collect();

    let public_keys: Vec<PublicKey> = validators.iter().map(|v| v.public_key.clone()).collect();

    println!("⏳ Benchmarking Non-Aggregated Signature Verification...");
    benchmark("🔍 Non-Aggregated Verification", || {
        for (i, sig) in signatures.iter().enumerate() {
            if bitlist[i] {
                verify_signature(&validators[i].public_key, sig, &block_hash);
            }
        }
    });

    println!("⏳ Benchmarking Aggregated Signature Verification...");
    if let Some(aggregated_signature) = aggregate_signatures(&signatures, &bitlist) {
        benchmark("🔍 Aggregated Verification (Bitlist Optimized)", || {
            verify_aggregated_signature(&public_keys, &aggregated_signature, &block_hash, &bitlist);
        });
    } else {
        println!("❌ No valid signatures available for aggregation.");
    }

    println!("✅ Benchmarking Complete!");
}

fn main() {
    run_benchmark();
}
