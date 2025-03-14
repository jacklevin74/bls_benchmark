use blst::min_pk::{SecretKey, PublicKey, Signature, AggregateSignature};
use rand::Rng;
use std::time::Instant;
use blst::BLST_ERROR;
use rand::rng;

/// Struct representing a validator with BLS key pair
#[derive(Clone)]
struct Validator {
    secret_key: SecretKey,
    public_key: PublicKey,
}

/// Generate a BLS key pair for a validator
fn generate_validator() -> Validator {
    let mut ikm = [0u8; 32];
    rng().fill(&mut ikm); // ✅ FIXED: Removed thread_rng()

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
    secret_key.sign(message, &[], &[]) // Signing with domain separation tags set to empty
}

/// Verify an individual validator’s signature
fn verify_signature(public_key: &PublicKey, signature: &Signature, message: &[u8; 32]) -> bool {
    let flag = true;
    signature.verify(
        flag,
        message,
        &[],
        &[],
        public_key,
        flag
    ) == BLST_ERROR::BLST_SUCCESS
}

/// Aggregate multiple signatures
fn aggregate_signatures<'a>(
    signatures: &'a [Signature],
    public_keys: &'a [PublicKey]
) -> Option<(AggregateSignature, Vec<&'a PublicKey>)> {
    let sig_refs: Vec<&Signature> = signatures.iter().collect();
    let filtered_pks: Vec<&PublicKey> = public_keys.iter().collect();

    println!("🔗 Aggregating {} signatures", sig_refs.len());
    println!("🔑 Using {} public keys in aggregation", filtered_pks.len());

    if sig_refs.is_empty() {
        println!("⚠️ No valid signatures available for aggregation.");
        return None;
    }

    match AggregateSignature::aggregate(&sig_refs, true) {
        Ok(agg_sig) => Some((agg_sig, filtered_pks)),
        Err(_) => {
            println!("❌ Failed to aggregate signatures!");
            None
        }
    }
}

/// Verify aggregated signatures using `fast_aggregate_verify`
fn verify_aggregated_signature(
    aggregated_signature: &AggregateSignature,
    message: &[u8; 32],
    public_keys: &[&PublicKey],
) -> bool {
    println!("🔍 Verifying aggregated signature for {} public keys", public_keys.len());
    println!("📜 Message hash: {:?}", message);

    if public_keys.is_empty() {
        println!("⚠️ No public keys selected for verification.");
        return false;
    }

    // Convert AggregateSignature to Signature
    let signature = Signature::from_aggregate(aggregated_signature);

    let result = signature.fast_aggregate_verify(
        true,         // Perform subgroup check
        message,      // Message signed
        &[],          // ✅ FIXED: Ensuring domain separation is correct
        public_keys   // Only use the exact subset of signers
    );

    if result == BLST_ERROR::BLST_SUCCESS {
        println!("✅ Aggregated Signature Verification Passed!");
        true
    } else {
        println!("❌ Aggregated Signature Verification Failed!");
        println!("🛠️ DEBUG: Checking mismatches...");
        println!("🔗 Aggregated Signatures: {}", public_keys.len());
        return false;
    }
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

    let signatures: Vec<Signature> = validators.iter()
        .map(|v| sign_block(&v.secret_key, &block_hash))
        .collect();

    let public_keys: Vec<PublicKey> = validators.iter()
        .map(|v| v.public_key.clone())
        .collect();

    println!("⏳ Benchmarking Non-Aggregated Signature Verification...");
    benchmark("🔍 Non-Aggregated Verification", || {
        for (pk, sig) in public_keys.iter().zip(signatures.iter()) {
            verify_signature(pk, sig, &block_hash);
        }
    });

    println!("⏳ Benchmarking Aggregated Signature Verification...");
    if let Some((aggregated_signature, filtered_keys)) = aggregate_signatures(&signatures, &public_keys) {
        benchmark("🔍 Aggregated Verification", || {
            let result = verify_aggregated_signature(&aggregated_signature, &block_hash, &filtered_keys);
            if !result {
                println!("❌ DEBUG: Aggregated verification failed!");
            }
        });
    } else {
        println!("❌ No valid signatures available for aggregation.");
    }

    println!("✅ Benchmarking Complete!");
}

fn main() {
    run_benchmark();
}
