// Copyright (c) 2022, Mangekyou Network, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use mangekyou::kamui_vrf::ecvrf::{ECVRFKeyPair, ECVRFPrivateKey, ECVRFProof, ECVRFPublicKey};
use mangekyou::kamui_vrf::{VRFKeyPair, VRFProof};
use rand::thread_rng;
use std::io::{Error, ErrorKind};

#[derive(Parser)]
#[command(name = "ecvrf-cli")]
#[command(about = "Elliptic Curve Verifiable Random Function (ECVRF) over Ristretto255 according to draft-irtf-cfrg-vrf-15.", long_about = None)]
enum Command {
    /// Generate a key pair for proving and verification.
    Keygen,

    /// Create an output/hash and a proof.
    Prove(ProveArguments),

    /// Verify an output/hash and a proof.
    Verify(VerifyArguments),
}

#[derive(Parser, Clone)]
struct ProveArguments {
    /// The hex encoded input string.
    #[clap(short, long)]
    input: String,

    /// A hex encoding of the secret key. Corresponds to a scalar in Ristretto255 and must be 32 bytes.
    #[clap(short, long)]
    secret_key: String,
}

#[derive(Parser, Clone)]
struct VerifyArguments {
    /// Hex-encoded Sha512 hash of the proof. Must be 64 bytes.
    #[clap(short, long)]
    output: String,

    /// Encoding of the proof to verify. Must be 80 bytes.
    #[clap(short, long)]
    proof: String,

    /// Hex encoding of the input string used to generate the proof.
    #[clap(short, long)]
    input: String,

    /// The public key corresponding to the secret key used to generate the proof.
    #[clap(short = 'k', long)]
    public_key: String,
}

fn main() {
    match execute(Command::parse()) {
        Ok(res) => {
            println!("{}", res);
            std::process::exit(exitcode::OK);
        }
        Err(e) => {
            println!("Error: {}", e);
            std::process::exit(exitcode::DATAERR);
        }
    }
}

fn execute(cmd: Command) -> Result<String, std::io::Error> {
    match cmd {
        Command::Keygen => {
            let keypair = ECVRFKeyPair::generate(&mut thread_rng());
            let sk_string =
                hex::encode(&keypair.sk);
            let pk_string =
                hex::encode(&keypair.pk);

            let mut result = "Secret key: ".to_string();
            result.push_str(&sk_string);
            result.push_str("\nPublic key: ");
            result.push_str(&pk_string);
            Ok(result)
        }

        Command::Prove(arguments) => {
            // Parse inputs
            let secret_key_bytes = hex::decode(arguments.secret_key)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid private key."))?;
            let alpha_string = hex::decode(arguments.input)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid input string."))?;

            // Create keypair from the secret key bytes
            let secret_key = ECVRFPrivateKey::from_bytes(&secret_key_bytes).unwrap();
            let kp = ECVRFKeyPair::from(secret_key);

            // Generate proof
            let proof = kp.prove(&alpha_string);
            let proof_string = hex::encode(proof.to_bytes());
            let proof_hash = hex::encode(proof.to_hash());

            let mut result = "Proof:  ".to_string();
            result.push_str(&proof_string);
            result.push_str("\nOutput: ");
            result.push_str(&proof_hash);
            Ok(result)
        }

        Command::Verify(arguments) => {
            // Parse inputs
            let public_key_bytes = hex::decode(arguments.public_key)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid public key."))?;
            let alpha_string = hex::decode(arguments.input)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid input string."))?;
            let proof_bytes = hex::decode(arguments.proof)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid proof string."))?;
            let output_bytes = hex::decode(arguments.output)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid output string."))?;
            let output: [u8; 64] = output_bytes
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Output must be 64 bytes."))?;

            // Create public key and proof from parsed bytes
            let public_key: ECVRFPublicKey =
                ECVRFPublicKey::from_bytes(&public_key_bytes).unwrap();
            let proof: ECVRFProof = ECVRFProof::from_bytes(&proof_bytes).unwrap();

            if proof
                .verify_output(&alpha_string, &public_key, &output)
                .is_ok()
            {
                return Ok("Proof verified correctly!".to_string());
            }
            Err(Error::new(ErrorKind::Other, "Proof is not correct."))
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{execute, Command, ProveArguments, VerifyArguments};
    use regex::Regex;

    #[test]
    fn test_keygen() {
        let result = execute(Command::Keygen).unwrap();
        let expected =
            Regex::new(r"Secret key: ([0-9a-fA-F]{64})\nPublic key: ([0-9a-fA-F]{64})").unwrap();
        assert!(expected.is_match(&result));
    }

    #[test]
    fn test_prove() {
        let secret_key = "d354a0525580ab79bf67797b824a7df3ddf81ff45729175fa4d98d9f3dcd150f";
        let input = "4869204b616d756921";

        let result = execute(Command::Prove(ProveArguments {
            input: input.to_string(),
            secret_key: secret_key.to_string(),
        }))
        .unwrap();

        let expected = format!(
            "Proof:  {}\nOutput: {}",
            "54b58f527e999ceedb24485a7629e3caa9f7deb152852a0f483a6646495fa253c4131e87ff0b48fefacf4b5be04211a77390ca85553aa2c06f0023db34e7b36194eadf11539c0ef1c8dcae09aa35580a",
            "8d9c5b901c05a4edf4dff80bbe970db6ca782fe785ef1375989a3fdb3a93b521f4165ea3a6d1c90ae5641bb528beb98c1eed13d36fb32951ecf163b7900e3da6"
        );
        assert_eq!(expected, result);
    }

    #[test]
    fn test_verify() {
        let input = "4869204b616d756921";
        let public_key = "7a66a0fe0f2bcdcea5bfb97e3e9f6b298d25899052721bc2b4f3cb570a921b23";
        let proof = "54b58f527e999ceedb24485a7629e3caa9f7deb152852a0f483a6646495fa253c4131e87ff0b48fefacf4b5be04211a77390ca85553aa2c06f0023db34e7b36194eadf11539c0ef1c8dcae09aa35580a";
        let output = "8d9c5b901c05a4edf4dff80bbe970db6ca782fe785ef1375989a3fdb3a93b521f4165ea3a6d1c90ae5641bb528beb98c1eed13d36fb32951ecf163b7900e3da6";

        let verify_result = execute(Command::Verify(VerifyArguments {
            input: input.to_string(),
            public_key: public_key.to_string(),
            proof: proof.to_string(),
            output: output.to_string(),
        }));

        assert!(verify_result.is_ok());
        assert_eq!("Proof verified correctly!", verify_result.unwrap());

        // Test invalid cases with clearly invalid hex
        let result = execute(Command::Verify(VerifyArguments {
            input: "zzzz".to_string(),  // Invalid hex
            public_key: public_key.to_string(),
            proof: proof.to_string(),
            output: output.to_string(),
        }));
        assert!(result.is_err());
    }
}
