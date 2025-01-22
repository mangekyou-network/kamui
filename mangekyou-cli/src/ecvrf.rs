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
        let secret_key = "58ff3113e38280ef17b3e276c44d10ff05517309d0fe145cf66a09aefcc7bd03";
        let input = "01020304";
        
        let result = execute(Command::Prove(ProveArguments {
            input: input.to_string(),
            secret_key: secret_key.to_string(),
        }))
        .unwrap();

        let expected = "Proof:  1a290c2cc2c76df369f97651c9afd01a59e5cb0e096d40827a573720f6cc681ed349949df21365e12e3aad5970dbbb2c236044f2efa73e354961dab98651bec1c5cc0a33f4a0b23af79a5ad84c304d02\nOutput: d11788f3a9cc69309d803db495623433db261150497944d1189f289058479c1abcef7a3b2c41effd658da8bb02fe96c449317f9f2e2e6b3910c925c568deeb28";
        assert_eq!(expected, result);
    }

    #[test]
    fn test_verify() {
        let input = "01020304";
        let public_key = "aac27ae1424168bf72eb98f1a7f701fec16e0880e179905cefbd155ec446b326";
        let proof = "1a290c2cc2c76df369f97651c9afd01a59e5cb0e096d40827a573720f6cc681ed349949df21365e12e3aad5970dbbb2c236044f2efa73e354961dab98651bec1c5cc0a33f4a0b23af79a5ad84c304d02";
        let output = "d11788f3a9cc69309d803db495623433db261150497944d1189f289058479c1abcef7a3b2c41effd658da8bb02fe96c449317f9f2e2e6b3910c925c568deeb28";

        // Verify with known good values
        let verify_result = execute(Command::Verify(VerifyArguments {
            input: input.to_string(),
            public_key: public_key.to_string(),
            proof: proof.to_string(),
            output: output.to_string(),
        }));

        if let Err(e) = &verify_result {
            println!("Verification error: {:?}", e);
        }

        assert!(verify_result.is_ok(), "Verification failed: {:?}", verify_result);
        assert_eq!("Proof verified correctly!", verify_result.unwrap());

        // Test invalid cases with clearly invalid hex
        let result = execute(Command::Verify(VerifyArguments {
            input: "zzzz".to_string(),  // Invalid hex
            public_key: public_key.to_string(),
            proof: proof.to_string(),
            output: output.to_string(),
        }));
        assert!(result.is_err());

        let result = execute(Command::Verify(VerifyArguments {
            input: input.to_string(),
            public_key: "zzzz".to_string(),  // Invalid hex
            proof: proof.to_string(),
            output: output.to_string(),
        }));
        assert!(result.is_err());

        let result = execute(Command::Verify(VerifyArguments {
            input: input.to_string(),
            public_key: public_key.to_string(),
            proof: "zzzz".to_string(),  // Invalid hex
            output: output.to_string(),
        }));
        assert!(result.is_err());
    }
}
