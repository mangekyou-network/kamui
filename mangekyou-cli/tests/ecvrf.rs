// Copyright (c) 2022, Mangekyou Network, Inc.
// SPDX-License-Identifier: Apache-2.0

use assert_cmd::Command;
use regex::Regex;
use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

#[test]
fn integration_test_ecvrf_keygen() {
    let result = Command::cargo_bin("ecvrf-cli").unwrap().arg("keygen").ok();
    assert!(result.is_ok());

    let expected =
        Regex::new(r"Secret key: ([0-9a-fA-F]{64})\nPublic key: ([0-9a-fA-F]{64})").unwrap();
    let output = String::from_utf8(result.unwrap().stdout).unwrap();
    assert!(expected.is_match(&output));
}

#[test]
fn integration_test_ecvrf_prove() {
    let secret_key = "d354a0525580ab79bf67797b824a7df3ddf81ff45729175fa4d98d9f3dcd150f";
    let input = "4869204b616d756921";

    let expected = format!(
        "Proof:  {}\nOutput: {}\n",
        "54b58f527e999ceedb24485a7629e3caa9f7deb152852a0f483a6646495fa253c4131e87ff0b48fefacf4b5be04211a77390ca85553aa2c06f0023db34e7b36194eadf11539c0ef1c8dcae09aa35580a",
        "8d9c5b901c05a4edf4dff80bbe970db6ca782fe785ef1375989a3fdb3a93b521f4165ea3a6d1c90ae5641bb528beb98c1eed13d36fb32951ecf163b7900e3da6"
    );

    let output = Command::new(env!("CARGO_BIN_EXE_ecvrf-cli"))
        .arg("prove")
        .arg("--input")
        .arg(input)
        .arg("--secret-key")
        .arg(secret_key)
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(expected, String::from_utf8_lossy(&output.stdout));
}

#[test]
fn integration_test_ecvrf_verify() {
    let input = "4869204b616d756921";
    let public_key = "7a66a0fe0f2bcdcea5bfb97e3e9f6b298d25899052721bc2b4f3cb570a921b23";
    let proof = "54b58f527e999ceedb24485a7629e3caa9f7deb152852a0f483a6646495fa253c4131e87ff0b48fefacf4b5be04211a77390ca85553aa2c06f0023db34e7b36194eadf11539c0ef1c8dcae09aa35580a";
    let output = "8d9c5b901c05a4edf4dff80bbe970db6ca782fe785ef1375989a3fdb3a93b521f4165ea3a6d1c90ae5641bb528beb98c1eed13d36fb32951ecf163b7900e3da6";

    let result = Command::new(env!("CARGO_BIN_EXE_ecvrf-cli"))
        .arg("verify")
        .arg("--input")
        .arg(input)
        .arg("--public-key")
        .arg(public_key)
        .arg("--proof")
        .arg(proof)
        .arg("--output")
        .arg(output)
        .output()
        .unwrap();

    assert!(result.status.success());
    assert_eq!("Proof verified correctly!\n", String::from_utf8_lossy(&result.stdout));
}

#[test]
fn integration_test_ecvrf_e2e() {
    // Keygen
    let result = Command::cargo_bin("ecvrf-cli").unwrap().arg("keygen").ok();
    assert!(result.is_ok());
    let pattern =
        Regex::new(r"Secret key: ([0-9a-fA-F]{64})\nPublic key: ([0-9a-fA-F]{64})").unwrap();
    let stdout = String::from_utf8(result.unwrap().stdout).unwrap();
    assert!(pattern.is_match(&stdout));
    let captures = pattern.captures(&stdout).unwrap();
    let secret_key = captures.get(1).unwrap().as_str();
    let public_key = captures.get(2).unwrap().as_str();

    // Prove
    let input = "01020304";
    let result = Command::cargo_bin("ecvrf-cli")
        .unwrap()
        .arg("prove")
        .arg("--input")
        .arg(input)
        .arg("--secret-key")
        .arg(secret_key)
        .ok();
    assert!(result.is_ok());
    let pattern = Regex::new(r"Proof:  ([0-9a-fA-F]{160})\nOutput: ([0-9a-fA-F]{128})").unwrap();
    let stdout = String::from_utf8(result.unwrap().stdout).unwrap();
    assert!(pattern.is_match(&stdout));
    let captures = pattern.captures(&stdout).unwrap();
    let proof = captures.get(1).unwrap().as_str();
    let output = captures.get(2).unwrap().as_str();

    // Verify
    let result = Command::cargo_bin("ecvrf-cli")
        .unwrap()
        .arg("verify")
        .arg("--output")
        .arg(output)
        .arg("--proof")
        .arg(proof)
        .arg("--input")
        .arg(input)
        .arg("--public-key")
        .arg(public_key)
        .ok();
    assert!(result.is_ok());
    let expected = "Proof verified correctly!\n";
    let output = String::from_utf8(result.unwrap().stdout).unwrap();
    assert_eq!(expected, output);
}
