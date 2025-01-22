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
    let temp_dir = tempdir().unwrap();
    let secret_key_path = temp_dir.path().join("secret_key.txt");
    let mut secret_key_file = File::create(&secret_key_path).unwrap();
    secret_key_file.write_all(b"d46923ae1b1c2c87b369db6d479fbde44e35de67586ccbea684a50a99849a907").unwrap();

    let output = Command::cargo_bin("ecvrf-cli")
        .unwrap()
        .args(&["prove", "-i", "4869204b616d756921", "-s", "d46923ae1b1c2c87b369db6d479fbde44e35de67586ccbea684a50a99849a907"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let output_str = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        output_str,
        "Proof:  06d5cbd3ef200a6f96f3f7e50a77de1429e0376d9b01107cde562ca82d18206e533243e40c96a8d41a99d737cdb30aa2563adb24c47014ece3502db0dd0a838fbaeec863cdf253294e57e2bbd66cac0a\nOutput: c73c584dff09e07c95f470161c7271041e776a52a02849b73e21f0c52251ba51874c6d0e3dee850a1f7d629d9de85f6b6bd5c9c5d4a70bdb7171589564ed623d\n"
    );
}

#[test]
fn integration_test_ecvrf_verify() {
    let result = Command::cargo_bin("ecvrf-cli")
        .unwrap()
        .args(&[
            "verify",
            "--input", "4869204b616d756921",
            "--public-key", "840175d00bcfe8289b43607f3c14ee184b1a9067e794193a8ee221c5b0050246",
            "--proof", "06d5cbd3ef200a6f96f3f7e50a77de1429e0376d9b01107cde562ca82d18206e533243e40c96a8d41a99d737cdb30aa2563adb24c47014ece3502db0dd0a838fbaeec863cdf253294e57e2bbd66cac0a",
            "--output", "c73c584dff09e07c95f470161c7271041e776a52a02849b73e21f0c52251ba51874c6d0e3dee850a1f7d629d9de85f6b6bd5c9c5d4a70bdb7171589564ed623d"
        ])
        .output()
        .unwrap();

    assert!(result.status.success());
    assert_eq!(String::from_utf8(result.stdout).unwrap(), "Proof verified correctly!\n");
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
