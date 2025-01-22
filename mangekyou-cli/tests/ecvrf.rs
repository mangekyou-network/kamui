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
    secret_key_file.write_all(b"58ff3113e38280ef17b3e276c44d10ff05517309d0fe145cf66a09aefcc7bd03").unwrap();

    let output = Command::cargo_bin("ecvrf-cli")
        .unwrap()
        .args(&["prove", "-i", "01020304", "-s", "58ff3113e38280ef17b3e276c44d10ff05517309d0fe145cf66a09aefcc7bd03"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let output_str = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        output_str,
        "Proof:  1a290c2cc2c76df369f97651c9afd01a59e5cb0e096d40827a573720f6cc681ed349949df21365e12e3aad5970dbbb2c236044f2efa73e354961dab98651bec1c5cc0a33f4a0b23af79a5ad84c304d02\nOutput: d11788f3a9cc69309d803db495623433db261150497944d1189f289058479c1abcef7a3b2c41effd658da8bb02fe96c449317f9f2e2e6b3910c925c568deeb28\n"
    );
}

#[test]
fn integration_test_ecvrf_verify() {
    let result = Command::cargo_bin("ecvrf-cli")
        .unwrap()
        .args(&[
            "verify",
            "--input", "01020304",
            "--public-key", "aac27ae1424168bf72eb98f1a7f701fec16e0880e179905cefbd155ec446b326",
            "--proof", "1a290c2cc2c76df369f97651c9afd01a59e5cb0e096d40827a573720f6cc681ed349949df21365e12e3aad5970dbbb2c236044f2efa73e354961dab98651bec1c5cc0a33f4a0b23af79a5ad84c304d02",
            "--output", "d11788f3a9cc69309d803db495623433db261150497944d1189f289058479c1abcef7a3b2c41effd658da8bb02fe96c449317f9f2e2e6b3910c925c568deeb28"
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
