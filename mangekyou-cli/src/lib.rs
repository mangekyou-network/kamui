//! This module contains test vectors for all signature schemes supported by the sigs_cli tool.
pub mod sigs_cli_test_vectors {

    /// A test vector containing a signature over MSG encoded as a hex string.
    pub struct TestVector {
        pub name: &'static str,
        pub private: &'static str,
        pub public: &'static str,
        pub sig: &'static str,
    }

    pub const MSG: &str = "00010203";
    pub const SEED: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    const ED25519_TEST: TestVector = TestVector {
        name: "ed25519",
        private: "3301e8d7e754db2cf57b0a4ca73f253c7053ad2bc5398777ba039b258e59ad9d",
        public: "8c553335eee80b9bfa0c544a45fe63474a09dff9c4b0b33db2b662f934ea46c4",
        sig: "e929370aa36bef3a6b51594b6d96e0f389f09f28807e6b3a25d0ea93f56dd4659e15995f87545ab8f7f924bc18e0502fa689a57e57e931620b79a6c9ec7b3208",
    };

    const SECP256K1_TEST: TestVector = TestVector {
        name: "secp256k1",
        private: "3301e8d7e754db2cf57b0a4ca73f253c7053ad2bc5398777ba039b258e59ad9d",
        public: "033e99a541db69bd32040dfe5037fbf5210dafa8151a71e21c5204b05d95ce0a62",
        sig: "416a21d50b3c838328d4f03213f8ef0c3776389a972ba1ecd37b56243734eba208ea6aaa6fc076ad7accd71d355f693a6fe54fe69b3c168eace9803827bc9046",
    };

    const SECP256K1_RECOVERABLE_TEST: TestVector = TestVector {
        name: "secp256k1-rec",
        private: SECP256K1_TEST.private,
        public: SECP256K1_TEST.public,
        sig: "416a21d50b3c838328d4f03213f8ef0c3776389a972ba1ecd37b56243734eba208ea6aaa6fc076ad7accd71d355f693a6fe54fe69b3c168eace9803827bc904601",
    };

    const SECP256R1_TEST: TestVector = TestVector {
        name: "secp256r1",
        private: "3301e8d7e754db2cf57b0a4ca73f253c7053ad2bc5398777ba039b258e59ad9d",
        public: "035a8b075508c75f4a124749982a7d21f80d9a5f6893e41a9e955fe4c821e0debe",
        sig: "54d7d68b43d65f718f3a92041292a514987739c36158a836b2218c505ba0e17c661642e58c996ba78f0cca493690b89658d0da3b9333a9e4fcea9ebf13da64bd",
    };

    const SECP256R1_RECOVERABLE_TEST: TestVector = TestVector {
        name: "secp256r1-rec",
        private: SECP256R1_TEST.private,
        public: SECP256R1_TEST.public,
        sig: "54d7d68b43d65f718f3a92041292a514987739c36158a836b2218c505ba0e17c661642e58c996ba78f0cca493690b89658d0da3b9333a9e4fcea9ebf13da64bd01",
    };

    const ECVRF_TEST: TestVector = TestVector {
        name: "ecvrf",
        private: "3301e8d7e754db2cf57b0a4ca73f253c7053ad2bc5398777ba039b258e59ad9d",
        public: "035a8b075508c75f4a124749982a7d21f80d9a5f6893e41a9e955fe4c821e0debe",
        sig: "54d7d68b43d65f718f3a92041292a514987739c36158a836b2218c505ba0e17c661642e58c996ba78f0cca493690b89658d0da3b9333a9e4fcea9ebf13da64bd",
    };

    const TEST_VECTORS: &[TestVector] = &[
        ED25519_TEST,
        SECP256K1_TEST,
        SECP256R1_TEST,
        ECVRF_TEST,
    ];
}
