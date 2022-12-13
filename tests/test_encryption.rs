pub mod encryption {
    use elgamal::{generate_random_scalar, Cypher, PrivateKey, PublicKey};
    use jubjub::ExtendedPoint;

    pub fn alice_gen_keypair() -> (PrivateKey, PublicKey) {
        let pk = PrivateKey::new(&mut rand::thread_rng());
        let pubkey = PublicKey::derive(pk);

        return (pk, pubkey);
    }

    fn bob_encrypts(pubkey: PublicKey, message: &str) -> (ExtendedPoint, Cypher) {
        let y = generate_random_scalar(&mut rand::thread_rng());
        let cypher = pubkey.encrypt(message, y);

        let shared_secret = pubkey.get() * y;

        return (shared_secret, cypher);
    }

    #[test]
    fn test_small_message() {
        let (pk, pubkey) = alice_gen_keypair();

        let message = "small message";
        let (shared_secret, cypher) = bob_encrypts(pubkey, message);

        let (plaintext, computed_secret) = cypher.decrypt(pk);

        assert_eq!(shared_secret, computed_secret);
        assert_eq!(plaintext, message);
    }

    #[should_panic(expected = "range end index 39 out of range for slice of length 32")]
    #[test]
    fn test_large_message_fail() {
        let (pk, pubkey) = alice_gen_keypair();

        let message = "A very long message with too many bytes";
        let (shared_secret, cypher) = bob_encrypts(pubkey, message);

        let (plaintext, computed_secret) = cypher.decrypt(pk);
        assert_eq!(shared_secret, computed_secret);
        assert_eq!(plaintext, message);
    }

    #[test]
    fn test_wrong_message() {
        let (pk, pubkey) = alice_gen_keypair();

        let message = "valid";
        let (shared_secret, cypher) = bob_encrypts(pubkey, message);

        let (plaintext, computed_secret) = cypher.decrypt(pk);
        assert_eq!(shared_secret, computed_secret);
        assert_ne!(plaintext, "junk");
    }
}
