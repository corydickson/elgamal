mod test_encryption;
use test_encryption::encryption::alice_gen_keypair;

mod signatures {
    use crate::alice_gen_keypair;
    use elgamal::gen_message_scalar;

    #[test]
    fn test_sign() {
        let (pk, pubkey) = alice_gen_keypair();
        let message = "Signed Message!!!";
        let (r, s, computed_scalar) = pubkey.sign(&mut rand::thread_rng(), message, pk);

        let z_scalar = gen_message_scalar(message);
        assert_eq!(computed_scalar, z_scalar);

        let valid = pubkey.verify_sig(r, s, z_scalar);
        assert!(valid);
    }

    #[test]
    fn test_wrong_pubkey() {
        let (pk, pubkey) = alice_gen_keypair();
        let (_, wrong_pubkey) = alice_gen_keypair();

        let message = "Signed Message!!!";
        let (r, s, computed_scalar) = pubkey.sign(&mut rand::thread_rng(), message, pk);

        let z_scalar = gen_message_scalar(message);
        assert_eq!(computed_scalar, z_scalar);

        let valid = wrong_pubkey.verify_sig(r, s, z_scalar);
        assert!(!valid);
    }

    #[test]
    fn test_wrong_message() {
        let (pk, pubkey) = alice_gen_keypair();

        let message = "Signed Message!!!";
        let (r, s, computed_scalar) = pubkey.sign(&mut rand::thread_rng(), message, pk);

        let wrong_message = "Different message";
        let z_scalar = gen_message_scalar(wrong_message);
        assert_ne!(computed_scalar, z_scalar);

        let valid = pubkey.verify_sig(r, s, z_scalar);
        assert!(!valid);
    }

    #[should_panic(expected = "Invalid private key")]
    #[test]
    fn test_wrong_privatekey() {
        let (_pk, pubkey) = alice_gen_keypair();
        let (wrong_pk, wrong_pubkey) = alice_gen_keypair();

        let message = "Signed Message!!!";
        let (r, s, computed_scalar) = pubkey.sign(&mut rand::thread_rng(), message, wrong_pk);

        let z_scalar = gen_message_scalar(message);
        assert_eq!(computed_scalar, z_scalar);

        let valid = wrong_pubkey.verify_sig(r, s, z_scalar);
        assert!(!valid);
    }
}
