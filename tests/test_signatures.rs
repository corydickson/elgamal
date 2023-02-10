mod test_encryption;
use test_encryption::encryption::alice_gen_keypair;

mod signatures {
    use crate::alice_gen_keypair;

    #[test]
    fn test_sign() {
        let (pk, pubkey) = alice_gen_keypair();
        let message = "Signed Message!!!";
        let sig = pubkey.sign(&mut rand::thread_rng(), message, pk);

        let valid = sig.verify(pubkey, message);
        assert!(valid);
    }

    #[test]
    fn test_wrong_pubkey() {
        let (pk, pubkey) = alice_gen_keypair();
        let (_, wrong_pubkey) = alice_gen_keypair();

        let message = "Signed Message!!!";
        let sig = pubkey.sign(&mut rand::thread_rng(), message, pk);

        let valid = sig.verify(wrong_pubkey, message);
        assert!(!valid);
    }

    #[test]
    fn test_wrong_message() {
        let (pk, pubkey) = alice_gen_keypair();

        let message = "Signed Message!!!";
        let sig = pubkey.sign(&mut rand::thread_rng(), message, pk);

        let wrong_message = "Different message";
        let valid = sig.verify(pubkey, wrong_message);
        assert!(!valid);
    }

    #[should_panic(expected = "Invalid private key")]
    #[test]
    fn test_wrong_privatekey() {
        let (_pk, pubkey) = alice_gen_keypair();
        let (wrong_pk, _wrong_pubkey) = alice_gen_keypair();

        let message = "Signed Message!!!";
        let sig = pubkey.sign(&mut rand::thread_rng(), message, wrong_pk);

        let valid = sig.verify(pubkey, message);
        assert!(!valid);
    }

    #[test]
    fn test_recover_pubkey() {
        let (pk, pubkey) = alice_gen_keypair();

        let message = "Signed Message!!!";
        let sig = pubkey.sign(&mut rand::thread_rng(), message, pk);
        let possible = sig.recover_pubkey(message);
        println!("possible n: {:?}, pubkey: {:?}", possible, pubkey);

        for n in possible {
            if n == pubkey.get() {
                println!("possible n: {:?}, pubkey: {:?}", n, pubkey);
            }
        }
    }
}
