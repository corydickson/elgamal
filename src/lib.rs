use jubjub::{AffinePoint, Base, ExtendedPoint, Scalar};
use rand_core::RngCore;

// Half of the bit length of the chosen prime
const MAX_BYTES: usize = 32;

// https://github.com/zkcrypto/jubjub/blob/6af5abf31c38e2ee006314743941c2912e39cfc4/src/lib.rs#L1578
const FULL_GENERATOR: AffinePoint = AffinePoint::from_raw_unchecked(
    Base::from_raw([
        0xe4b3_d35d_f1a7_adfe,
        0xcaf5_5d1b_29bf_81af,
        0x8b0f_03dd_d60a_8187,
        0x62ed_cbb8_bf37_87c8,
    ]),
    Base::from_raw([0xb, 0x0, 0x0, 0x0]),
);

pub fn generate_random_scalar<T: RngCore>(rng: &mut T) -> Scalar {
    let mut random_bytes = [0u8; 64];
    rng.fill_bytes(&mut random_bytes);
    return Scalar::from_bytes_wide(&random_bytes);
}

fn xor_bs(lhs: BitString, rhs: BitString) -> Vec<u8> {
    lhs.iter().zip(rhs).map(|(a, b)| a ^ b).collect()
}

type Plaintext = String;
type BitString = [u8; MAX_BYTES];

#[derive(Default, Clone, Copy, Debug)]
pub struct PrivateKey(Scalar);

impl PrivateKey {
    pub fn new<T: RngCore>(rng: &mut T) -> Self {
        return PrivateKey(generate_random_scalar(rng));
    }
}

#[derive(Default, Clone, Copy, Debug)]
pub struct PublicKey(ExtendedPoint);

impl PublicKey {
    pub fn derive(pk: PrivateKey) -> Self {
        return PublicKey(FULL_GENERATOR * pk.0);
    }

    pub fn get(self) -> ExtendedPoint {
        self.0
    }

    pub fn encrypt(self, message: &str, y: Scalar) -> Cypher {
        let mut m_b = [0u8; MAX_BYTES];
        m_b[..message.len()].clone_from_slice(&message.as_bytes());

        let shared_secret = self.0 * y;
        let gamma = FULL_GENERATOR * y;

        let (epsilon, phi) = Self::map_to_curve(&mut rand::thread_rng(), m_b);
        let delta = shared_secret + epsilon;

        return Cypher {
            delta,
            gamma,
            phi,
            padding: MAX_BYTES - message.len(),
        };
    }

    fn map_to_curve<T: RngCore>(rng: &mut T, message: BitString) -> (AffinePoint, BitString) {
        let mut encoded_point;
        let mut phi;

        loop {
            let r = generate_random_scalar(rng);
            phi = r.to_bytes();

            // XOR to find a possible X coordinate in the Affine plane
            let x: Vec<u8> = xor_bs(phi, message);
            let guess: BitString = x.try_into().unwrap();

            // check if this is a valid bit string that is on the elliptic curve
            encoded_point = AffinePoint::from_bytes(guess);
            if encoded_point.is_some().unwrap_u8() == 1 {
                break;
            }
        }

        return (encoded_point.unwrap(), phi);
    }
}

pub struct Cypher {
    phi: BitString,
    padding: usize,
    delta: ExtendedPoint,
    gamma: ExtendedPoint,
}

impl Cypher {
    pub fn decrypt(&self, pk: PrivateKey) -> (Plaintext, ExtendedPoint) {
        let epsilon = self.delta - self.gamma * pk.0;
        // Use the mapping to get the plaintext and remove padding
        let point = AffinePoint::from(epsilon).to_bytes();
        let shared_secret = self.delta - epsilon;
        let m_b: Vec<u8> = xor_bs(point, self.phi);
        let plaintext =
            String::from_utf8_lossy(&m_b[0..m_b.len().checked_sub(self.padding).unwrap()])
                .to_string();

        return (plaintext, shared_secret);
    }
}
