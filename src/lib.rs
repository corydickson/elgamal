use crypto::digest::Digest;
use crypto::sha2::Sha256;
use jubjub::{AffinePoint, Base, ExtendedPoint, Fr, Scalar, Fq};
use rand_core::RngCore;

const ORDER: Fr = Fr::from_raw([
    0x25f8_0bb3_b996_07d9,
    0xf315_d62f_66b6_e750,
    0x9325_14ee_eb88_14f4,
    0x09a6_fc6f_4791_55c6,
]);

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

    pub fn sign<T: RngCore>(self, rng: &mut T, message: &str, pk: PrivateKey) -> Signature {
        let z_scalar = Signature::gen_message_scalar(message);
        let mut k;
        assert!(self.0 == FULL_GENERATOR * pk.0, "Invalid private key");

        loop {
            k = generate_random_scalar(rng);
            let curve_point = FULL_GENERATOR * k;

            if curve_point.is_identity().unwrap_u8() == 0 {
                let affine = AffinePoint::from(curve_point);
                let possible_r = Scalar::from_bytes(&affine.get_u().to_bytes());

                if possible_r.is_some().unwrap_u8() == 1 {
                    let r = possible_r.unwrap();
                    let inner = z_scalar + r.mul(&pk.0);
                    let s = k.invert().unwrap().mul(&inner);
                    let sig = Signature { r, s };
                    // hack: sometimes there is an x coordinate that's not in the scalar field
                    if sig.verify(self, message) {
                        return sig;
                    }
                }
            }
        }
    }

}

pub struct Signature {
    r: Fr,
    s: Fr,
}

impl Signature {
    pub fn gen_message_scalar(message: &str) -> Fr {
        let mut hasher = Sha256::new();
        hasher.input_str(message);
        let hex = hasher.result_str();
        let e = hex.as_bytes();
        let z: [u8; 64] = e[0..64].try_into().unwrap();
        Scalar::from_bytes_wide(&z)
    }

    pub fn verify(&self, pubkey: PublicKey, message: &str) -> bool {
        let z_scalar = Signature::gen_message_scalar(message);
        let s_invert = &self.s.invert().unwrap();
        let u_1 = z_scalar.mul(s_invert);
        let u_2 = self.r.mul(s_invert);

        let point = (FULL_GENERATOR * u_1) + (pubkey.get() * u_2);
        let possible_r = Scalar::from_bytes(&AffinePoint::from(point).get_u().to_bytes());

        if possible_r.is_some().unwrap_u8() == 1 {
            return self.r == possible_r.unwrap();
        }

        return false;
    }

    fn solve_affine_point(u: Fr) -> AffinePoint {
        // d = -(10240/10241)

        // potential solutions for v:
        // where u = r, u = r + n, u = r + 2n;
        // v = +- (7 * sqrt(209) * sqrt(u^2 + 1)) / sqrt(10240u^2  + 10241)
        let mut a = [0u8; 32];
        a[0] = *7_u8.to_le_bytes().get(0).unwrap();
        let mut b = [0u8; 32];
        b[0] = *209_u8.to_le_bytes().get(0).unwrap();
        let mut c = [0u8; 32];
        c[0] = *1_u8.to_le_bytes().get(0).unwrap();
        let mut d1 = [0u8; 32];
        d1[0..2].copy_from_slice(&10240_u16.to_le_bytes());
        let mut d2 = [0u8; 32];
        d2[0..2].copy_from_slice(&10241_u16.to_le_bytes());

        let t: &[u64; 4] = &[
            0x0000_0000_0000,
            0x0000_0000_0000,
            0x0000_0000_0000,
            0x0000_0000_0001
        ];

        let numerator =
            Fr::from_bytes(&a).unwrap() *
            Fr::from_bytes(&b).unwrap().sqrt().unwrap() *
            (u.pow(t) + Fr::from_bytes(&c).unwrap()).sqrt().unwrap();

        let denominator = (
            Fr::from_bytes(&d1).unwrap() *
            u.pow(t) + Fr::from_bytes(&d2).unwrap()
        ).sqrt().unwrap();
        let div = numerator * denominator.invert().unwrap();

        return AffinePoint::from_raw_unchecked(Fq::from_bytes(&u.to_bytes()).unwrap(), Fq::from_bytes(&div.to_bytes()).unwrap());
        // return AffinePoint::identity()
    }

    pub fn find_sig_points(&self) -> Vec<AffinePoint> {
        // the goal here is to use these values to find a point on the curve where these are the x
        // values. The problem is that the api currently takes in the byte representation of both
        // points which we don't have. Therefore finding possible points that can be used to find
        // the pub key is reduced to this one r because it's certainly within the field
        let mut rn = self.r.clone();
        rn = rn + &ORDER;
        let r2n = rn + ORDER;

        let mut points = Vec::new();
        points.push(Self::solve_affine_point(self.r));
        points.push(Self::solve_affine_point(rn));
        points.push(Self::solve_affine_point(r2n));
        return points;
    }

    pub fn recover_pubkey(&self, message: &str) -> Vec<ExtendedPoint> {
        let points = self.find_sig_points();
        let z_scalar = Signature::gen_message_scalar(message);
        let u_1 = z_scalar.neg().mul(&self.r);
        let u_2 = self.s.mul(&self.r.invert().unwrap());

        let mut possible_keys = Vec::new();

        for p in points {
            let q = (FULL_GENERATOR * u_1) + (p * u_2);
            possible_keys.push(q);
        }

        return possible_keys;
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
