use num_bigint::BigUint;

// pub struct RSAPrivateKey {
//     e: BigUint,
//     n: BigUint,
//     d: BigUint,
// }

pub struct RSAPublicKey {
    e: BigUint,
    n: BigUint,
}

impl RSAPublicKey {
    pub fn new_from_hex_string(exp: &str, modulus: &str) -> Option<RSAPublicKey> {
        let e = BigUint::parse_bytes(exp.as_bytes(), 16)?;
        let n = BigUint::parse_bytes(modulus.as_bytes(), 16)?;
        Some(RSAPublicKey { e: e, n: n })
    }

    fn chunk_size(&self) -> u64 {
        self.n.bits()
    }

    pub fn encrypt_string_hex(&self, msg: &str) -> String {
        let msg_seq = msg.as_bytes();
        let mut enc_text = String::new();

        for block in msg_seq.chunks(self.chunk_size().try_into().unwrap_or(1024) / 8) {
            let enc = BigUint::from_bytes_le(block).modpow(&self.e, &self.n);
            enc_text.push_str(&enc.to_str_radix(16));
            enc_text.push(' ');
        }

        enc_text.pop().unwrap_or_default();
        enc_text
    }
}

// impl Into<RSAPublicKey> for RSAPrivateKey {
//     fn into(self) -> RSAPublicKey {
//         RSAPublicKey {
//             e: self.e,
//             n: self.n,
//         }
//     }
// }

#[cfg(test)]
mod test {
    use super::RSAPublicKey;
    #[test]
    fn encryption_test() {
        let public_key = RSAPublicKey::new_from_hex_string("10001","c5697412dccc5af2dd8472b0391e959c0359bf83c8179454b5ed34c6ed983b1c3b302738a1881f0f6044fae6b7fb004ffc13980ff718ec4b2b3f5ee4332078d1").unwrap();
        assert_eq!(public_key.encrypt_string_hex("12345"),"96c3d9a9551be5593dcf835df2cfdce0171889c1156227dd402d3c8a5b43e963561da7ff5f183642ece61945c67d00e95829d9c9e24d43d651b7dae3b296d045",);
    }
}
