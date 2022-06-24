use std::{borrow::Borrow, str::from_utf8};

use aes_gcm::{
    aead::{Aead, NewAead},
    Aes256Gcm, Key, Nonce,
};
use ecdsa::elliptic_curve::{group::GroupEncoding, rand_core::OsRng, sec1::ToEncodedPoint};
use hkdf::Hkdf;
use k256::{
    ecdh::{self, diffie_hellman, EphemeralSecret},
    PublicKey, Secp256k1, SecretKey,
};
use lazy_static::lazy_static;
mod proto;
use proto::{
    encryption::{Audience, ContextType, Payload, DIME},
    wasm::EncryptRequest,
};
use protobuf::{Message, MessageField};
use ring::rand::{self, SecureRandom, SystemRandom};
use sha2::Sha256;

#[no_mangle]
pub extern "C" fn create_dime(request_bytes: *const u8, request_bytes_len: usize) -> *const u8 {
    let request_buffer = unsafe { std::slice::from_raw_parts(request_bytes, request_bytes_len) };

    let request = EncryptRequest::parse_from_bytes(request_buffer).unwrap();

    let response = create_dime_inner(request);
    let response_bytes = response.write_to_bytes().unwrap();

    let buf_len: i32 = response_bytes.len().try_into().unwrap();
    let dst_ptr = unsafe {
        let dst_ptr = p8e_helpers::p8e_allocate(buf_len + 4);
        let dst_data_ptr = dst_ptr.offset(4);
        let src_ptr = &response_bytes[0] as *const u8;
        std::ptr::copy_nonoverlapping(buf_len.to_le_bytes().as_ptr(), dst_ptr, 4);
        std::ptr::copy_nonoverlapping(src_ptr, dst_data_ptr, buf_len.try_into().unwrap());
        dst_ptr
    };
    dst_ptr
}

fn create_dime_inner(request: EncryptRequest) -> DIME {
    let key = generate_encryption_key();
    let cipher_text = encrypt(&request.payload, &key, false);

    let owner = get_audience(&request.owner_public_key, &key);

    // for each audience member, calculate derived secret to generate MAC and ENC key, encrypt DEK
    let mut audience_list = request
        .audience_public_key
        .iter()
        .map(|public_key| get_audience(public_key, &key))
        .collect::<Vec<Audience>>(); // add owner to audience list

    audience_list.append(&mut vec![owner.clone()]);

    // create DIME message w/ encrypted payload and audience
    let mut dime = DIME::new();

    let mut payload = Payload::new();
    payload.id = 0;
    payload.cipher_text = cipher_text;

    dime.uuid = request.uuid;
    dime.payload = vec![payload];
    dime.owner = MessageField::some(owner);
    dime.audience = audience_list;
    dime.metadata = request.metadata;

    dime
}

/**
 * Create Audience proto for a given audience public key and encryption key (DEK)
 *
 * This proto contains an encrypted version of the symmetric encryption key used to encrypt a DIME payload, that can be
 * decrypted by the corresponding audience member's private key and subsequently used to decrypt the DIME encrypted payload.
 */
fn get_audience(audience_public_key: &[u8], key: &[u8]) -> Audience {
    let ephemeral_secret = EphemeralSecret::random(&mut OsRng);

    let secret =
        ephemeral_secret.diffie_hellman(&PublicKey::from_sec1_bytes(audience_public_key).unwrap());

    let derived_key = hkdf_derive(64, None, secret.raw_secret_bytes().as_slice(), &[]);

    let (enc_key, mac_key) = derived_key.split_at(32);

    let tag = encrypt(mac_key, enc_key, true);
    let encrypted_key = encrypt(key, enc_key, false);

    let mut audience = Audience::new();

    audience.context = ContextType::RETRIEVAL.into(); // todo: support other context types? Is this still needed in DIME world?
    audience.public_key = audience_public_key.to_vec();
    audience.encrypted_dek = encrypted_key;
    audience.ephemeral_pubkey = ephemeral_secret
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    audience.tag = tag;
    audience.payload_id = 0; // todo: are multi-payload actually used/going to be used?

    audience
}

const NONCE_LENGTH: usize = 12;
fn encrypt(payload: &[u8], encryption_key: &[u8], zero_iv: bool) -> Vec<u8> {
    // encrypt payload with DEK
    let key = Key::from_slice(encryption_key);
    let cipher = Aes256Gcm::new(key);
    let mut nonce_buffer = [0u8; NONCE_LENGTH];
    if !zero_iv {
        RANDOM.fill(&mut nonce_buffer).unwrap();
    }
    let nonce = Nonce::from_slice(&nonce_buffer);
    let ciphertext = cipher.encrypt(nonce, payload).expect("encryption error");

    // return encrypted data
    if !zero_iv {
        // place size and nonce in buffer before ciphertext
        let mut buffer = u32::to_le_bytes(NONCE_LENGTH.try_into().unwrap()).to_vec();
        buffer.extend(nonce_buffer);
        buffer.extend(ciphertext);
        buffer
    } else {
        // place NONCE_LENGTH zero buffer before ciphertext
        let mut buffer = nonce_buffer.to_vec();
        buffer.extend(ciphertext);
        buffer
    }
}

fn decrypt(ciphertext: &[u8], encryption_key: &[u8], zero_iv: bool) -> Vec<u8> {
    // decrypt payload with DEK
    let key = Key::from_slice(encryption_key);
    let cipher = Aes256Gcm::new(key);
    let (nonce_buffer, ciphertext): (&[u8], &[u8]) = if !zero_iv {
        let mut nonce_length = [0u8; 4];
        nonce_length.copy_from_slice(&ciphertext[0..4]);
        let nonce_length: usize = u32::from_le_bytes(nonce_length).try_into().unwrap();
        (
            &ciphertext[4..nonce_length + 4],
            &ciphertext[nonce_length + 4..],
        )
        // RANDOM.fill(&mut nonce_buffer).unwrap(); // todo: fetch off payload
    } else {
        (&[0u8; NONCE_LENGTH], &ciphertext[NONCE_LENGTH..])
    };
    let nonce = Nonce::from_slice(&nonce_buffer);
    let plaintext = cipher.decrypt(nonce, ciphertext).unwrap();

    // return decrypted data
    plaintext
}

// todo: decrypt entrypoint
fn decrypt_dime(dime: DIME, private_key_bytes: &[u8]) -> Vec<u8> {
    let private_key = SecretKey::from_be_bytes(&private_key_bytes).unwrap();
    let public_key = private_key.public_key();
    let public_key_bytes = public_key.to_encoded_point(false).as_bytes().to_vec();
    let audience_member = find_audience(&dime, &public_key_bytes);

    let secret = diffie_hellman(
        private_key.to_nonzero_scalar(),
        PublicKey::from_sec1_bytes(&audience_member.ephemeral_pubkey)
            .unwrap()
            .as_affine(),
    );

    let derived_key = hkdf_derive(64, None, secret.raw_secret_bytes(), &[]);

    let (enc_key, mac_key) = derived_key.split_at(32);

    let mac = encrypt(mac_key, enc_key, true);
    assert_eq!(
        audience_member.tag,
        mac,
        "Invalid MAC (expected length: {}, actual length: {})",
        audience_member.tag.len(),
        mac.len()
    );

    let dek = decrypt(&audience_member.encrypted_dek, enc_key, false);
    let plaintext = decrypt(&dime.payload.first().unwrap().cipher_text, &dek, false);

    plaintext
}

fn find_audience(dime: &DIME, public_key_bytes: &[u8]) -> Audience {
    dime.audience
        .iter()
        .find(|audience| audience.public_key == public_key_bytes)
        .expect("Audience list does not contain audience member")
        .to_owned()
}

lazy_static! {
    static ref RANDOM: SystemRandom = SystemRandom::new();
}

// todo: is this the correct key length?
const ENCRYPTION_KEY_LENGTH: usize = 32;

fn generate_encryption_key() -> [u8; ENCRYPTION_KEY_LENGTH] {
    let mut key = [0u8; ENCRYPTION_KEY_LENGTH];
    RANDOM.fill(&mut key).unwrap();

    key
}

/**
 * Key derivation function for deriving Data Encryption Key (DEK)
 */
fn hkdf_derive(
    size: usize,
    salt: Option<&[u8]>,
    input_key_material: &[u8],
    info: &[u8],
) -> Vec<u8> {
    let pseudorandom_key = Hkdf::<Sha256>::new(salt, input_key_material);
    let mut output_key_material = vec![0u8; size];

    pseudorandom_key
        .expand(info, &mut output_key_material)
        .unwrap();

    output_key_material.into()
}

// todo: round-trip test of plaintext -> ciphertext -> plaintext
// todo: derive repeatability test
// todo: failure to decrypt with non-audience private key test
#[cfg(test)]
mod tests {
    use core::panic;
    use std::{ascii::AsciiExt, borrow::Borrow};

    use aes_gcm::{
        aead::generic_array::{ArrayLength, GenericArray},
        aead::{Aead, NewAead},
        Aes256Gcm, Key,
    };
    use ecdsa::elliptic_curve::{group::GroupEncoding, sec1::ToEncodedPoint};
    use k256::{
        pkcs8::{der::pem::Base64Decoder, AlgorithmIdentifier, DecodePrivateKey, PrivateKeyInfo},
        SecretKey,
    };
    use protobuf::MessageField;
    use ring::test::from_hex;
    use uuid::Uuid;

    use crate::{
        create_dime_inner, decrypt, decrypt_dime, encrypt, hkdf_derive,
        proto::{self, wasm::EncryptRequest},
    };

    #[test]
    fn created_dime_contains_owner_in_audience() {
        let plaintext = b"test text";
        let owner_private_key = base64::decode("3aTCPoNkrszooOadNgFv1JnweFrgjNmAlWKIdBemssA=")
            .expect("Failed to parse owner private key bytes");
        let owner_private_key = SecretKey::from_be_bytes(&owner_private_key).unwrap();
        let owner_public_key = owner_private_key.public_key();

        let mut request = EncryptRequest::new();
        request.owner_public_key = owner_public_key.to_encoded_point(false).as_bytes().to_vec();
        request.payload = plaintext.to_vec();
        let mut uuid = proto::util::UUID::new();
        uuid.value = Uuid::new_v4().to_string();
        request.uuid = MessageField::some(uuid);

        let dime = create_dime_inner(request.clone());

        if let Some(owner) = dime.owner.0 {
            assert_eq!(
                &request.owner_public_key, &owner.public_key,
                "owner public key mismatch: expected {:#?}, received {:#?}",
                &request.owner_public_key, &owner.public_key
            );
        } else {
            panic!("dime owner field is not set");
        }

        dime.audience
            .iter()
            .find(|audience| audience.public_key == request.owner_public_key)
            .expect("Owner key not listed in dime audience");
    }

    #[test]
    fn encryption_decryption_roundtrip() {
        let plaintext = b"test text";
        let owner_private_key_bytes =
            base64::decode("3aTCPoNkrszooOadNgFv1JnweFrgjNmAlWKIdBemssA=")
                .expect("Failed to parse owner private key bytes");
        let owner_private_key = SecretKey::from_be_bytes(&owner_private_key_bytes).unwrap();
        let owner_public_key = owner_private_key.public_key();

        let mut request = EncryptRequest::new();
        request.owner_public_key = owner_public_key.to_encoded_point(false).as_bytes().to_vec();
        request.payload = plaintext.to_vec();
        let mut uuid = proto::util::UUID::new();
        uuid.value = Uuid::new_v4().to_string();
        request.uuid = MessageField::some(uuid);

        let dime = create_dime_inner(request);

        let decrypted_plaintext = decrypt_dime(dime, &owner_private_key_bytes);

        assert_eq!(
            plaintext,
            decrypted_plaintext.as_slice(),
            "Decryption failed, expected {}, received {}",
            std::str::from_utf8(plaintext).unwrap(),
            std::str::from_utf8(decrypted_plaintext.as_slice()).unwrap()
        );
    }

    #[test]
    fn hkdf_derive_is_repeatable() {
        let owner_private_key_bytes =
            base64::decode("3aTCPoNkrszooOadNgFv1JnweFrgjNmAlWKIdBemssA=")
                .expect("Failed to parse owner private key bytes");

        let result1 = hkdf_derive(64, None, &owner_private_key_bytes, &[]);
        let result2 = hkdf_derive(64, None, &owner_private_key_bytes, &[]);

        assert_eq!(
            result1, result2,
            "hkdf_derive produced different results for same input!"
        );
    }

    #[test]
    fn aes_encrypt_decrypt_round_trip_nonzero_iv() {
        let super_secret_key = b"an example very very secret key.";
        let key = Key::from_slice(super_secret_key);
        Aes256Gcm::new(key);

        let plaintext = b"hello there";
        let ciphertext = encrypt(plaintext, key, false);
        let decrypted = decrypt(&ciphertext, key, false);

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn aes_encrypt_decrypt_round_trip_zero_iv() {
        let super_secret_key = b"an example very very secret key.";
        let key = Key::from_slice(super_secret_key);
        Aes256Gcm::new(key);

        let plaintext = b"hello there";
        let ciphertext = encrypt(plaintext, key, true);
        let decrypted = decrypt(&ciphertext, key, true);

        assert_eq!(plaintext, decrypted.as_slice());
    }
}
