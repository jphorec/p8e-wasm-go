use std::panic::catch_unwind;

use aes_gcm::{
    aead::{Aead, NewAead},
    Aes256Gcm, Key, Nonce,
};
use ecdsa::elliptic_curve::{rand_core::OsRng, sec1::ToEncodedPoint};
use errors::P8eEncryptionError;
use hkdf::Hkdf;
use k256::{
    ecdh::{diffie_hellman, EphemeralSecret},
    PublicKey, SecretKey,
};
use lazy_static::lazy_static;
mod errors;
mod proto;
use proto::wasm::{Audience, DecryptRequest, DecryptResponse, EncryptRequest, EncryptResponse};
use protobuf::Message;
use ring::rand::{SecureRandom, SystemRandom};
use sha2::Sha256;

lazy_static! {
    static ref RANDOM: SystemRandom = SystemRandom::new();
}

#[no_mangle]
pub extern "C" fn p8e_encrypt(request_bytes: *const u8, request_bytes_len: usize) -> *const u8 {
    entrypoint(request_bytes, request_bytes_len, p8e_encrypt_inner)
}

#[no_mangle]
pub extern "C" fn p8e_decrypt(request_bytes: *const u8, request_bytes_len: usize) -> *const u8 {
    entrypoint(request_bytes, request_bytes_len, p8e_decrypt_inner)
}

/**
 * Helper function to create generic wasm entrypoints with a single proto request/response pattern
 */
fn entrypoint<T, R, H>(request_bytes: *const u8, request_bytes_len: usize, handler: H) -> *const u8
where
    T: Message,
    R: Message,
    H: Fn(T) -> Result<R, P8eEncryptionError>,
{
    let request_buffer = unsafe { std::slice::from_raw_parts(request_bytes, request_bytes_len) };

    let request = T::parse_from_bytes(request_buffer).unwrap();

    let response = handler(request).unwrap();
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

fn p8e_encrypt_inner(request: EncryptRequest) -> Result<EncryptResponse, P8eEncryptionError> {
    let key = generate_encryption_key();
    let cipher_text = encrypt(&request.payload, &key, false)?;

    // base64 encoding the DEK before encrypting for each audience member, for legacy compatability reasons
    let base64_key = base64(&key);

    // for each audience member, calculate derived secret to generate MAC and ENC key, encrypt DEK
    let audience_list = request
        .audience_public_key
        .iter()
        .map(|public_key| get_audience(public_key, &base64_key))
        .collect::<Result<Vec<Audience>, _>>()?; // add owner to audience list

    let mut response = EncryptResponse::new();
    response.encrypted_payload = cipher_text;
    response.audience = audience_list;

    Ok(response)
}

fn p8e_decrypt_inner(request: DecryptRequest) -> Result<DecryptResponse, P8eEncryptionError> {
    let private_key_bytes = request.private_key;
    let private_key = SecretKey::from_be_bytes(&private_key_bytes)
        .map_err(|_| P8eEncryptionError::PrivateKeyDecodingError)?;
    let audience_member = request.audience.unwrap();

    let secret = diffie_hellman(
        private_key.to_nonzero_scalar(),
        PublicKey::from_sec1_bytes(&&audience_member.ephemeral_pubkey)
            .unwrap()
            .as_affine(),
    );

    let derived_key = hkdf_derive(64, None, secret.raw_secret_bytes(), &[])?;

    let (enc_key, mac_key) = derived_key.split_at(32);

    let mac = encrypt(mac_key, enc_key, true)?;
    let tag_bytes = audience_member.tag;
    assert_eq!(
        tag_bytes,
        mac,
        "Invalid MAC (expected length: {}, actual length: {})",
        tag_bytes.len(),
        mac.len()
    );

    let dek_base64 = decrypt(&audience_member.encrypted_dek, enc_key)?;
    // data encryption key is base64 encoded for legacy reasons
    let plaintext = decrypt(&request.encrypted_payload, &unbase64(&dek_base64))?;

    let mut response = DecryptResponse::new();
    response.payload = plaintext;

    Ok(response)
}

fn unbase64(base64_bytes: &[u8]) -> Vec<u8> {
    base64::decode(base64_bytes).unwrap()
}

fn base64(bytes: &[u8]) -> Vec<u8> {
    base64::encode(bytes).into()
}

const NONCE_LENGTH: usize = 12;
fn encrypt(
    payload: &[u8],
    encryption_key: &[u8],
    zero_iv: bool,
) -> Result<Vec<u8>, P8eEncryptionError> {
    // encrypt payload with DEK
    let key = Key::from_slice(encryption_key);
    let cipher = Aes256Gcm::new(key);
    let mut nonce_buffer = [0u8; NONCE_LENGTH];
    if !zero_iv {
        RANDOM
            .fill(&mut nonce_buffer)
            .map_err(|_| P8eEncryptionError::Unspecified)?;
    }
    let nonce = Nonce::from_slice(&nonce_buffer);
    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| P8eEncryptionError::EncryptionError)?;

    // return encrypted data
    // place size and nonce in buffer before ciphertext
    let mut buffer = u32::to_be_bytes(
        NONCE_LENGTH
            .try_into()
            .map_err(|_| P8eEncryptionError::Unspecified)?,
    )
    .to_vec();
    buffer.extend(nonce_buffer);
    buffer.extend(ciphertext);
    Ok(buffer)
    // if !zero_iv { // todo: what is up with the mismatch on whether the length is in the encrypted data in encrypt/decrypt kotlin-land?
    // } else {
    //     // place NONCE_LENGTH zero buffer before ciphertext
    //     let mut buffer = nonce_buffer.to_vec();
    //     buffer.extend(ciphertext);
    //     Ok(buffer)
    // }
}

fn decrypt(ciphertext: &[u8], encryption_key: &[u8]) -> Result<Vec<u8>, P8eEncryptionError> {
    // decrypt payload with DEK
    let key = Key::from_slice(encryption_key);
    let cipher = Aes256Gcm::new(key);
    let mut nonce_length = [0u8; 4];
    println!("ciphertext len {}", ciphertext.len());
    nonce_length.copy_from_slice(&ciphertext[0..4]);
    let nonce_length: usize = u32::from_be_bytes(nonce_length)
        .try_into()
        .map_err(|_| P8eEncryptionError::DecryptionError)?;

    let nonce_buffer = &ciphertext[4..nonce_length + 4];
    let ciphertext = &ciphertext[nonce_length + 4..];
    // Nonce::from_slice panics if the slice isn't valid, catch_unwind allows converting this to a Result
    let nonce = catch_unwind(|| Nonce::from_slice(&nonce_buffer))
        .map_err(|_| P8eEncryptionError::DecryptionError)?;
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| P8eEncryptionError::DecryptionError)?;

    // return decrypted data
    Ok(plaintext)
}

/** Audience creation/retrieval */

/**
 * Create Audience proto for a given audience public key and encryption key (DEK)
 *
 * This proto contains an encrypted version of the symmetric encryption key used to encrypt the payload, that can be
 * decrypted by the corresponding audience member's private key and subsequently used to decrypt the encrypted payload.
 */
fn get_audience(audience_public_key: &[u8], key: &[u8]) -> Result<Audience, P8eEncryptionError> {
    let ephemeral_secret = EphemeralSecret::random(&mut OsRng);

    let secret = ephemeral_secret.diffie_hellman(
        &PublicKey::from_sec1_bytes(audience_public_key)
            .map_err(|_| P8eEncryptionError::PublicKeyDecodingError)?,
    );

    let derived_key = hkdf_derive(64, None, secret.raw_secret_bytes().as_slice(), &[])?;

    let (enc_key, mac_key) = derived_key.split_at(32);

    let tag = encrypt(mac_key, enc_key, true)?;
    let encrypted_key = encrypt(key, &enc_key, false)?;

    let mut audience = Audience::new();

    audience.public_key = audience_public_key.to_vec();
    audience.encrypted_dek = encrypted_key;
    audience.ephemeral_pubkey = ephemeral_secret
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    audience.tag = tag;

    Ok(audience)
}

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
) -> Result<Vec<u8>, P8eEncryptionError> {
    let pseudorandom_key = Hkdf::<Sha256>::new(salt, input_key_material);
    let mut output_key_material = vec![0u8; size];

    pseudorandom_key
        .expand(info, &mut output_key_material)
        .map_err(|_| P8eEncryptionError::HkdfError)?;

    Ok(output_key_material.into())
}

// todo: failure to decrypt with non-audience private key test
#[cfg(test)]
mod tests {
    use crate::{
        base64, decrypt, encrypt, hkdf_derive, p8e_decrypt_inner, p8e_encrypt_inner,
        proto::{
            self,
            util::UUID,
            wasm::{Audience, DecryptRequest, EncryptRequest},
        },
        unbase64,
    };
    use aes_gcm::{aead::NewAead, Aes256Gcm, Key};
    use ecdsa::elliptic_curve::sec1::ToEncodedPoint;
    use k256::SecretKey;
    use protobuf::MessageField;

    #[test]
    fn response_contains_owner_in_audience() {
        let plaintext = b"test text";
        let owner_private_key = base64::decode("3aTCPoNkrszooOadNgFv1JnweFrgjNmAlWKIdBemssA=")
            .expect("Failed to parse owner private key bytes");
        let owner_private_key = SecretKey::from_be_bytes(&owner_private_key).unwrap();
        let owner_public_key = owner_private_key.public_key();
        let owner_public_key_bytes = owner_public_key.to_encoded_point(false).as_bytes().to_vec();

        let mut request = EncryptRequest::new();
        request.payload = plaintext.to_vec();
        request.audience_public_key = vec![owner_public_key_bytes.clone()];

        let response = p8e_encrypt_inner(request.clone()).unwrap();

        response
            .audience
            .iter()
            .find(|audience| audience.public_key == owner_public_key_bytes)
            .expect("Owner key not listed in audience");
    }

    #[test]
    fn encryption_decryption_roundtrip() {
        let plaintext = b"test text";
        let owner_private_key_bytes =
            base64::decode("3aTCPoNkrszooOadNgFv1JnweFrgjNmAlWKIdBemssA=")
                .expect("Failed to parse owner private key bytes");
        let owner_private_key = SecretKey::from_be_bytes(&owner_private_key_bytes).unwrap();
        let owner_public_key = owner_private_key.public_key();
        let owner_public_key_bytes = owner_public_key.to_encoded_point(false).as_bytes().to_vec();

        let mut request = EncryptRequest::new();
        request.payload = plaintext.to_vec();
        request.audience_public_key = vec![owner_public_key_bytes];

        let response = p8e_encrypt_inner(request).unwrap();

        let mut decrypt_request = DecryptRequest::new();
        decrypt_request.encrypted_payload = response.encrypted_payload;
        decrypt_request.audience =
            MessageField::some(response.audience.first().unwrap().to_owned());
        decrypt_request.private_key = owner_private_key_bytes;

        let decrypted_plaintext = p8e_decrypt_inner(decrypt_request).unwrap().payload;

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

        let result1 = hkdf_derive(64, None, &owner_private_key_bytes, &[]).unwrap();
        let result2 = hkdf_derive(64, None, &owner_private_key_bytes, &[]).unwrap();

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
        let ciphertext = encrypt(plaintext, key, false).unwrap();
        let decrypted = decrypt(&ciphertext, key).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn aes_encrypt_decrypt_round_trip_zero_iv() {
        let super_secret_key = b"an example very very secret key.";
        let key = Key::from_slice(super_secret_key);
        Aes256Gcm::new(key);

        let plaintext = b"hello there";
        let ciphertext = encrypt(plaintext, key, true).unwrap();
        let decrypted = decrypt(&ciphertext, key).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn bogus_private_key_returns_decoding_error() {
        let mut request = DecryptRequest::new();
        request.private_key = b"bogus stuff".to_vec();

        p8e_decrypt_inner(request).unwrap_err();
    }

    #[test]
    fn decrypt_from_kotlin_example() {
        let plaintext = b"hello from test kotlinland";
        let private_key_bytes =
            base64::decode("70qTkZA7/iUsskDaZpW8X2gKdKjha+ugA4M9/psYwUc=").unwrap();
        let dime_input_stream = base64::decode("RElNRQABAAAAEKRBAk+QlUWDqKHH1SucDCMAAADNeyJTSUdOQVRVUkVfUFVCTElDX0tFWSI6Ii0tLS0tQkVHSU4gUFVCTElDIEtFWS0tLS0tXG5NRll3RUFZSEtvWkl6ajBDQVFZRks0RUVBQW9EUWdBRWVFT3JGaGhHWlZ0MjRGNVc0b29RdUNCZEQ5dHRmRFl4XG4rTmpLK0RYQ2xwSTBVcVR0bjJMdHZhVndhWDVqelpib3FzMTRNNVQrMzJKbUhwWE1UMzMxRUE9PVxuLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tXG4ifQAAAAAAAAFpW3sic2lnbmF0dXJlIjoiTUVRQ0lGaHNrOTBlbXZNekUwb1FMaXJ6UEQzYXlyY3puYWU5WXdvSmVnWHhWWmVRQWlCdUVxeXkrZzQzbTlRUWJ6ZTlGVkNqTkJ5YzBQMVdTMkJXT1AwWDBFNjljQT09IiwicHVibGljS2V5IjoiTFMwdExTMUNSVWRKVGlCUVZVSk1TVU1nUzBWWkxTMHRMUzBLVFVaWmQwVkJXVWhMYjFwSmVtb3dRMEZSV1VaTE5FVkZRVUZ2UkZGblFVVmxSVTl5Um1ob1IxcFdkREkwUmpWWE5HOXZVWFZEUW1SRU9YUjBaa1JaZUFvclRtcExLMFJZUTJ4d1NUQlZjVlIwYmpKTWRIWmhWbmRoV0RWcWVscGliM0Z6TVRSTk5WUXJNekpLYlVod1dFMVVNek14UlVFOVBRb3RMUzB0TFVWT1JDQlFWVUpNU1VNZ1MwVlpMUzB0TFMwSyJ9XQAAAzkKJgokZmI2ODNkZGUtZjUxOC00NWVkLWFjZTUtOGJmOWE4M2Q5YjUxEvoCElhCSGhEcXhZWVJtVmJkdUJlVnVLS0VMZ2dYUS9iYlh3Mk1mall5dmcxd3BhU05GS2s3WjlpN2IybGNHbCtZODJXNktyTmVET1UvdDlpWmg2VnpFOTk5UkE9GAEiWEFBQUFEQUFBQUFBQUFBQUFBQUFBQU04ZUxvcmJuSlZpSTZrRHZGTkVBNUk1NGEvOFNCOWE0YUpKdnJFeE1YblRMSTYydTVRMlQ2bG1rZng0RTNCMEdRPT0qWEJFaVpZLzVBNnVOaFB6bC8xazUycTk3MFRxTTE5Z3FpeTlQS245WHpxdkdKcjlSaFFkK1hGcHYwT3VMRDY0TENFRGg3cXpNUlZNbXk0dFB2TVJGVytqcz0yaEFBQUFEUGg2bkR6bS81VDVpRGcySW9PbDQwR1hwZzU1UFRKUVpyL281TUlBekJja0xmYThYc2ErQ2VtQXN5QUl6UXVtMFFUZmgvSklVTU8wZ2Q5aldZTTMxL204RTVlenhvcnhpUT09IvoCElhCSGhEcXhZWVJtVmJkdUJlVnVLS0VMZ2dYUS9iYlh3Mk1mall5dmcxd3BhU05GS2s3WjlpN2IybGNHbCtZODJXNktyTmVET1UvdDlpWmg2VnpFOTk5UkE9GAEiWEFBQUFEQUFBQUFBQUFBQUFBQUFBQU04ZUxvcmJuSlZpSTZrRHZGTkVBNUk1NGEvOFNCOWE0YUpKdnJFeE1YblRMSTYydTVRMlQ2bG1rZng0RTNCMEdRPT0qWEJFaVpZLzVBNnVOaFB6bC8xazUycTk3MFRxTTE5Z3FpeTlQS245WHpxdkdKcjlSaFFkK1hGcHYwT3VMRDY0TENFRGg3cXpNUlZNbXk0dFB2TVJGVytqcz0yaEFBQUFEUGg2bkR6bS81VDVpRGcySW9PbDQwR1hwZzU1UFRKUVpyL281TUlBekJja0xmYThYc2ErQ2VtQXN5QUl6UXVtMFFUZmgvSklVTU8wZ2Q5aldZTTMxL204RTVlenhvcnhpUT09KgCaBhIKBgjC99iVBhoGCML32JUGKAEAAAAM+LAfdHPRTqxhHpDxm1T4Odf00LTmB7J7HghyXCr42vUrqOcfVXFJ8awpv0DNAJ7WvF1p0gQs").unwrap();

        // Audience pieces
        let audience_public_key = base64::decode("QkhoRHF4WVlSbVZiZHVCZVZ1S0tFTGdnWFEvYmJYdzJNZmpZeXZnMXdwYVNORktrN1o5aTdiMmxjR2wrWTgyVzZLck5lRE9VL3Q5aVpoNlZ6RTk5OVJBPQ==").unwrap();
        let audience_ephemeral_public_key = base64::decode("QkVpWlkvNUE2dU5oUHpsLzFrNTJxOTcwVHFNMTlncWl5OVBLbjlYenF2R0pyOVJoUWQrWEZwdjBPdUxENjRMQ0VEaDdxek1SVk1teTR0UHZNUkZXK2pzPQ==").unwrap();
        let audience_tag = base64::decode("QUFBQURBQUFBQUFBQUFBQUFBQUFBTThlTG9yYm5KVmlJNmtEdkZORUE1STU0YS84U0I5YTRhSkp2ckV4TVhuVExJNjJ1NVEyVDZsbWtmeDRFM0IwR1E9PQ==").unwrap();
        let audience_encrypted_dek = base64::decode("QUFBQURQaDZuRHptLzVUNWlEZzJJb09sNDBHWHBnNTVQVEpRWnIvbzVNSUF6QmNrTGZhOFhzYStDZW1Bc3lBSXpRdW0wUVRmaC9KSVVNTzBnZDlqV1lNMzEvbThFNWV6eG9yeGlRPT0=").unwrap();

        let mut audience = Audience::new();
        // have to unbase64 all the things, as the legacy DIME implementation stored things this way...
        // pushing this off to the client to do so the encrypt/decrypt code here stays cleaner without all the
        // unnecessary base64-encoded byte arrays
        audience.public_key = unbase64(&audience_public_key);
        audience.ephemeral_pubkey = unbase64(&audience_ephemeral_public_key);
        audience.tag = unbase64(&audience_tag);
        audience.encrypted_dek = unbase64(&audience_encrypted_dek);

        let mut request = DecryptRequest::new();
        request.private_key = private_key_bytes.into();
        request.audience = MessageField::some(audience);
        request.encrypted_payload = remove_header(&dime_input_stream);

        let result = p8e_decrypt_inner(request).unwrap();

        assert_eq!(plaintext, result.payload.as_slice())
    }

    fn remove_header(dime_input_stream: &[u8]) -> Vec<u8> {
        let dime_input_stream = dime_input_stream[6..].to_vec(); // skip magic bytes and version outright
        let dime_input_stream = discard_u32_sized_chunk(&dime_input_stream); // remove uuid
        let dime_input_stream = discard_u32_sized_chunk(&dime_input_stream); // remove metadata
        let dime_input_stream = discard_u32_sized_chunk(&dime_input_stream); // remove uri
        let dime_input_stream = discard_u32_sized_chunk(&dime_input_stream); // remove signatures
        let dime_input_stream = discard_u32_sized_chunk(&dime_input_stream); // remove dime proto
        dime_input_stream
    }

    fn discard_u32_sized_chunk(bytes: &[u8]) -> Vec<u8> {
        let mut length_buffer = [0u8; 4];
        length_buffer.copy_from_slice(&bytes[0..4]);
        let length: usize = u32::from_be_bytes(length_buffer).try_into().unwrap();
        bytes[4 + length..].to_vec() //skip length and data
    }

    // #[test]
    // fn decrypt_from_node_js_example() {
    //     let plaintext = b"Hello World!Hello World!Hello World!Hello World!";
    //     let private_key_bytes =
    //         base64::decode("vunkS5CB+Q2Pbi0ySLOTI0iD49wCPqHHNFfaDTk4iY8=").unwrap();
    //     let public_key_bytes = SecretKey::from_be_bytes(&private_key_bytes)
    //         .unwrap()
    //         .public_key()
    //         .to_encoded_point(false)
    //         .as_bytes()
    //         .to_vec();
    //     let ephemeral_public_key = base64::decode("BAJdqCnxVk41DjtdV4c3oz32q8aHnbSAA4L6eYwbU0aRNf5kwgpxzjZ37bqXnrSJdF8sWoADeCTKQ43srG5FG8w=").unwrap();
    //     let tag = base64::decode("AAAADAAAAAAAAAAAAAAAAARtiJ6Fsn59QmLPaQpfxH2sPveWFyInfSxNM98yN1JtWp4Cl0LhB1kOkdJq+HmVUw==").unwrap();
    //     let ciphertext = base64::decode("AAAADAAAAAAAAAAAAAAAAJgoosk1IhNczHOsuWUsXtf/PPXBBJRIfx68tx9+Bi2CwpoO9OtICMwC7BLfovSNXh1Jqb6wQaGjwqv2IdPR4C4=").unwrap();

    //     let mut payload = Payload::new();
    //     payload.id = 0;
    //     payload.cipher_text = base64(&ciphertext);

    //     let mut owner_audience = Audience::new();
    //     owner_audience.public_key = base64(&public_key_bytes);
    //     owner_audience.context = ContextType::RETRIEVAL.into();
    //     owner_audience.payload_id = 0;
    //     owner_audience.tag = base64(&tag);
    //     owner_audience.ephemeral_pubkey = base64(&ephemeral_public_key);
    //     // owner_audience.encrypted_dek = // todo: calculate this beforehand from audience private key and ephemeral public key? Isn't that just used for secret used to decrypt dek itself?

    //     let mut dime = DIME::new();
    //     dime.payload = vec![payload];
    //     dime.owner = MessageField::some(owner_audience.clone());
    //     dime.audience = vec![owner_audience];
    //     let mut uuid = UUID::new();
    //     uuid.value = Uuid::new_v4().to_string();
    //     dime.uuid = MessageField::some(uuid);

    //     let mut decrypt_request = DecryptRequest::new();
    //     decrypt_request.dime = MessageField::some(dime);
    //     decrypt_request.private_key = private_key_bytes;

    //     // let response = decrypt(&ciphertext, &private_key_bytes, true).unwrap();
    //     // assert_eq!(plaintext.to_vec(), response);

    //     let response = p8e_decrypt_inner(decrypt_request).unwrap();
    //     assert_eq!(plaintext.to_vec(), response.payload);
    // }
}
