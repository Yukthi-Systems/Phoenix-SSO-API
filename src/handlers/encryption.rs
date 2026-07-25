/*
 * Copyright (C) 2026 Yukthi Systems Private Limited
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 3 along with this program. If not, see
 * <https://www.gnu.org/licenses/>.
 */


use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm,
    Nonce,
};
use base64::{
    engine::general_purpose,
    Engine as _,
};


// A fixed 32-byte key for AES-256 encryption
const SECRET_KEY: &[u8; 32] = b"T9H5cEIwcbVk97SXFKTvNBJ33zfXcPni";


/// Creates a new AES-256-GCM cipher instance using the fixed secret key.
fn cipher() -> Aes256Gcm {
    Aes256Gcm::new_from_slice(SECRET_KEY)
        .expect("invalid key")
}


/// Encrypts the given text using AES-256-GCM and returns the base64-encoded ciphertext
pub fn encrypt(text: &str) -> String {
    let cipher = cipher();

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let encrypted = cipher
        .encrypt(&nonce, text.as_bytes())
        .expect("encrypt failed");

    let mut data = nonce.to_vec();

    data.extend(encrypted);

    general_purpose::STANDARD.encode(data)
}


/// Decrypts the given base64-encoded ciphertext using AES-256-GCM and returns the original text
pub fn decrypt(encoded: &str) -> String {
    let data = general_purpose::STANDARD
        .decode(encoded)
        .expect("invalid base64");

    let (nonce_bytes, cipher_bytes) = data.split_at(12);

    let cipher = cipher();

    let decrypted = cipher
        .decrypt(
            Nonce::from_slice(nonce_bytes),
            cipher_bytes,
        )
        .expect("decrypt failed");

    String::from_utf8(decrypted)
        .expect("invalid utf8")
}
