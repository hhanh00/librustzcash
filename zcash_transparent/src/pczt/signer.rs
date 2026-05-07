use alloc::vec::Vec;

use zcash_script::solver;

use crate::{address::Script, sighash::SignableInput};

impl super::Input {
    /// Helper to prepare a [`SignableInput`] for this input.
    ///
    /// This can be used to calculate the sighash for this input within its transaction,
    /// to produce a signature externally suitable for passing to [`Self::append_signature`].
    pub fn with_signable_input<T, F>(&self, index: usize, f: F) -> T
    where
        F: FnOnce(SignableInput) -> T,
    {
        // For P2PKH, `script_code` is always the same as `script_pubkey`.
        let script_code = self.redeem_script.as_ref().unwrap_or(&self.script_pubkey);

        f(SignableInput {
            hash_type: self.sighash_type,
            index,
            script_code: &Script::from(script_code),
            script_pubkey: &Script::from(&self.script_pubkey),
            value: self.value,
        })
    }

    /// Signs the transparent spend with the given spend authorizing key.
    ///
    /// It is the caller's responsibility to perform any semantic validity checks on the
    /// PCZT (for example, comfirming that the change amounts are correct) before calling
    /// this method.
    ///
    /// Returns an error if the spend authorizing key does not match any pubkey involved
    /// with spend control of the input's spent coin. The supported script formats are:
    /// - P2PKH
    /// - P2MS
    /// - P2PK
    pub fn sign<C: secp256k1::Signing, F>(
        &mut self,
        index: usize,
        calculate_sighash: F,
        sk: &secp256k1::SecretKey,
        secp: &secp256k1::Secp256k1<C>,
    ) -> Result<(), SignerError>
    where
        F: FnOnce(SignableInput) -> [u8; 32],
    {
        let pubkey = secp256k1::PublicKey::from_secret_key(secp, sk);

        // For P2PKH, `script_code` is always the same as `script_pubkey`.
        let script_code = self.redeem_script.as_ref().unwrap_or(&self.script_pubkey);

        // Check that the corresponding pubkey appears in either `script_pubkey` or
        // `redeem_script`, and determine the correct format (compressed or uncompressed).
        let pubkey_bytes = match script_code
            .refine()
            .ok()
            .as_ref()
            .and_then(solver::standard)
        {
            Some(solver::ScriptKind::PubKeyHash { hash }) => {
                // Determine pubkey format: prefer preimage, otherwise try both
                let pubkey_bytes = if let Some(preimage) = self.hash160_preimages.get(&hash) {
                    match preimage.len() {
                        33 => pubkey.serialize().to_vec(),
                        65 => pubkey.serialize_uncompressed().to_vec(),
                        _ => return Err(SignerError::UnsupportedPubkey),
                    }
                } else {
                    // Try both formats, see which matches the address hash
                    let compressed = pubkey.serialize();
                    let uncompressed = pubkey.serialize_uncompressed();
                    if crate::util::hash160::hash(&compressed) == hash {
                        compressed.to_vec()
                    } else if crate::util::hash160::hash(&uncompressed) == hash {
                        uncompressed.to_vec()
                    } else {
                        return Err(SignerError::WrongSpendingKey);
                    }
                };

                pubkey_bytes
            }
            Some(solver::ScriptKind::MultiSig { pubkeys, .. }) => {
                // Check if our pubkey (in either format) appears in the multisig
                let compressed = pubkey.serialize();
                let uncompressed = pubkey.serialize_uncompressed();

                let found = pubkeys.iter().find(|data| {
                    data.as_slice() == compressed.as_slice()
                        || data.as_slice() == uncompressed.as_slice()
                });

                match found {
                    Some(data) if data.as_slice() == compressed.as_slice() => compressed.to_vec(),
                    Some(data) if data.as_slice() == uncompressed.as_slice() => {
                        uncompressed.to_vec()
                    }
                    _ => return Err(SignerError::WrongSpendingKey),
                }
            }
            Some(solver::ScriptKind::PubKey { data }) => {
                let compressed = pubkey.serialize();
                let uncompressed = pubkey.serialize_uncompressed();

                if data.as_slice() == compressed.as_slice() {
                    compressed.to_vec()
                } else if data.as_slice() == uncompressed.as_slice() {
                    uncompressed.to_vec()
                } else {
                    return Err(SignerError::WrongSpendingKey);
                }
            }
            // This spending key isn't involved with the input in any way we can detect.
            _ => return Err(SignerError::WrongSpendingKey),
        };

        let sighash = calculate_sighash(SignableInput {
            hash_type: self.sighash_type,
            index,
            script_code: &Script::from(script_code),
            script_pubkey: &Script::from(&self.script_pubkey),
            value: self.value,
        });

        let msg = secp256k1::Message::from_digest(sighash);
        let sig = secp.sign_ecdsa(&msg, sk);

        // Signature has to have the SighashType appended to it.
        let mut sig_bytes: Vec<u8> = sig.serialize_der()[..].to_vec();
        sig_bytes.extend([self.sighash_type.encode()]);

        self.partial_signatures.insert(pubkey_bytes, sig_bytes);

        Ok(())
    }

    /// Appends the given signature to the transparent spend.
    ///
    /// It is the caller's responsibility to perform any semantic validity checks on the
    /// PCZT (for example, comfirming that the change amounts are correct) before calling
    /// this method.
    ///
    /// Returns an error if the signature does not match any pubkey involved with spend
    /// control of the input's spent coin. The supported script formats are:
    /// - P2PKH
    ///   - The [`Input::hash160_preimages`] field must contan a mapping from the `pubkeyhash` to
    ///     the pubkey.
    /// - P2MS
    /// - P2PK
    ///
    /// [`Input::hash160_preimages`]: super::Input::hash160_preimages
    pub fn append_signature<C: secp256k1::Verification, F>(
        &mut self,
        index: usize,
        calculate_sighash: F,
        sig: secp256k1::ecdsa::Signature,
        secp: &secp256k1::Secp256k1<C>,
    ) -> Result<(), SignerError>
    where
        F: FnOnce(SignableInput) -> [u8; 32],
    {
        // For P2PKH, `script_code` is always the same as `script_pubkey`.
        let script_code = self.redeem_script.as_ref().unwrap_or(&self.script_pubkey);
        let script_kind = script_code
            .refine()
            .ok()
            .as_ref()
            .and_then(solver::standard);

        fn to_pubkey(data: &[u8]) -> Result<Vec<u8>, SignerError> {
            match data.len() {
                33 | 65 => Ok(data.to_vec()),
                _ => Err(SignerError::UnsupportedPubkey),
            }
        }

        // Extract all candidate pubkeys.
        let pubkeys = match script_kind {
            Some(solver::ScriptKind::PubKeyHash { hash }) => {
                let data = self
                    .hash160_preimages()
                    .get(&hash)
                    .ok_or(SignerError::MissingPreimage)?;
                to_pubkey(data).map(|pubkey| vec![pubkey])
            }
            Some(solver::ScriptKind::MultiSig { pubkeys, .. }) => pubkeys
                .iter()
                .map(|data| to_pubkey(data.as_slice()))
                .collect::<Result<Vec<_>, _>>(),
            Some(solver::ScriptKind::PubKey { data }) => {
                to_pubkey(data.as_slice()).map(|pubkey| vec![pubkey])
            }
            // This spending key isn't involved with the input in any way we can detect.
            _ => Err(SignerError::WrongSpendingKey),
        }?;

        let sighash = calculate_sighash(SignableInput {
            hash_type: self.sighash_type,
            index,
            script_code: &Script::from(script_code),
            script_pubkey: &Script::from(&self.script_pubkey),
            value: self.value,
        });
        let msg = secp256k1::Message::from_digest(sighash);

        // Find the pubkey that the signature validates with.
        for pubkey in pubkeys {
            let pk = secp256k1::PublicKey::from_slice(&pubkey)
                .map_err(|_| SignerError::UnsupportedPubkey)?;

            if secp.verify_ecdsa(&msg, &sig, &pk).is_ok() {
                // Signature has to have the SighashType appended to it.
                let mut sig_bytes: Vec<u8> = sig.serialize_der()[..].to_vec();
                sig_bytes.extend([self.sighash_type.encode()]);

                self.partial_signatures.insert(pubkey, sig_bytes);

                return Ok(());
            }
        }

        Err(SignerError::InvalidExternalSignature)
    }
}

/// Errors that can occur while signing a transparent input in a PCZT.
#[derive(Debug)]
pub enum SignerError {
    /// A provided external signature was not valid for any detected pubkey involved with
    /// spend control of the input's spent coin.
    InvalidExternalSignature,
    /// A required entry in one of the preimage maps is missing.
    MissingPreimage,
    /// A pubkey within the transparent input uses an unsupported format.
    UnsupportedPubkey,
    /// The provided `sk` does not match any pubkey involved with spend control of the
    /// input's spent coin.
    WrongSpendingKey,
}
