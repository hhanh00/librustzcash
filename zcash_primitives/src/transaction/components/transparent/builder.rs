//! Types and functions for building transparent transaction components.

use std::fmt;

use crate::{
    legacy::{Script, TransparentAddress},
    transaction::{
        components::{
            amount::{Amount, BalanceError, NonNegativeAmount},
            transparent::{self, Authorization, Authorized, Bundle, TxIn, TxOut},
        },
        sighash::TransparentAuthorizingContext,
    },
};

#[cfg(feature = "transparent-inputs")]
use {
    crate::transaction::{
        self as tx,
        components::transparent::OutPoint,
        sighash::{signature_hash, SignableInput, SIGHASH_ALL},
        TransactionData, TxDigests,
    },
    blake2b_simd::Hash as Blake2bHash,
    sha2::Digest,
};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidAddress,
    InvalidAmount,
    InvalidOpReturn,
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidAddress => write!(f, "Invalid address"),
            Error::InvalidAmount => write!(f, "Invalid amount"),
            Error::InvalidOpReturn => write!(f, "Invalid memo"),
        }
    }
}

#[cfg(feature = "transparent-inputs")]
#[derive(Debug, Clone)]
pub struct TransparentInputInfo {
    sk: Option<secp256k1::SecretKey>,
    pubkey: [u8; secp256k1::constants::PUBLIC_KEY_SIZE],
    utxo: OutPoint,
    coin: TxOut,
}

#[cfg(feature = "transparent-inputs")]
impl TransparentInputInfo {
    pub fn outpoint(&self) -> &OutPoint {
        &self.utxo
    }

    pub fn coin(&self) -> &TxOut {
        &self.coin
    }
}

pub struct TransparentBuilder {
    #[cfg(feature = "transparent-inputs")]
    secp: secp256k1::Secp256k1<secp256k1::SignOnly>,
    #[cfg(feature = "transparent-inputs")]
    inputs: Vec<TransparentInputInfo>,
    vout: Vec<TxOut>,
}

#[derive(Debug, Clone)]
pub struct Unauthorized {
    #[cfg(feature = "transparent-inputs")]
    secp: secp256k1::Secp256k1<secp256k1::SignOnly>,
    #[cfg(feature = "transparent-inputs")]
    inputs: Vec<TransparentInputInfo>,
}

impl Authorization for Unauthorized {
    type ScriptSig = ();
}

impl TransparentBuilder {
    /// Constructs a new TransparentBuilder
    pub fn empty() -> Self {
        TransparentBuilder {
            #[cfg(feature = "transparent-inputs")]
            secp: secp256k1::Secp256k1::gen_new(),
            #[cfg(feature = "transparent-inputs")]
            inputs: vec![],
            vout: vec![],
        }
    }

    /// Returns the list of transparent inputs that will be consumed by the transaction being
    /// constructed.
    #[cfg(feature = "transparent-inputs")]
    pub fn inputs(&self) -> &[TransparentInputInfo] {
        &self.inputs
    }

    /// Returns the transparent outputs that will be produced by the transaction being constructed.
    pub fn outputs(&self) -> &[TxOut] {
        &self.vout
    }

    /// Adds a coin (the output of a previous transaction) to be spent to the transaction.
    #[cfg(feature = "transparent-inputs")]
    pub fn add_input(
        &mut self,
        sk: secp256k1::SecretKey,
        utxo: OutPoint,
        coin: TxOut
    ) -> Result<(), Error> {
        let pk = secp256k1::PublicKey::from_secret_key(&self.secp, &sk);
        let pubkey = pk.serialize();
        self.check_input(&pubkey, &coin)?;
        self.inputs.push(TransparentInputInfo {
            sk: Some(sk),
            pubkey,
            utxo,
            coin,
        });
        Ok(())
    }

    /// Adds a coin (the output of a previous transaction) to be spent to the transaction.
    #[cfg(feature = "transparent-inputs")]
    pub fn add_input_without_sk(
        &mut self,
        pk: secp256k1::PublicKey,
        utxo: OutPoint,
        coin: TxOut,
    ) -> Result<(), Error> {
        let pubkey = pk.serialize();
        self.check_input(&pubkey, &coin)?;
        self.inputs.push(TransparentInputInfo {
            sk: None,
            utxo,
            pubkey,
            coin,
        });
        Ok(())
    }

    /// Adds a coin (the output of a previous transaction) to be spent to the transaction.
    #[cfg(feature = "transparent-inputs")]
    pub fn check_input(
        &self,
        pubkey: &[u8; 33],
        coin: &TxOut,
    ) -> Result<(), Error> {
        // Ensure that the RIPEMD-160 digest of the public key associated with the
        // provided secret key matches that of the address to which the provided
        // output may be spent.
        match coin.script_pubkey.address() {
            Some(TransparentAddress::PublicKeyHash(hash)) => {
                use ripemd::Ripemd160;
                use sha2::Sha256;

                if hash[..] != Ripemd160::digest(Sha256::digest(pubkey))[..] {
                    return Err(Error::InvalidAddress);
                }
            }
            _ => return Err(Error::InvalidAddress),
        }

        Ok(())
    }

    pub fn add_output(
        &mut self,
        to: &TransparentAddress,
        value: NonNegativeAmount,
    ) -> Result<(), Error> {
        self.vout.push(TxOut {
            value,
            script_pubkey: to.script(),
        });

        Ok(())
    }

    pub fn add_output_memo(
        &mut self,
        memo: &[u8]
    ) -> Result<(), Error> {
        let script = Script::op_return(memo).ok_or_else(|| Error::InvalidOpReturn)?;
        self.vout.push(TxOut {
            value: NonNegativeAmount::ZERO,
            script_pubkey: script,
        });

        Ok(())
    }

    pub fn value_balance(&self) -> Result<Amount, BalanceError> {
        #[cfg(feature = "transparent-inputs")]
        let input_sum = self
            .inputs
            .iter()
            .map(|input| input.coin.value)
            .sum::<Option<NonNegativeAmount>>()
            .ok_or(BalanceError::Overflow)?;

        #[cfg(not(feature = "transparent-inputs"))]
        let input_sum = NonNegativeAmount::ZERO;

        let output_sum = self
            .vout
            .iter()
            .map(|vo| vo.value)
            .sum::<Option<NonNegativeAmount>>()
            .ok_or(BalanceError::Overflow)?;

        (Amount::from(input_sum) - Amount::from(output_sum)).ok_or(BalanceError::Underflow)
    }

    pub fn build(self) -> Option<transparent::Bundle<Unauthorized>> {
        #[cfg(feature = "transparent-inputs")]
        let vin: Vec<TxIn<Unauthorized>> = self
            .inputs
            .iter()
            .map(|i| TxIn::new(i.utxo.clone()))
            .collect();

        #[cfg(not(feature = "transparent-inputs"))]
        let vin: Vec<TxIn<Unauthorized>> = vec![];

        if vin.is_empty() && self.vout.is_empty() {
            None
        } else {
            Some(transparent::Bundle {
                vin,
                vout: self.vout,
                authorization: Unauthorized {
                    #[cfg(feature = "transparent-inputs")]
                    secp: self.secp,
                    #[cfg(feature = "transparent-inputs")]
                    inputs: self.inputs,
                },
            })
        }
    }
}

impl TxIn<Unauthorized> {
    #[cfg(feature = "transparent-inputs")]
    pub fn new(prevout: OutPoint) -> Self {
        TxIn {
            prevout,
            script_sig: (),
            sequence: std::u32::MAX,
        }
    }
}

#[cfg(not(feature = "transparent-inputs"))]
impl TransparentAuthorizingContext for Unauthorized {
    fn input_amounts(&self) -> Vec<NonNegativeAmount> {
        vec![]
    }

    fn input_scriptpubkeys(&self) -> Vec<Script> {
        vec![]
    }
}

#[cfg(feature = "transparent-inputs")]
impl TransparentAuthorizingContext for Unauthorized {
    fn input_amounts(&self) -> Vec<NonNegativeAmount> {
        return self.inputs.iter().map(|txin| txin.coin.value).collect();
    }

    fn input_scriptpubkeys(&self) -> Vec<Script> {
        return self
            .inputs
            .iter()
            .map(|txin| txin.coin.script_pubkey.clone())
            .collect();
    }
}

impl Bundle<Unauthorized> {
    pub fn get_sighashes(
        &self,
        #[cfg(feature = "transparent-inputs")] mtx: &TransactionData<tx::Unauthorized>,
        #[cfg(feature = "transparent-inputs")] txid_parts_cache: &TxDigests<Blake2bHash>,
    ) -> Vec<Vec<u8>> {
        #[cfg(feature = "transparent-inputs")]
        let sighashes = self
            .authorization
            .inputs
            .iter()
            .enumerate()
            .map(|(index, info)| {
                let sighash = signature_hash(
                    mtx,
                    &SignableInput::Transparent {
                        hash_type: SIGHASH_ALL,
                        index,
                        script_code: &info.coin.script_pubkey, // for p2pkh, always the same as script_pubkey
                        script_pubkey: &info.coin.script_pubkey,
                        value: info.coin.value,
                    },
                    txid_parts_cache,
                );
                sighash.as_ref().to_vec()
            })
            .collect::<Vec<_>>();

        #[cfg(not(feature = "transparent-inputs"))]
        let script_sigs: Vec<Vec<u8>> = vec![];

        sighashes
    }

    pub fn apply_external_signatures(
        self,
        #[cfg(feature = "transparent-inputs")] signatures: Vec<secp256k1::ecdsa::Signature>,
    ) -> Bundle<Authorized> {
        #[cfg(feature = "transparent-inputs")]
        let script_sigs = {
            self
            .authorization
            .inputs
            .iter()
            .zip(signatures)
            .map(|(info, signature)| {
                let mut sig_bytes: Vec<u8> = signature.serialize_der()[..].to_vec();
                sig_bytes.extend([SIGHASH_ALL]);

                // P2PKH scriptSig
                Script::default() << &sig_bytes[..] << &info.pubkey[..]
            })
        };

        #[cfg(not(feature = "transparent-inputs"))]
        let script_sigs = std::iter::empty::<Script>();

        transparent::Bundle {
            vin: self
                .vin
                .iter()
                .zip(script_sigs)
                .map(|(txin, sig)| TxIn {
                    prevout: txin.prevout.clone(),
                    script_sig: sig,
                    sequence: txin.sequence,
                })
                .collect(),
            vout: self.vout,
            authorization: Authorized,
        }
    }

    pub fn apply_signatures(
        self,
        #[cfg(feature = "transparent-inputs")] mtx: &TransactionData<tx::Unauthorized>,
        #[cfg(feature = "transparent-inputs")] txid_parts_cache: &TxDigests<Blake2bHash>,
    ) -> Bundle<Authorized> {
        #[cfg(feature = "transparent-inputs")]
        let script_sigs = {
            let sighashes = self.get_sighashes(mtx, txid_parts_cache);
            self
            .authorization
            .inputs
            .iter()
            .zip(sighashes)
            .map(|(info, sighash)| {
                let msg = secp256k1::Message::from_slice(sighash.as_ref()).expect("32 bytes");
                let sig = self.authorization.secp.sign_ecdsa(&msg, &info.sk.expect("Must have secret key"));

                // Signature has to have "SIGHASH_ALL" appended to it
                let mut sig_bytes: Vec<u8> = sig.serialize_der()[..].to_vec();
                sig_bytes.extend([SIGHASH_ALL]);

                // P2PKH scriptSig
                Script::default() << &sig_bytes[..] << &info.pubkey[..]
            })
        };

        #[cfg(not(feature = "transparent-inputs"))]
        let script_sigs = std::iter::empty::<Script>();

        transparent::Bundle {
            vin: self
                .vin
                .iter()
                .zip(script_sigs)
                .map(|(txin, sig)| TxIn {
                    prevout: txin.prevout.clone(),
                    script_sig: sig,
                    sequence: txin.sequence,
                })
                .collect(),
            vout: self.vout,
            authorization: Authorized,
        }
    }
}
