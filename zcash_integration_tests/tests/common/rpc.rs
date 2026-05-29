//! JSON-RPC client for communicating with a zebra/zcashd node.

use serde::de::DeserializeOwned;
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};

/// A blocking JSON-RPC client for zebra/zcashd.
pub struct RpcClient {
    url: String,
    nonce: AtomicU64,
}

impl RpcClient {
    /// Creates a new client using the `ZEBRA_RPC_URL` environment variable,
    /// defaulting to `http://127.0.0.1:8232`.
    pub fn new() -> Self {
        let url = std::env::var("ZEBRA_RPC_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8232".to_string());
        RpcClient {
            url,
            nonce: AtomicU64::new(1),
        }
    }

    /// Makes a JSON-RPC call and deserializes the result.
    pub fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Vec<Value>,
    ) -> Result<T, String> {
        let id = self.nonce.fetch_add(1, Ordering::SeqCst);
        let body = serde_json::json!({
            "jsonrpc": "1.0",
            "id": id.to_string(),
            "method": method,
            "params": params,
        });

        let resp: Value = ureq::post(&self.url)
            .set("Content-Type", "application/json")
            .send_string(&body.to_string())
            .map_err(|e| format!("RPC HTTP error for {method}: {e}"))?
            .into_json()
            .map_err(|e| format!("RPC JSON parse error for {method}: {e}"))?;

        if let Some(err) = resp.get("error").and_then(|e| e.as_object()) {
            return Err(format!(
                "RPC error for {method}: code={:?}, message={:?}",
                err.get("code"),
                err.get("message")
            ));
        }

        let result = resp
            .get("result")
            .ok_or_else(|| format!("RPC response missing 'result' for {method}"))?;

        serde_json::from_value(result.clone())
            .map_err(|e| format!("RPC deserialize error for {method}: {e}"))
    }

    // ── Common RPC methods ──

    /// Returns blockchain info.
    pub fn get_blockchain_info(&self) -> Result<Value, String> {
        self.call("getblockchaininfo", vec![])
    }

    /// Mines `nblocks` to the given address (zcashd).
    pub fn generate_to_address(
        &self,
        nblocks: u32,
        address: &str,
    ) -> Result<Vec<String>, String> {
        self.call(
            "generatetoaddress",
            vec![Value::from(nblocks), Value::String(address.to_string())],
        )
    }

    /// Mines `nblocks` to the configured miner address (zebra).
    pub fn generate(&self, nblocks: u32) -> Result<Vec<String>, String> {
        self.call("generate", vec![Value::from(nblocks)])
    }

    /// Lists unspent transparent outputs for the given addresses (zcashd).
    pub fn list_unspent(
        &self,
        addresses: &[String],
    ) -> Result<Vec<serde_json::Value>, String> {
        self.call(
            "listunspent",
            vec![Value::from(0), Value::from(9999999), Value::from(addresses.to_vec())],
        )
    }

    /// Lists unspent transparent outputs for the given address (zebra).
    pub fn get_address_utxos(
        &self,
        address: &str,
    ) -> Result<Vec<serde_json::Value>, String> {
        self.call(
            "getaddressutxos",
            vec![Value::String(address.to_string())],
        )
    }

    /// Submits a raw transaction hex and returns the txid.
    pub fn send_raw_transaction(&self, hex: &str) -> Result<String, String> {
        self.call("sendrawtransaction", vec![Value::String(hex.to_string())])
    }

    /// Returns a transaction by txid.
    pub fn get_transaction(&self, txid: &str) -> Result<Value, String> {
        self.call(
            "gettransaction",
            vec![Value::String(txid.to_string())],
        )
    }

    /// Returns the raw transaction hex for a txid.
    pub fn get_raw_transaction(&self, txid: &str) -> Result<String, String> {
        self.call(
            "getrawtransaction",
            vec![Value::String(txid.to_string())],
        )
    }

    /// Returns block data by hash (verbosity 2 = full tx data).
    pub fn get_block(&self, block_hash: &str) -> Result<Value, String> {
        self.call(
            "getblock",
            vec![Value::String(block_hash.to_string()), Value::from(2)],
        )
    }

    /// Returns the best block hash.
    pub fn get_best_block_hash(&self) -> Result<String, String> {
        self.call("getbestblockhash", vec![])
    }

    /// Polls `getblock` until the txid is found in a block.
    /// Returns the block hash once confirmed.
    pub fn wait_for_confirmation(&self, txid: &str) -> Result<String, String> {
        for _ in 0..120 {
            let block_hash = self.get_best_block_hash()?;
            let block: Value = self.get_block(&block_hash)?;
            if let Some(tx_ids) = block["tx"].as_array() {
                for tx in tx_ids {
                    if let Some(txid_str) = tx["txid"].as_str() {
                        if txid_str == txid {
                            return Ok(block_hash);
                        }
                    }
                    // Also check if tx is a hex string (zebra format)
                    if let Some(hex_str) = tx.as_str() {
                        if hex_str == txid {
                            return Ok(block_hash);
                        }
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        Err(format!("timed out waiting for confirmation of {txid}"))
    }
}
