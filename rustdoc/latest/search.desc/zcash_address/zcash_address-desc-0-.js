searchState.loadedDescShard("zcash_address", 0, "<em>Parser for all defined Zcash address types.</em>\nAn error encountered while converting a parsed <code>ZcashAddress</code>…\nConversion errors for the user type (e.g. failing to parse …\nConversion errors for the user type (e.g. failing to parse …\nThe address is for the wrong network.\nThe string is an invalid encoding.\nZcash Mainnet.\nThe string is not a Zcash address.\nAn error while attempting to parse a string as a Zcash …\nPrivate integration / regression testing, used in <code>zcashd</code>.\nZcash Testnet.\nA helper trait for converting another type into a …\nA helper trait for converting a <code>ZcashAddress</code> into another …\nA helper trait for converting a <code>ZcashAddress</code> into a …\nErrors specific to unified addresses.\nThe address type is not supported by the target type.\nAn error indicating that an address type is not supported …\nA conversion error returned by the target type.\nA Zcash address.\nReturns whether this address has the ability to receive …\nReturns whether this address can receive a memo.\nConverts this address into another type.\nConverts this address into another type, if it matches the …\nEncodes this Zcash address in its canonical string …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nAttempts to parse the given string as a Zcash address.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns whether or not this address contains or …\nAttempts to parse the given string as a Zcash address.\nImplementation of ZIP 316 Unified Addresses and Viewing …\nExport test vectors for reuse by implementers of address …\nCreate an arbitrary, structurally-valid <code>ZcashAddress</code> value.\nA Unified Address.\nThe bech32m checksum algorithm, defined in BIP-350, …\nThe unified container contains both P2PKH and P2SH items.\nTrait for Unified containers, that exposes the items …\nThe unified container contains a duplicated typecode.\nTrait providing common encoding and decoding logic for …\nThe set of known FVKs for Unified FVKs.\nThe string is an invalid encoding.\nThe items in the unified container are not in typecode …\nThe parsed typecode exceeds the maximum allowed …\nThe type of item in this unified container.\nThe set of known IVKs for Unified IVKs.\nThe string is not Bech32m encoded, and so cannot be a …\nThe unified container only contains transparent items.\nThe raw encoding of an Orchard Full Viewing Key.\nThe raw encoding of an Orchard Incoming Viewing Key.\nAn Orchard raw address, FVK, or IVK encoding as specified …\nA pruned version of the extended public key for the BIP 44 …\nA pruned version of the extended public key for the BIP 44 …\nA transparent P2PKH address, FVK, or IVK encoding as …\nA transparent P2SH address.\nAn error while attempting to parse a string as a Zcash …\nThe set of known Receivers for Unified Addresses.\nData contained within the Sapling component of a Unified …\nData contained within the Sapling component of a Unified …\nA Sapling raw address, FVK, or IVK encoding as specified …\nThe known Receiver and Viewing Key types.\nA Unified Full Viewing Key.\nA Unified Incoming Viewing Key.\nAn unknown or experimental typecode.\nThe Bech32m string has an unrecognized human-readable …\nReturns whether this address can receive a memo.\nReturns whether this address contains the given receiver.\nDecodes a unified container from its string …\nDecodes a unified container from its string …\nEncodes the contents of the unified container to its …\nEncodes the contents of the unified container to its …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns whether this address has the ability to receive …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns the items contained within this container, sorted …\nReturns the items contained within this container, sorted …\nReturns the items in the order they were parsed from the …\nReturns the FVKs contained within this UFVK, in the order …\nReturns the IVKs contained within this UIVK, in the order …\nConstructs a value of a unified container type from a …\nConstructs a value of a unified container type from a …")