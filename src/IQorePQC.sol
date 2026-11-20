// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// QoreChain post-quantum EVM precompiles (active on testnet qorechain-diana).
// Source: qorechain-core docs/EVM_PRECOMPILES.md. Behaviour notes that differ from the docs
//      were measured against the live testnet and are encoded in the pqc-forge mocks.
address constant PQC_VERIFY = 0x0000000000000000000000000000000000000a01;
address constant PQC_KEY_STATUS = 0x0000000000000000000000000000000000000a02;

uint256 constant MLDSA87_PUBKEY_LEN = 2592;
uint256 constant MLDSA87_SIG_LEN = 4627;

interface IPqcVerify {
    /// Pure ML-DSA-87 (FIPS-204, empty context, no prehash). Returns false on a bad signature or wrong sizes.
    function pqcVerify(bytes calldata pubkey, bytes calldata signature, bytes calldata message)
        external
        view
        returns (bool);
}

interface IPqcKeyStatus {
    function pqcKeyStatus(address account)
        external
        view
        returns (bool registered, uint8 algorithmId, bytes memory pubkey, bool possessionProven);
}
