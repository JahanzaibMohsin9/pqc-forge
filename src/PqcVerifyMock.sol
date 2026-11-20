// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {MLDSA87_PUBKEY_LEN, MLDSA87_SIG_LEN} from "./IQorePQC.sol";

/// @notice Drop-in test double for QoreChain's pqcVerify precompile (0x…0a01) that performs REAL ML-DSA-87
///         verification (FIPS-204, via vm.ffi to the qorechain-pqc npm package). It mirrors behaviour
///         measured on the live testnet (2026-11-20):
///         - unknown selector            -> revert (the docs say the selector is ignored; the chain disagrees)
///         - non-canonical ABI input     -> revert
///         - wrong key / signature size  -> false
///         - empty message               -> false (FIPS-204 accepts it; the chain does not)
/// @dev Install with PqcForge.installPqc(). Requires `ffi = true`. Test-only deviation: the mock also answers
///      pqcForgeConfigure / pqcForgeFfiPath (configuration hooks) which the real precompile would reject.
contract PqcVerifyMock {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes4 private constant SELECTOR = 0xf52bde0a; // pqcVerify(bytes,bytes,bytes)

    /// Path of ffi/mldsa.mjs, set by PqcForge.installPqc (storage of the etched address).
    string public pqcForgeFfiPath;

    error UnknownSelector(bytes4 selector);

    /// Test-only configuration hook (never present on chain).
    function pqcForgeConfigure(string calldata ffiPath) external {
        pqcForgeFfiPath = ffiPath;
    }

    fallback(bytes calldata data) external returns (bytes memory) {
        if (data.length < 4 || bytes4(data[:4]) != SELECTOR) revert UnknownSelector(bytes4(data));
        (bytes memory pk, bytes memory sig, bytes memory message) = abi.decode(data[4:], (bytes, bytes, bytes));
        if (pk.length != MLDSA87_PUBKEY_LEN || sig.length != MLDSA87_SIG_LEN || message.length == 0) {
            return abi.encode(false);
        }
        string[] memory cmd = new string[](6);
        cmd[0] = "node";
        cmd[1] = pqcForgeFfiPath;
        cmd[2] = "verify";
        cmd[3] = vm.toString(pk);
        cmd[4] = vm.toString(sig);
        cmd[5] = vm.toString(message);
        return vm.ffi(cmd); // abi.encode(bool)
    }
}
