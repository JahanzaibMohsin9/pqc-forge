// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {PQC_VERIFY, PQC_KEY_STATUS} from "./IQorePQC.sol";
import {PqcVerifyMock} from "./PqcVerifyMock.sol";
import {PqcKeyStatusMock} from "./PqcKeyStatusMock.sol";

/// @notice Inherit in Foundry tests: installs QoreChain PQC precompile mocks and produces REAL ML-DSA-87
///         keys and signatures (deterministic, FIPS-204) through vm.ffi.
/// @dev The ffi script lives at `lib/pqc-forge/ffi/mldsa.mjs` when pqc-forge is a dependency. Override
///      `pqcForgeFfiPath()` or set env PQC_FORGE_FFI to change it. Run `npm ci` in pqc-forge once.
abstract contract PqcForge {
    Vm private constant _vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    struct PqcKey {
        bytes publicKey;
        bytes secretKey;
    }

    function pqcForgeFfiPath() internal view virtual returns (string memory) {
        return _vm.envOr("PQC_FORGE_FFI", string("lib/pqc-forge/ffi/mldsa.mjs"));
    }

    /// Etch the pqcVerify (0x…0a01) and pqcKeyStatus (0x…0a02) mocks.
    function installPqc() internal {
        _vm.etch(PQC_VERIFY, address(new PqcVerifyMock()).code);
        PqcVerifyMock(PQC_VERIFY).pqcForgeConfigure(pqcForgeFfiPath());
        _vm.etch(PQC_KEY_STATUS, address(new PqcKeyStatusMock()).code);
    }

    /// Simulate a network where the precompiles are inactive (e.g. mainnet today): calls succeed with empty data.
    function deactivatePqc() internal {
        _vm.etch(PQC_VERIFY, "");
        _vm.etch(PQC_KEY_STATUS, "");
    }

    /// Deterministic ML-DSA-87 keypair from a 32-byte seed.
    function pqcKeygen(bytes32 seed) internal returns (PqcKey memory k) {
        string[] memory cmd = new string[](4);
        cmd[0] = "node";
        cmd[1] = pqcForgeFfiPath();
        cmd[2] = "keygen";
        cmd[3] = _vm.toString(abi.encodePacked(seed));
        (k.publicKey, k.secretKey) = abi.decode(_vm.ffi(cmd), (bytes, bytes));
    }

    /// Pure ML-DSA-87 signature (empty context, no prehash), exactly what the precompile verifies.
    function pqcSign(PqcKey memory k, bytes memory message) internal returns (bytes memory sig) {
        string[] memory cmd = new string[](5);
        cmd[0] = "node";
        cmd[1] = pqcForgeFfiPath();
        cmd[2] = "sign";
        cmd[3] = _vm.toString(k.secretKey);
        cmd[4] = _vm.toString(message);
        sig = abi.decode(_vm.ffi(cmd), (bytes));
    }

    /// Sign QoreSign message-signing-v1 bytes ("qorechain-msg-v1|qorechain-diana|" + data), as QoreX signArbitrary does.
    function pqcSignMessage(PqcKey memory k, bytes memory data) internal returns (bytes memory) {
        return pqcSign(k, bytes.concat("qorechain-msg-v1|qorechain-diana|", data));
    }

    /// Register `pubkey` for `account` in the pqcKeyStatus mock.
    function pqcRegister(address account, bytes memory pubkey, bool possessionProven) internal {
        PqcKeyStatusMock(PQC_KEY_STATUS).setKey(account, pubkey, possessionProven);
    }

    /// Register `pubkey` for `account` under an explicit algorithm id.
    function pqcRegisterWithAlgorithm(address account, bytes memory pubkey, uint8 algorithmId, bool possessionProven) internal {
        PqcKeyStatusMock(PQC_KEY_STATUS).setKeyWithAlgorithm(account, pubkey, algorithmId, possessionProven);
    }

    /// Generate, register (with possession proven) and return a key for `account`.
    function pqcRegisterNew(address account, bytes32 seed) internal returns (PqcKey memory k) {
        k = pqcKeygen(seed);
        pqcRegister(account, k.publicKey, true);
    }
}
