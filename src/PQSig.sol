// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPqcVerify, IPqcKeyStatus, PQC_VERIFY, PQC_KEY_STATUS} from "./IQorePQC.sol";

/// @title PQSig
/// @notice Fail-closed helpers around QoreChain's ML-DSA-87 precompiles.
/// @dev Safety rules, each one learned from the live chain or the docs:
///  - A precompile that is inactive (e.g. mainnet today) returns success with EMPTY return data.
///    A naive `abi.decode` would revert by accident, and a hand-rolled check might read it as "true".
///    We require exactly 32 bytes back, or we revert.
///  - If the call runs out of gas the call fails but the caller carries on, so we revert in that case.
///  - A registered key is not enough: a copied public key passes `registered`.
///    We require `possessionProven` and algorithmId 1 (ML-DSA-87).
///  - Messages use the QoreSign message-signing-v1 domain:
///    "qorechain-msg-v1|" + cosmosChainId + "|" + data
///    so the bytes are exactly what QoreX `signArbitrary` signs, and can't be replayed as a tx.
library PQSig {
    uint8 internal constant ALG_MLDSA87 = 1;

    error PqcPrecompileUnavailable(address precompile);
    error PqcKeyNotRegistered(address account);
    error PqcPossessionNotProven(address account);
    error PqcUnsupportedAlgorithm(address account, uint8 algorithmId);
    error UnknownChain(uint256 chainId);

    /// @notice The ML-DSA-87 public key registered on chain for `account`, with possession proven.
    function registeredKey(address account) internal view returns (bytes memory pubkey) {
        (bool ok, bytes memory ret) =
            PQC_KEY_STATUS.staticcall(abi.encodeCall(IPqcKeyStatus.pqcKeyStatus, (account)));
        if (!ok || ret.length < 128) revert PqcPrecompileUnavailable(PQC_KEY_STATUS);
        bool registered;
        uint8 alg;
        bool proven;
        (registered, alg, pubkey, proven) = abi.decode(ret, (bool, uint8, bytes, bool));
        if (!registered) revert PqcKeyNotRegistered(account);
        if (alg != ALG_MLDSA87) revert PqcUnsupportedAlgorithm(account, alg);
        if (!proven) revert PqcPossessionNotProven(account);
    }

    /// @notice Raw ML-DSA-87 verification. Reverts if the precompile is unavailable; never returns a false positive.
    function verify(bytes memory pubkey, bytes memory signature, bytes memory message) internal view returns (bool) {
        (bool ok, bytes memory ret) =
            PQC_VERIFY.staticcall(abi.encodeCall(IPqcVerify.pqcVerify, (pubkey, signature, message)));
        if (!ok || ret.length != 32) revert PqcPrecompileUnavailable(PQC_VERIFY);
        return abi.decode(ret, (bool));
    }

    /// @notice Verify `signature` by `account`'s registered key over QoreSign message bytes for `data`.
    function verifyMessageBy(address account, bytes memory data, bytes memory signature) internal view returns (bool) {
        return verify(registeredKey(account), signature, messageBytes(data));
    }

    /// @notice QoreSign message-signing-v1 bytes: "qorechain-msg-v1|" + chain_id + "|" + data.
    function messageBytes(bytes memory data) internal view returns (bytes memory) {
        return bytes.concat("qorechain-msg-v1|", bytes(cosmosChainId()), "|", data);
    }

    /// @notice Cosmos chain id for the current EVM chain id.
    function cosmosChainId() internal view returns (string memory) {
        if (block.chainid == 9800) return "qorechain-diana";
        if (block.chainid == 9801) return "qorechain-vladi";
        revert UnknownChain(block.chainid);
    }
}
