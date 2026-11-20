// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {PqcForge} from "../src/PqcForge.sol";
import {PQSig} from "../src/PQSig.sol";
import {IPqcVerify, IPqcKeyStatus, PQC_VERIFY, PQC_KEY_STATUS} from "../src/IQorePQC.sol";

/// A consumer that calls the precompile from a `view` function (STATICCALL), like real dApps do.
contract ViewConsumer {
    function check(bytes calldata pk, bytes calldata sig, bytes calldata m) external view returns (bool) {
        return IPqcVerify(PQC_VERIFY).pqcVerify(pk, sig, m);
    }
}

/// Exposes the PQSig library to tests.
contract PQSigHarness {
    function verifyMessageBy(address a, bytes calldata data, bytes calldata sig) external view returns (bool) {
        return PQSig.verifyMessageBy(a, data, sig);
    }

    function registeredKey(address a) external view returns (bytes memory) {
        return PQSig.registeredKey(a);
    }
}

contract PqcForgeTest is Test, PqcForge {
    ViewConsumer consumer;
    PQSigHarness harness;
    PqcKey key;
    bytes message = "pqc-forge: approve 100 fUSD";

    // The kit's own repo keeps the ffi script at ./ffi (consumers use lib/pqc-forge/ffi).
    function pqcForgeFfiPath() internal view override returns (string memory) {
        return vm.envOr("PQC_FORGE_FFI", string("ffi/mldsa.mjs"));
    }

    function setUp() public {
        vm.chainId(9800);
        installPqc();
        consumer = new ViewConsumer();
        harness = new PQSigHarness();
        key = pqcKeygen(bytes32(uint256(7)));
    }

    // ------------------------------------------------------------ FIPS-204 known-answer tests

    function test_kat_officialVectors() public {
        string memory json = vm.readFile("test/vectors/ml-dsa-87.json");
        for (uint256 i = 0; i < 5; i++) {
            string memory c = string.concat(".cases[", vm.toString(i), "]");
            bytes32 seed = vm.parseJsonBytes32(json, string.concat(c, ".seed"));
            bytes memory pk = vm.parseJsonBytes(json, string.concat(c, ".publicKey"));
            bytes memory m = vm.parseJsonBytes(json, string.concat(c, ".message"));
            bytes memory sig = vm.parseJsonBytes(json, string.concat(c, ".signature"));
            PqcKey memory k = pqcKeygen(seed);
            assertEq(keccak256(k.publicKey), keccak256(pk), "keygen != vector");
            assertEq(keccak256(pqcSign(k, m)), keccak256(sig), "deterministic sign != vector");
            assertTrue(consumer.check(pk, sig, m), "vector signature must verify");
        }
    }

    // ------------------------------------------------------------ precompile mock semantics (live-chain parity)

    function test_realSignatureVerifiesThroughStaticcall() public {
        bytes memory sig = pqcSign(key, message);
        assertEq(sig.length, 4627);
        assertTrue(consumer.check(key.publicKey, sig, message));
    }

    function test_tamperedMessageFails() public {
        bytes memory sig = pqcSign(key, message);
        assertFalse(consumer.check(key.publicKey, sig, bytes.concat(message, "!")));
    }

    function test_otherKeyFails() public {
        PqcKey memory other = pqcKeygen(bytes32(uint256(8)));
        assertFalse(consumer.check(key.publicKey, pqcSign(other, message), message));
    }

    function test_emptyMessageIsFalseLikeTheChain() public {
        bytes memory empty;
        assertFalse(consumer.check(key.publicKey, pqcSign(key, empty), empty));
    }

    function test_shortSignatureIsFalse() public {
        bytes memory sig = pqcSign(key, message);
        assembly { mstore(sig, sub(mload(sig), 1)) }
        assertFalse(consumer.check(key.publicKey, sig, message));
    }

    function test_unknownSelectorRevertsLikeTheChain() public view {
        (bool ok,) = PQC_VERIFY.staticcall(abi.encodeWithSelector(bytes4(0xdeadbeef), key.publicKey, "", ""));
        assertFalse(ok);
    }

    function test_nonCanonicalAbiRevertsLikeTheChain() public view {
        (bool ok,) = PQC_VERIFY.staticcall(abi.encodePacked(bytes4(0xf52bde0a), hex"0102"));
        assertFalse(ok);
    }

    function test_keyStatusRegistry() public {
        address alice = makeAddr("alice");
        (bool reg,,,) = IPqcKeyStatus(PQC_KEY_STATUS).pqcKeyStatus(alice);
        assertFalse(reg);
        pqcRegister(alice, key.publicKey, true);
        (bool reg2, uint8 alg, bytes memory pk, bool proven) = IPqcKeyStatus(PQC_KEY_STATUS).pqcKeyStatus(alice);
        assertTrue(reg2);
        assertEq(alg, 1);
        assertEq(keccak256(pk), keccak256(key.publicKey));
        assertTrue(proven);
    }

    // ------------------------------------------------------------ PQSig (fail-closed library)

    function test_pqsig_acceptsQoreSignMessage() public {
        address alice = makeAddr("alice");
        pqcRegister(alice, key.publicKey, true);
        assertTrue(harness.verifyMessageBy(alice, message, pqcSignMessage(key, message)));
    }

    function test_pqsig_rejectsRawSignatureWithoutDomain() public {
        address alice = makeAddr("alice");
        pqcRegister(alice, key.publicKey, true);
        assertFalse(harness.verifyMessageBy(alice, message, pqcSign(key, message)));
    }

    function test_pqsig_rejectsWrongChain() public {
        address alice = makeAddr("alice");
        pqcRegister(alice, key.publicKey, true);
        bytes memory sig = pqcSignMessage(key, message); // signed for qorechain-diana
        vm.chainId(9801);
        assertFalse(harness.verifyMessageBy(alice, message, sig));
    }

    function test_pqsig_requiresPossessionProof() public {
        address alice = makeAddr("alice");
        pqcRegister(alice, key.publicKey, false);
        vm.expectRevert(abi.encodeWithSelector(PQSig.PqcPossessionNotProven.selector, alice));
        harness.registeredKey(alice);
    }

    function test_pqsig_requiresRegistration() public {
        address bob = makeAddr("bob");
        vm.expectRevert(abi.encodeWithSelector(PQSig.PqcKeyNotRegistered.selector, bob));
        harness.registeredKey(bob);
    }

    function test_pqsig_failsClosedWhenPrecompilesInactive() public {
        address alice = makeAddr("alice");
        pqcRegister(alice, key.publicKey, true);
        bytes memory sig = pqcSignMessage(key, message);
        deactivatePqc();
        vm.expectRevert(abi.encodeWithSelector(PQSig.PqcPrecompileUnavailable.selector, PQC_KEY_STATUS));
        harness.verifyMessageBy(alice, message, sig);
    }

    function test_pqsig_unknownChainReverts() public {
        address alice = makeAddr("alice");
        pqcRegister(alice, key.publicKey, true);
        bytes memory sig = pqcSignMessage(key, message);
        vm.chainId(1);
        vm.expectRevert(abi.encodeWithSelector(PQSig.UnknownChain.selector, 1));
        harness.verifyMessageBy(alice, message, sig);
    }

    function test_latency() public {
        bytes memory sig = pqcSign(key, message);
        uint256 t0 = vm.unixTime();
        for (uint256 i = 0; i < 5; i++) assertTrue(consumer.check(key.publicKey, sig, message));
        console.log("avg ms per real ML-DSA-87 verify via ffi:", (vm.unixTime() - t0) / 5);
    }
}
