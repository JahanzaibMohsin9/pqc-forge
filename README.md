# pqc-forge

**Foundry test kit for QoreChain's post-quantum precompiles, with real ML-DSA-87 instead of fake mocks.**

Most QoreChain projects test `pqcVerify` (`0x…0a01`) against a keccak stand-in that accepts any "signature" the test author chooses. pqc-forge gives your Foundry tests the real thing:

- **Real FIPS-204 ML-DSA-87.** Keys and signatures come from `@qorechain/pqc` through `vm.ffi`. The mock verifies them for real, so a tampered byte fails just as it does on chain.
- **Live-chain behaviour, not just the documented behaviour.** The mock reproduces what the **live testnet** does (measured 2026-11-20). Three of these differ from the docs:

| Input | Docs | Live chain | pqc-forge |
|---|---|---|---|
| Unknown selector | ignored | **reverts** (`unknown method selector`) | reverts |
| Non-canonical ABI | `false` | **reverts** (`head out of bounds`) | reverts |
| Valid signature over an **empty message** | (FIPS-204: valid) | **`false`** | `false` |
| Wrong key or signature size | `false` | `false` | `false` |
| Inactive network (mainnet today) | succeeds with empty return data | – | `deactivatePqc()` |

- **The official vectors pass.** The five FIPS-204 known-answer vectors from `qorechain-pqc` reproduce exactly: key generation, deterministic signing and verification.
- **`PQSig.sol`, a fail-closed verification library** for production contracts:
  - It requires exactly 32 bytes back, so an inactive precompile can never read as "valid".
  - It reverts when the call runs out of gas.
  - It requires `possessionProven` and algorithm 1, because a copied public key passes `registered`.
  - It verifies **QoreSign message-signing-v1** bytes (`"qorechain-msg-v1|" + chainId + "|" + data`), exactly what QoreX `signArbitrary` signs.
- **A live parity check:** `node ffi/live-parity.mjs` compares the mock's expectations with the real testnet precompile using `eth_call`. It is read-only and needs no funds.

## Install
```sh
forge install JahanzaibMohsin9/pqc-forge
(cd lib/pqc-forge && npm ci)
```
In `foundry.toml`:
```toml
ffi = true
remappings = ["@pqc-forge/=lib/pqc-forge/src/"]
```

## Use
```solidity
import {Test} from "forge-std/Test.sol";
import {PqcForge} from "@pqc-forge/PqcForge.sol";
import {PQSig} from "@pqc-forge/PQSig.sol";

contract MyTest is Test, PqcForge {
    function setUp() public {
        vm.chainId(9800);          // qorechain-diana
        installPqc();              // etch 0x…0a01 and 0x…0a02
    }

    function test_realSignature() public {
        address alice = makeAddr("alice");
        PqcKey memory k = pqcRegisterNew(alice, keccak256("alice")); // registered, possession proven
        bytes memory sig = pqcSignMessage(k, "approve 100");          // QoreSign message-signing-v1
        // ... call your contract, which uses PQSig.verifyMessageBy(alice, "approve 100", sig)
    }
}
```
| Helper | What it does |
|---|---|
| `installPqc()` / `deactivatePqc()` | Install the mocks, or simulate a network without the precompiles. |
| `pqcKeygen(seed)` | A deterministic ML-DSA-87 keypair (2,592-byte public key). |
| `pqcSign(k, msg)` / `pqcSignMessage(k, data)` | A raw pure ML-DSA-87 signature, or one over the QoreSign message format. |
| `pqcRegister(addr, pk, proven)` / `pqcRegisterNew(addr, seed)` | Set the `pqcKeyStatus` answer for an address. |

Speed: about 90 ms per real verification through ffi (Node start-up dominates).

## Used by
- [PQ Permit](https://github.com/JahanzaibMohsin9/pq-permit): gasless token approvals signed with ML-DSA-87.
- [Tollgate](https://github.com/JahanzaibMohsin9/tollgate): pay-per-call payment channels for AI agents.

## Develop
```sh
npm ci && forge test        # 19 tests, including the official FIPS-204 vectors
node ffi/live-parity.mjs    # compare with the live testnet precompile
```

## Credits
- `@qorechain/pqc` (Apache-2.0) does the ML-DSA-87 work.
- `test/vectors/ml-dsa-87.json` is copied from qorechain/qorechain-pqc (Apache-2.0).
- Built for **Build Before Q-Day** (QoreChain).

MIT licence.
