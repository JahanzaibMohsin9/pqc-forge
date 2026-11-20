# AI usage

Built with **Claude Code** (Anthropic) as a pair programmer. A human developer directed the work and reviewed it.

- **AI-drafted:** the mocks, the PQSig library, the ffi bridge and the tests.
- **Checked against reality, not assumed:**
  - Every behaviour the mock reproduces was measured against the live qorechain-diana precompile with `eth_call` (`ffi/live-parity.mjs`).
  - The ML-DSA path is checked against the official FIPS-204 vectors.
- **Found by testing, not from the docs:** the chain reverts on an unknown selector, reverts on non-canonical ABI input, and returns false for an empty message.
