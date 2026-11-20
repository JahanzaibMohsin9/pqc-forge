// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Test double for the pqcKeyStatus precompile (0x…0a02): an in-test key registry.
/// @dev Tests register keys with `setKey`. Unregistered accounts return (false, 0, "", false).
contract PqcKeyStatusMock {
    struct Entry {
        bool registered;
        uint8 algorithmId;
        bytes pubkey;
        bool possessionProven;
    }

    mapping(address => Entry) private entries;

    function setKey(address account, bytes calldata pubkey, bool possessionProven) external {
        entries[account] = Entry(true, 1, pubkey, possessionProven); // 1 = ML-DSA-87
    }

    function clearKey(address account) external {
        delete entries[account];
    }

    function pqcKeyStatus(address account) external view returns (bool, uint8, bytes memory, bool) {
        Entry storage e = entries[account];
        return (e.registered, e.algorithmId, e.pubkey, e.possessionProven);
    }
}
