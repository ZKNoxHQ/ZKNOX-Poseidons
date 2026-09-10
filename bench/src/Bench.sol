// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

/// Measures a single Poseidon call, cold then warm, from a raw STATICCALL.
contract SingleHash {
    function run(address lib, bytes calldata cd) external view returns (uint256 cold, uint256 warm, bytes32 out) {
        bool ok;
        bytes memory r;
        uint256 g = gasleft();
        (ok, r) = lib.staticcall(cd);
        cold = g - gasleft();
        require(ok, "cold fail");
        g = gasleft();
        (ok, r) = lib.staticcall(cd);
        warm = g - gasleft();
        require(ok, "warm fail");
        out = abi.decode(r, (bytes32));
    }
}
