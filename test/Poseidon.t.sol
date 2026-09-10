// SPDX-License-Identifier: MIT
pragma solidity 0.7.6;

import "../src/PoseidonT3.sol";
import "../src/PoseidonT4.sol";
import "./reference/RefPoseidonT3.sol";
import "./reference/RefPoseidonT4.sol";

interface IRefT3 {
    function hash(uint256[2] memory inputs) external pure returns (uint256);
}

interface IRefT4 {
    function hash(uint256[3] memory inputs) external pure returns (uint256);
}

abstract contract Deployer {
    uint256 internal constant FIELD_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant EIP170_CODE_SIZE_LIMIT = 24576;

    function deploy(bytes memory creationCode) internal returns (address deployed) {
        assembly {
            deployed := create(0, add(creationCode, 0x20), mload(creationCode))
        }
        require(deployed != address(0), "deployment failed");
    }

    function codeSize(address account) internal view returns (uint256 size) {
        assembly {
            size := extcodesize(account)
        }
    }

    function log(string memory label, uint256 a, uint256 b) internal view {
        // forge console (no forge-std dependency)
        (bool ok,) = address(0x000000000000000000636F6e736F6c652e6c6f67).staticcall(
            abi.encodeWithSignature("log(string,uint256,uint256)", label, a, b)
        );
        ok;
    }

    /// Raw call so that the measured gas is the callee's cost plus the STATICCALL itself.
    function rawHash(address target, bytes memory data) internal view returns (uint256 out, uint256 gasUsed) {
        bool ok;
        assembly {
            let g := gas()
            ok := staticcall(gas(), target, add(data, 0x20), mload(data), 0, 0x20)
            gasUsed := sub(g, gas())
            out := mload(0)
        }
        require(ok, "hash call failed");
    }
}

contract PoseidonT3Test is Deployer {
    IPoseidonT3 private poseidon;
    IRefT3 private ref;

    function setUp() public {
        poseidon = IPoseidonT3(deploy(type(PoseidonT3).creationCode));
        ref = IRefT3(deploy(type(RefPoseidonT3).creationCode));
    }

    /// the shielded pool's stub ABI: poseidon(bytes32[2]) returns (bytes32)
    function h(uint256[2] memory x) internal view returns (uint256) {
        return uint256(poseidon.poseidon([bytes32(x[0]), bytes32(x[1])]));
    }

    function testCircomlibVector() public view {
        uint256[2] memory inputs = [uint256(1), uint256(2)];
        require(
            h(inputs) == 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a,
            "T3 vector mismatch"
        );
    }

    function testEdgeVectors() public view {
        uint256 p = FIELD_MODULUS;
        uint256[2] memory a = [uint256(0), uint256(0)];
        uint256[2] memory b = [p - 1, p - 1];
        uint256[2] memory c = [type(uint256).max, p];
        require(h(a) == ref.hash(a), "zero");
        require(h(b) == ref.hash(b), "p-1");
        require(h(c) == ref.hash(c), "unreduced");
    }

    function testFuzzMatchesReference(uint256 left, uint256 right) public view {
        uint256[2] memory inputs = [left, right];
        require(h(inputs) == ref.hash(inputs), "T3 differs from poseidon-solidity");
    }

    function testFuzzReducesInputs(uint256 left, uint256 right) public view {
        uint256[2] memory inputs = [left, right];
        uint256[2] memory reduced = [left % FIELD_MODULUS, right % FIELD_MODULUS];
        require(h(inputs) == h(reduced), "T3 reduction mismatch");
    }

    function testRejectsBadSelectorAndShortCalldata() public view {
        (bool ok,) = address(poseidon).staticcall(abi.encodeWithSelector(0xdeadbeef, uint256(1), uint256(2)));
        require(!ok, "bad selector accepted");
        // single-selector runtime: poseidon-solidity's hash(uint256[2]) is not served
        (ok,) = address(poseidon).staticcall(abi.encodeWithSelector(0x561558fe, uint256(1), uint256(2)));
        require(!ok, "hash(uint256[2]) accepted");
        (ok,) = address(poseidon).staticcall(abi.encodeWithSelector(IPoseidonT3.poseidon.selector, uint256(1)));
        require(!ok, "short calldata accepted");
    }

    function testGasBelowReference() public view {
        bytes memory data = abi.encodeWithSelector(IPoseidonT3.poseidon.selector, uint256(1), uint256(2));
        bytes memory dataRef = abi.encodeWithSelector(IRefT3.hash.selector, uint256(1), uint256(2));
        // warm both accounts first
        rawHash(address(poseidon), data);
        rawHash(address(ref), dataRef);
        (uint256 a, uint256 gNew) = rawHash(address(poseidon), data);
        (uint256 b, uint256 gRef) = rawHash(address(ref), dataRef);
        require(a == b, "outputs differ");
        require(gNew < gRef, "not cheaper than the ref");
        log("T3 warm STATICCALL gas (new, poseidon-solidity)", gNew, gRef);
        require(gNew <= 10149 + 800, "T3 gas regression (callee 10150 + STATICCALL overhead)");
    }

    function testRuntimeBelowEip170Limit() public view {
        require(codeSize(address(poseidon)) <= EIP170_CODE_SIZE_LIMIT, "T3 exceeds EIP-170");
    }
}

contract PoseidonT4Test is Deployer {
    IPoseidonT4 private poseidon;
    IRefT4 private ref;

    function setUp() public {
        poseidon = IPoseidonT4(deploy(type(PoseidonT4).creationCode));
        ref = IRefT4(deploy(type(RefPoseidonT4).creationCode));
    }

    function h(uint256[3] memory x) internal view returns (uint256) {
        return uint256(poseidon.poseidon([bytes32(x[0]), bytes32(x[1]), bytes32(x[2])]));
    }

    function testCircomlibVector() public view {
        uint256[3] memory inputs = [uint256(1), uint256(2), uint256(3)];
        require(
            h(inputs) == 0x0e7732d89e6939c0ff03d5e58dab6302f3230e269dc5b968f725df34ab36d732,
            "T4 vector mismatch"
        );
    }

    function testLazyReductionOverflowRegression() public view {
        uint256[3] memory inputs = [
            uint256(0xbf53906633b58a54668b0db562b2427c6a0d56a8687b1f4c733a1f186163afdb),
            uint256(0x331aaad253eb40ed161b42b7844d80c3ad4ff18eacf4a9fa3929f90740ae52a8),
            uint256(0x7b10ea4b4f5960df623ddd0d017a90d422b5d6289a2bc1768cd44a90619110e4)
        ];
        require(
            h(inputs) == 0x1be4341850d3eb335d0198da5416f28073bf86001cf52ca2c43e062084d69cd0,
            "T4 lazy-reduction regression"
        );
    }

    function testFuzzMatchesReference(uint256 a, uint256 b, uint256 c) public view {
        uint256[3] memory inputs = [a, b, c];
        require(h(inputs) == ref.hash(inputs), "T4 differs from poseidon-solidity");
    }

    function testFuzzReducesInputs(uint256 a, uint256 b, uint256 c) public view {
        uint256[3] memory inputs = [a, b, c];
        uint256[3] memory reduced = [a % FIELD_MODULUS, b % FIELD_MODULUS, c % FIELD_MODULUS];
        require(h(inputs) == h(reduced), "T4 reduction mismatch");
    }

    function testGasBelowReference() public view {
        bytes memory data = abi.encodeWithSelector(IPoseidonT4.poseidon.selector, uint256(1), uint256(2), uint256(3));
        bytes memory dataRef = abi.encodeWithSelector(IRefT4.hash.selector, uint256(1), uint256(2), uint256(3));
        rawHash(address(poseidon), data);
        rawHash(address(ref), dataRef);
        (uint256 a, uint256 gNew) = rawHash(address(poseidon), data);
        (uint256 b, uint256 gRef) = rawHash(address(ref), dataRef);
        require(a == b, "outputs differ");
        require(gNew < gRef, "not cheaper than the ref");
        log("T4 warm STATICCALL gas (new, poseidon-solidity)", gNew, gRef);
        require(gNew <= 14051 + 800, "T4 gas regression (callee 14049 + STATICCALL overhead)");
    }

    function testRuntimeBelowEip170Limit() public view {
        require(codeSize(address(poseidon)) <= EIP170_CODE_SIZE_LIMIT, "T4 exceeds EIP-170");
    }
}
