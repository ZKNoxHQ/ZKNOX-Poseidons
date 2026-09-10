// SPDX-License-Identifier: MIT
pragma solidity 0.7.6;

import "../src/PoseidonT3ForkAbi.sol";
import "../src/PoseidonT4ForkAbi.sol";
import "../src/PoseidonT3.sol";
import "../src/PoseidonT4.sol";
import "./reference/RefPoseidonT3.sol";
import "./reference/RefPoseidonT4.sol";

/// I/O compatibility with partylikeits1983/poseidon-solidity on BN254, at the ABI level:
/// the `hash(uint256[n])` variants of the generated runtimes answer to the fork's own selectors
/// with the fork's own calldata layout, and return the same digest as the fork's library for
/// every input, reduced or not.
interface IForkT3 { function hash(uint256[2] memory) external pure returns (uint256); }
interface IForkT4 { function hash(uint256[3] memory) external pure returns (uint256); }

abstract contract ForkAbiDeployer {
    uint256 internal constant P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function deploy(bytes memory creationCode) internal returns (address deployed) {
        assembly { deployed := create(0, add(creationCode, 0x20), mload(creationCode)) }
        require(deployed != address(0), "deployment failed");
    }
}

contract PoseidonT3ForkAbiTest is ForkAbiDeployer {
    IForkT3 private ours;      // generated runtime, selector hash(uint256[2]) = 0x561558fe
    IForkT3 private fork;      // partylikeits1983/poseidon-solidity PoseidonT3 (Yul, solc 0.7.6)
    IPoseidonT3 private shieldedAbi;

    function setUp() public {
        ours = IForkT3(deploy(type(PoseidonT3ForkAbi).creationCode));
        fork = IForkT3(deploy(type(RefPoseidonT3).creationCode));
        shieldedAbi = IPoseidonT3(deploy(type(PoseidonT3).creationCode));
    }

    function testSelectorIsTheForksOne() public pure {
        require(IForkT3.hash.selector == 0x561558fe, "selector");
        require(IPoseidonT3.poseidon.selector == 0x299e5660, "shielded selector");
    }

    function testSameOutputsAsFork() public view {
        uint256[2][6] memory v = [
            [uint256(1), uint256(2)], [uint256(0), uint256(0)], [P - 1, P - 1],
            [P, P + 1], [type(uint256).max, type(uint256).max], [uint256(2) ** 255, uint256(7)]
        ];
        for (uint256 i = 0; i < v.length; i++) {
            require(ours.hash(v[i]) == fork.hash(v[i]), "digest differs from poseidon-solidity");
        }
        require(ours.hash(v[0]) == 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a, "circomlib vector");
    }

    function testFuzzSameOutputsAsFork(uint256 a, uint256 b) public view {
        uint256[2] memory x = [a, b];
        uint256 h = ours.hash(x);
        require(h == fork.hash(x), "digest differs from poseidon-solidity");
        require(h == uint256(shieldedAbi.poseidon([bytes32(a), bytes32(b)])), "shielded-ABI variant differs");
        require(h < P, "output not canonical");
    }

    function testForkAbiVariantRejectsShieldedSelector() public view {
        (bool ok,) = address(ours).staticcall(abi.encodeWithSelector(IPoseidonT3.poseidon.selector, uint256(1), uint256(2)));
        require(!ok, "poseidon(bytes32[2]) accepted by the hash(uint256[2]) build");
        (ok,) = address(ours).staticcall(abi.encodeWithSelector(IForkT3.hash.selector, uint256(1)));
        require(!ok, "short calldata accepted");
    }
}

contract PoseidonT4ForkAbiTest is ForkAbiDeployer {
    IForkT4 private ours;
    IForkT4 private fork;

    function setUp() public {
        ours = IForkT4(deploy(type(PoseidonT4ForkAbi).creationCode));
        fork = IForkT4(deploy(type(RefPoseidonT4).creationCode));
    }

    function testSelectorIsTheForksOne() public pure {
        require(IForkT4.hash.selector == 0x20cf0a37, "selector");
    }

    function testFuzzSameOutputsAsFork(uint256 a, uint256 b, uint256 c) public view {
        uint256[3] memory x = [a, b, c];
        require(ours.hash(x) == fork.hash(x), "digest differs from poseidon-solidity");
    }

    function testLazyReductionRegressionVectorFromFork() public view {
        uint256[3] memory x = [
            uint256(0xbf53906633b58a54668b0db562b2427c6a0d56a8687b1f4c733a1f186163afdb),
            uint256(0x331aaad253eb40ed161b42b7844d80c3ad4ff18eacf4a9fa3929f90740ae52a8),
            uint256(0x7b10ea4b4f5960df623ddd0d017a90d422b5d6289a2bc1768cd44a90619110e4)
        ];
        require(ours.hash(x) == 0x1be4341850d3eb335d0198da5416f28073bf86001cf52ca2c43e062084d69cd0, "fork regression vector");
    }
}
