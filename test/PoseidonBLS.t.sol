// SPDX-License-Identifier: MIT
pragma solidity 0.7.6;

import "../src/PoseidonT3BLS12381.sol";
import "../src/PoseidonT4BLS12381.sol";
import "./reference/RefPoseidonT3BLS.sol";
import "./reference/RefPoseidonT4BLS.sol";

interface IRefBLS3 { function hash(uint256[2] memory) external pure returns (uint256); }
interface IRefBLS4 { function hash(uint256[3] memory) external pure returns (uint256); }

/// Poseidon over the BLS12-381 scalar field: hadeshash instances 255/3/8/57 and 255/4/8/56,
/// circomlib conventions.  Reference = the generated Yul (gen/poseidon_opt.py) compiled by solc,
/// itself checked against gen/poseidon_ref.py.
abstract contract DeployerBLS {
    uint256 internal constant R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    function deploy(bytes memory creationCode) internal returns (address deployed) {
        assembly { deployed := create(0, add(creationCode, 0x20), mload(creationCode)) }
        require(deployed != address(0), "deployment failed");
    }

    function codeSize(address a) internal view returns (uint256 s) { assembly { s := extcodesize(a) } }

    function log(string memory label, uint256 a, uint256 b) internal view {
        (bool ok,) = address(0x000000000000000000636F6e736F6c652e6c6f67).staticcall(
            abi.encodeWithSignature("log(string,uint256,uint256)", label, a, b));
        ok;
    }

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

contract PoseidonT3BLSTest is DeployerBLS {
    IPoseidonT3BLS12381 private poseidon;
    IRefBLS3 private ref;

    function setUp() public {
        poseidon = IPoseidonT3BLS12381(deploy(type(PoseidonT3BLS12381).creationCode));
        ref = IRefBLS3(deploy(type(RefPoseidonT3BLS).creationCode));
    }

    function h(uint256[2] memory x) internal view returns (uint256) {
        return uint256(poseidon.poseidon([bytes32(x[0]), bytes32(x[1])]));
    }

    function testReferenceVectors() public view {
        require(h([uint256(1), uint256(2)]) == 0x28ce19420fc246a05553ad1e8c98f5c9d67166be2c18e9e4cb4b4e317dd2a78a, "hash(1,2)");
        require(h([R - 1, R - 1]) == 0x1bbdb9eb04eeb93f5c409bc56b2b48c6ceaec3c18e8763d6ab4eca418c599ab, "hash(r-1,r-1)");
    }

    function testFuzzMatchesGeneratedYul(uint256 a, uint256 b) public view {
        uint256[2] memory x = [a, b];
        require(h(x) == ref.hash(x), "differs from the solc-compiled Yul");
    }

    function testFuzzReducesInputs(uint256 a, uint256 b) public view {
        require(h([a, b]) == h([a % R, b % R]), "reduction");
    }

    function testRejectsBadSelectorAndShortCalldata() public view {
        (bool ok,) = address(poseidon).staticcall(abi.encodeWithSelector(0xdeadbeef, uint256(1), uint256(2)));
        require(!ok, "bad selector accepted");
        (ok,) = address(poseidon).staticcall(abi.encodeWithSelector(IPoseidonT3BLS12381.poseidon.selector, uint256(1)));
        require(!ok, "short calldata accepted");
    }

    function testGasBelowSolc() public view {
        bytes memory d = abi.encodeWithSelector(IPoseidonT3BLS12381.poseidon.selector, uint256(1), uint256(2));
        bytes memory dRef = abi.encodeWithSelector(IRefBLS3.hash.selector, uint256(1), uint256(2));
        rawHash(address(poseidon), d); rawHash(address(ref), dRef);
        (uint256 a, uint256 gNew) = rawHash(address(poseidon), d);
        (uint256 b, uint256 gRef) = rawHash(address(ref), dRef);
        log("BLS T3 warm STATICCALL gas (new, solc Yul)", gNew, gRef);
        require(a == b && gNew < gRef, "gas");
        require(gNew <= 11368 + 800, "T3 BLS gas regression");
    }

    function testRuntimeBelowEip170Limit() public view { require(codeSize(address(poseidon)) <= 24576); }
}

contract PoseidonT4BLSTest is DeployerBLS {
    IPoseidonT4BLS12381 private poseidon;
    IRefBLS4 private ref;

    function setUp() public {
        poseidon = IPoseidonT4BLS12381(deploy(type(PoseidonT4BLS12381).creationCode));
        ref = IRefBLS4(deploy(type(RefPoseidonT4BLS).creationCode));
    }

    function h(uint256[3] memory x) internal view returns (uint256) {
        return uint256(poseidon.poseidon([bytes32(x[0]), bytes32(x[1]), bytes32(x[2])]));
    }

    function testReferenceVectors() public view {
        require(h([uint256(1), uint256(2), uint256(3)]) == 0x5ad8bcfa9754b5bc043cc74dea65ae15e3fdb0c2295970aaacfc116c802d9895, "hash(1,2,3)");
        require(h([R - 1, R - 1, R - 1]) == 0x298c7876a0e9299b611c7d84537e0c60fe1de51f71790109a570b80d0f380f3a, "hash(r-1,..)");
    }

    function testFuzzMatchesGeneratedYul(uint256 a, uint256 b, uint256 c) public view {
        uint256[3] memory x = [a, b, c];
        require(h(x) == ref.hash(x), "differs from the solc-compiled Yul");
    }

    function testFuzzReducesInputs(uint256 a, uint256 b, uint256 c) public view {
        require(h([a, b, c]) == h([a % R, b % R, c % R]), "reduction");
    }

    function testGasBelowSolc() public view {
        bytes memory d = abi.encodeWithSelector(IPoseidonT4BLS12381.poseidon.selector, uint256(1), uint256(2), uint256(3));
        bytes memory dRef = abi.encodeWithSelector(IRefBLS4.hash.selector, uint256(1), uint256(2), uint256(3));
        rawHash(address(poseidon), d); rawHash(address(ref), dRef);
        (uint256 a, uint256 gNew) = rawHash(address(poseidon), d);
        (uint256 b, uint256 gRef) = rawHash(address(ref), dRef);
        log("BLS T4 warm STATICCALL gas (new, solc Yul)", gNew, gRef);
        require(a == b && gNew < gRef, "gas");
        require(gNew <= 16008 + 800, "T4 BLS gas regression");
    }

    function testRuntimeBelowEip170Limit() public view { require(codeSize(address(poseidon)) <= 24576); }
}
