// SPDX-License-Identifier: UNLICENSED
// Faithful copy of the shielded pool's contract repository contracts/logic/Commitments.sol with the
// PoseidonT3 library link replaced by a raw staticcall to a swappable address/selector.
pragma solidity ^0.8.12;

uint256 constant SNARK_SCALAR_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617;

contract CommitmentsBench {
  address public immutable POSEIDON;
  bytes4 public immutable SEL;

  uint256 internal constant TREE_DEPTH = 16;
  bytes32 public constant ZERO_VALUE = bytes32(uint256(keccak256("the shielded pool")) % SNARK_SCALAR_FIELD);

  uint256 public nextLeafIndex;
  bytes32 public merkleRoot;
  bytes32 private newTreeRoot;
  uint256 public treeNumber;
  bytes32[TREE_DEPTH] public zeros;
  bytes32[TREE_DEPTH] private filledSubTrees;
  mapping(uint256 => mapping(bytes32 => bool)) public rootHistory;

  constructor(address _poseidon, bytes4 _sel) {
    POSEIDON = _poseidon;
    SEL = _sel;
    bytes32 currentZero = ZERO_VALUE;
    for (uint256 i = 0; i < TREE_DEPTH; i += 1) {
      zeros[i] = currentZero;
      filledSubTrees[i] = currentZero;
      currentZero = hashLeftRight(currentZero, currentZero);
    }
    newTreeRoot = merkleRoot = currentZero;
    rootHistory[treeNumber][currentZero] = true;
  }

  function hashLeftRight(bytes32 _left, bytes32 _right) public view returns (bytes32 res) {
    address lib_ = POSEIDON;
    bytes4 s = SEL;
    assembly {
      let p := mload(0x40)
      mstore(p, s)
      mstore(add(p, 4), _left)
      mstore(add(p, 36), _right)
      if iszero(staticcall(gas(), lib_, p, 68, p, 32)) {
        revert(0, 0)
      }
      res := mload(p)
    }
  }

  function insertLeaves(bytes32[] memory _leafHashes) public {
    uint256 count = _leafHashes.length;
    if (count == 0) return;
    if ((nextLeafIndex + count) > (2 ** TREE_DEPTH)) newTree();
    uint256 levelInsertionIndex = nextLeafIndex;
    nextLeafIndex += count;
    uint256 nextLevelHashIndex;
    uint256 nextLevelStartIndex;
    for (uint256 level = 0; level < TREE_DEPTH; level += 1) {
      nextLevelStartIndex = levelInsertionIndex >> 1;
      uint256 insertionElement = 0;
      if (levelInsertionIndex % 2 == 1) {
        nextLevelHashIndex = (levelInsertionIndex >> 1) - nextLevelStartIndex;
        _leafHashes[nextLevelHashIndex] = hashLeftRight(filledSubTrees[level], _leafHashes[insertionElement]);
        insertionElement += 1;
        levelInsertionIndex += 1;
      }
      for (insertionElement; insertionElement < count; insertionElement += 2) {
        bytes32 right;
        if (insertionElement < count - 1) {
          right = _leafHashes[insertionElement + 1];
        } else {
          right = zeros[level];
        }
        if (insertionElement == count - 1 || insertionElement == count - 2) {
          filledSubTrees[level] = _leafHashes[insertionElement];
        }
        nextLevelHashIndex = (levelInsertionIndex >> 1) - nextLevelStartIndex;
        _leafHashes[nextLevelHashIndex] = hashLeftRight(_leafHashes[insertionElement], right);
        levelInsertionIndex += 2;
      }
      levelInsertionIndex = nextLevelStartIndex;
      count = nextLevelHashIndex + 1;
    }
    merkleRoot = _leafHashes[0];
    rootHistory[treeNumber][merkleRoot] = true;
  }

  function newTree() internal {
    merkleRoot = newTreeRoot;
    nextLeafIndex = 0;
    treeNumber += 1;
  }

  /// Insert `n` dummy leaves and report the gas the insertion actually cost (library warm).
  function measure(uint256 n) external returns (uint256 used, bytes32 root) {
    bytes32[] memory leaves = new bytes32[](n);
    for (uint256 i = 0; i < n; i++) leaves[i] = bytes32(uint256(i) + 1);
    hashLeftRight(bytes32(uint256(1)), bytes32(uint256(2)));
    uint256 g = gasleft();
    insertLeaves(leaves);
    used = g - gasleft();
    root = merkleRoot;
  }
}
