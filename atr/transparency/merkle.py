"""Merkle tree implementation for transparency log"""
import hashlib
from typing import List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime


@dataclass
class MerkleNode:
    """Merkle tree node"""
    hash: str
    left: Optional['MerkleNode'] = None
    right: Optional['MerkleNode'] = None
    data: Optional[bytes] = None  # Only leaf nodes have data


def hash_data(data: bytes) -> str:
    """Hash data using SHA-256"""
    return hashlib.sha256(data).hexdigest()


def hash_pair(left_hash: str, right_hash: str) -> str:
    """Hash a pair of hashes"""
    combined = left_hash + right_hash
    return hashlib.sha256(combined.encode('utf-8')).hexdigest()


class MerkleTree:
    """Merkle tree implementation for transparency log"""
    
    def __init__(self, entries: List[bytes]):
        """Build Merkle tree from entries"""
        if not entries:
            self.root = None
            self.leaves = []
            return
        
        # Create leaf nodes
        self.leaves = [MerkleNode(hash=hash_data(entry), data=entry) for entry in entries]
        
        # Build tree bottom-up
        nodes = self.leaves.copy()
        while len(nodes) > 1:
            next_level = []
            for i in range(0, len(nodes), 2):
                if i + 1 < len(nodes):
                    # Pair of nodes
                    left = nodes[i]
                    right = nodes[i + 1]
                    combined_hash = hash_pair(left.hash, right.hash)
                    parent = MerkleNode(hash=combined_hash, left=left, right=right)
                    next_level.append(parent)
                else:
                    # Odd node, promote it
                    next_level.append(nodes[i])
            nodes = next_level
        
        self.root = nodes[0] if nodes else None
    
    def get_root_hash(self) -> Optional[str]:
        """Get root hash of the tree"""
        return self.root.hash if self.root else None
    
    def generate_inclusion_proof(self, entry_index: int) -> List[str]:
        """
        Generate inclusion proof for entry at given index.
        Returns list of sibling hashes needed to verify inclusion.
        """
        if entry_index < 0 or entry_index >= len(self.leaves):
            raise ValueError(f"Entry index {entry_index} out of range")
        
        proof = []
        node = self.leaves[entry_index]
        current_level = self.leaves.copy()
        current_index = entry_index
        
        # Traverse up the tree, collecting sibling hashes
        while len(current_level) > 1:
            # Find sibling
            if current_index % 2 == 0:
                # Left child - sibling is right
                if current_index + 1 < len(current_level):
                    sibling = current_level[current_index + 1]
                    proof.append(sibling.hash)
                    current_index = current_index // 2
                else:
                    # No sibling, add empty hash
                    proof.append(None)
                    current_index = current_index // 2
            else:
                # Right child - sibling is left
                sibling = current_level[current_index - 1]
                proof.append(sibling.hash)
                current_index = (current_index - 1) // 2
            
            # Build next level
            next_level = []
            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    left = current_level[i]
                    right = current_level[i + 1]
                    combined_hash = hash_pair(left.hash, right.hash)
                    parent = MerkleNode(hash=combined_hash, left=left, right=right)
                    next_level.append(parent)
                else:
                    next_level.append(current_level[i])
            current_level = next_level
        
        # Filter out None values (where there's no sibling)
        return [h for h in proof if h is not None]
    
    def verify_inclusion_proof(
        self,
        entry: bytes,
        entry_index: int,
        root_hash: str,
        proof: List[str]
    ) -> bool:
        """Verify that an entry is included in the tree with given root hash"""
        # Compute entry hash
        entry_hash = hash_data(entry)
        
        # Reconstruct hash from proof
        current_hash = entry_hash
        proof_index = 0
        current_level_size = len(self.leaves)
        idx = entry_index
        
        while proof_index < len(proof):
            sibling_hash = proof[proof_index]
            
            if idx % 2 == 0:
                # We're left child, sibling is right
                current_hash = hash_pair(current_hash, sibling_hash)
            else:
                # We're right child, sibling is left
                current_hash = hash_pair(sibling_hash, current_hash)
            
            idx = idx // 2
            current_level_size = (current_level_size + 1) // 2
            proof_index += 1
        
        return current_hash == root_hash


def build_merkle_tree(entries: List[bytes]) -> MerkleTree:
    """Build a Merkle tree from a list of entries"""
    return MerkleTree(entries)
