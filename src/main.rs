use digest::Digest;
use hex::encode;

// Merkle tree node
#[derive(Debug, Clone)]
struct MerkleNode {
    left: Option<Box<MerkleNode>>,
    right: Option<Box<MerkleNode>>,
    hash: String,
}

impl MerkleNode {
    fn new(hash: &str) -> MerkleNode {
        MerkleNode {
            left: None,
            right: None,
            hash: hash.to_string(),
        }
    }
}

// Merkle tree
#[derive(Debug)]
struct MerkleTree {
    root: Option<Box<MerkleNode>>,
}

impl MerkleTree {
    fn new(leaves: Vec<&str>) -> MerkleTree {
        let nodes: Vec<MerkleNode> = leaves.iter().map(|&l| MerkleNode::new(l)).collect();
        let mut tree = MerkleTree { root: None };

        tree.build_tree(nodes);

        tree
    }

    fn build_tree(&mut self, nodes: Vec<MerkleNode>) {
        let mut temp_nodes = nodes;

        while temp_nodes.len() > 1 {
            let mut new_level = Vec::new();

            for i in (0..temp_nodes.len()).step_by(2) {
                let left = temp_nodes[i].clone();
                let right = if i + 1 < temp_nodes.len() {
                    temp_nodes[i + 1].clone()
                } else {
                    left.clone()
                };

                let hash_input = format!("{}{}", left.hash, right.hash);
                let hash_bytes = sha256(&hash_input);
                let hash = encode(hash_bytes);


                let node = MerkleNode {
                    left: Some(Box::new(left)),
                    right: Some(Box::new(right)),
                    hash,
                };

                new_level.push(node);
            }

            temp_nodes = new_level;
        }

        if temp_nodes.len() == 1 {
            self.root = Some(Box::new(temp_nodes.remove(0)));
        }
    }

    fn generate_proof(&self, target_leaf: &str) -> Option<Vec<String>> {
        let mut proof = Vec::new();

        if let Some(ref root) = self.root {
            self.generate_proof_recursive(root, target_leaf, &mut proof);
        }

        if proof.is_empty() {
            None
        } else {
            Some(proof)
        }
    }

    fn generate_proof_recursive(
        &self,
        node: &Box<MerkleNode>,
        target_leaf: &str,
        proof: &mut Vec<String>,
    ) -> bool {
        if node.hash == target_leaf {
            return true;
        }

        if let Some(ref left) = node.left {
            if self.generate_proof_recursive(left, target_leaf, proof) {
                proof.push(node.right.as_ref().unwrap().hash.clone());
                return true;
            }
        }

        if let Some(ref right) = node.right {
            if self.generate_proof_recursive(right, target_leaf, proof) {
                proof.push(node.left.as_ref().unwrap().hash.clone());
                return true;
            }
        }

        false
    }
}

fn sha256(data: &str) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn main() {
    // Example usage
    let leaves = vec!["data1", "data2", "data3", "data4"];
    let merkle_tree = MerkleTree::new(leaves);

    // Choose a leaf for which you want to generate a proof
    let target_leaf = "data3";
    
    // Generate the Merkle proof
    if let Some(proof) = merkle_tree.generate_proof(target_leaf) {
        println!("Merkle Proof for {}: {:?}", target_leaf, proof);
    } else {
        println!("Leaf not found in the Merkle tree.");
    }
}
