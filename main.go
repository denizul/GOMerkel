package main

import (
	"crypto/sha256"
	"bytes"
	"os"
	"bufio"
	"fmt"
	"errors"
	"time"
	"log"
)

// implements the Content interface provided by merkletree and represents the content stored in the tree.
type TestContent struct {
	x string
}

//CalculateHash hashes the values of a TestContent
func (t TestContent) CalculateHash() ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write([]byte(t.x)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

//Equals tests for equality of two Contents
func (t TestContent) Equals(other Content) (bool, error) {
	return t.x == other.(TestContent).x, nil
}

//Content represents the data that is stored and verified by the tree. A type that
//implements this interface can be used as an item in the tree.
type Content interface {
	CalculateHash() ([]byte, error)
	Equals(other Content) (bool, error)
}

//MerkleTree is the container for the tree. It holds a pointer to the root of the tree,
//a list of pointers to the leaf nodes, and the merkle root.
type MerkleTree struct {
	Root       *Node
	merkleRoot []byte
	Leafs      []*Node
}

//Node represents a node, root, or leaf in the tree. It stores pointers to its immediate
//relationships, a hash, the content stored if it is a leaf, and other metadata.
type Node struct {
	Parent *Node
	Left   *Node
	Right  *Node
	leaf   bool
	dup    bool
	Hash   []byte
	C      Content
}

//verifyNode walks down the tree until hitting a leaf, calculating the hash at each level
//and returning the resulting hash of Node n.
func (n *Node) verifyNode() ([]byte, error) {
	if n.leaf {
		return n.C.CalculateHash()
	}
	rightBytes, err := n.Right.verifyNode()
	if err != nil {
		return nil, err
	}

	leftBytes, err := n.Left.verifyNode()
	if err != nil {
		return nil, err
	}

	h := sha256.New()
	if _, err := h.Write(append(leftBytes, rightBytes...)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

//calculateNodeHash is a helper function that calculates the hash of the node.
func (n *Node) calculateNodeHash() ([]byte, error) {
	if n.leaf {
		return n.C.CalculateHash()
	}

	h := sha256.New()
	if _, err := h.Write(append(n.Left.Hash, n.Right.Hash...)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// Creates a new Merkle Tree using the content cs.
func Setup(cs []Content) (*MerkleTree, error) {
	defer timeTrack(time.Now(), "Setup")
	root, leafs, err := buildWithContent(cs)
	if err != nil {
		return nil, err
	}
	t := &MerkleTree{
		Root:       root,
		merkleRoot: root.Hash,
		Leafs:      leafs,
	}
	return t, nil
}

//buildWithContent is a helper function that for a given set of Contents, generates a
//corresponding tree and returns the root node, a list of leaf nodes, and a possible error.
//Returns an error if cs contains no Contents.
func buildWithContent(cs []Content) (*Node, []*Node, error) {
	if len(cs) == 0 {
		return nil, nil, errors.New("error: cannot construct tree with no content")
	}
	var leafs []*Node
	for _, c := range cs {
		hash, err := c.CalculateHash()
		if err != nil {
			return nil, nil, err
		}

		leafs = append(leafs, &Node{
			Hash: hash,
			C:    c,
			leaf: true,
		})
	}
	if len(leafs)%2 == 1 {
		duplicate := &Node{
			Hash: leafs[len(leafs)-1].Hash,
			C:    leafs[len(leafs)-1].C,
			leaf: true,
			dup:  true,
		}
		leafs = append(leafs, duplicate)
	}
	root, err := buildIntermediate(leafs)
	if err != nil {
		return nil, nil, err
	}

	return root, leafs, nil
}

//buildIntermediate is a helper function that for a given list of leaf nodes, constructs
//the intermediate and root levels of the tree. Returns the resulting root node of the tree.
func buildIntermediate(nl []*Node) (*Node, error) {
	var nodes []*Node
	for i := 0; i < len(nl); i += 2 {
		h := sha256.New()
		var left, right int = i, i + 1
		if i+1 == len(nl) {
			right = i
		}
		chash := append(nl[left].Hash, nl[right].Hash...)
		if _, err := h.Write(chash); err != nil {
			return nil, err
		}
		n := &Node{
			Left:  nl[left],
			Right: nl[right],
			Hash:  h.Sum(nil),
		}
		nodes = append(nodes, n)
		nl[left].Parent = n
		nl[right].Parent = n
		if len(nl) == 2 {
			return n, nil
		}
	}
	return buildIntermediate(nodes)
}

//VerifyTree verify tree validates the hashes at each level of the tree and returns true if the
//resulting hash at the root of the tree matches the resulting root hash; returns false otherwise.
func (m *MerkleTree) VerifyTree() (bool, error) {
	calculatedMerkleRoot, err := m.Root.verifyNode()
	if err != nil {
		return false, err
	}

	if bytes.Compare(m.merkleRoot, calculatedMerkleRoot) == 0 {
		return true, nil
	}
	return false, nil
}

//VerifyContent indicates whether a given content is in the tree and the hashes are valid for that content.
//Returns true if the expected Merkle Root is equivalent to the Merkle root calculated on the critical path
//for a given content. Returns true if valid and false otherwise.
func (m *MerkleTree) VerifyContent(content Content) (bool, error) {
	for _, l := range m.Leafs {
		ok, err := l.C.Equals(content)
		if err != nil {
			return false, err
		}

		if ok {
			currentParent := l.Parent
			for currentParent != nil {
				h := sha256.New()
				rightBytes, err := currentParent.Right.calculateNodeHash()
				if err != nil {
					return false, err
				}

				leftBytes, err := currentParent.Left.calculateNodeHash()
				if err != nil {
					return false, err
				}
				if currentParent.Left.leaf && currentParent.Right.leaf {
					if _, err := h.Write(append(leftBytes, rightBytes...)); err != nil {
						return false, err
					}
					if bytes.Compare(h.Sum(nil), currentParent.Hash) != 0 {
						return false, nil
					}
					currentParent = currentParent.Parent
				} else {
					if _, err := h.Write(append(leftBytes, rightBytes...)); err != nil {
						return false, err
					}
					if bytes.Compare(h.Sum(nil), currentParent.Hash) != 0 {
						return false, nil
					}
					currentParent = currentParent.Parent
				}
			}
			return true, nil
		}
	}
	return false, nil
}

//Records Execution time of a function
func timeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	log.Printf("function %s took %s", name, elapsed)
}


//Gets data from given file
func RetrieveData(filename string) ([]byte, error) {
    file, err := os.Open(filename)

    if err != nil {
        return nil, err
    }
    defer file.Close()

    stats, statsErr := file.Stat()
    if statsErr != nil {
        return nil, statsErr
    }

    var size int64 = stats.Size()
    bytes := make([]byte, size)

    bufr := bufio.NewReader(file)
    _,err = bufr.Read(bytes)

    return bytes, err
}

func main() {
	//Build list structure of all files
	//in the "files" directory
	var file_list []Content
	var m []byte

	//Open the folder and check for failure
	file, file_err := os.Open("files")
	if file_err != nil { panic(file_err) }
	defer file.Close()
	
	//Create list and then iterate through the list of read files
	//These read files will be opened, their data loaded
	//Then stored in slice of Content Structs
	list,_ := file.Readdirnames(0) // Returns slice of read files
	for _, name := range list {
		m, _ = RetrieveData("files/" + name)
		file_list = append(file_list, TestContent{x: string(m)})
	}
	fmt.Printf("Num Entries: %d\n", len(file_list))

	//Setup Case
	//Setup will generate a tree from given 
	//Slice of Content structs
	_, err := Setup(file_list)
	if err != nil { panic(file_err) }

	//Proof Case
	//In this case we have to essentially grab any node within
	//the tree and then prove it is in there by showing 
	//the derivation of hashes that got to that point

	//Verify Case
	//This part will require to get a random hash, say the ending
	//With this hash we have to check if it matches with hashes of any elements 
	//We do this by accessing the list we just made
	//We then try to create a hash from the list element chosen
	//Once we do that we will have to traverse the tree for a match
	//If we don't have a match REJECT else ACCEPT


	//Update Case
	//Add an extra file to the tree
	//Once added the tree will have to be rebuilt
	//This is the easy case

  }