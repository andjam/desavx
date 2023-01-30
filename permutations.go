//go:build amd64
// +build amd64

package desavx

// ip performs the initial permutation (IP) described in HoAC table 7.2.
func ip(in v64) v64
func ipVec2(in [2]v64) [2]v64

// ipInverse is the inverse (IP⁻¹) of the initial permutation.
func ipInverse(in v64) v64
func ipInverseVec2(in [2]v64) [2]v64

// e is the per round function E described in HoAC table 7.3.
func e(in v64) v64
func eVec2(in [2]v64) [2]v64

// p is the per round function P described in HoAC table 7.3.
func p(in v64) v64
func pVec2(in [2]v64) [2]v64

// pc1 performs the bit selections (PC1) described in HoAC table 7.4.
func pc1(in v64) v64
func pc1Vec2(in [2]v64) [2]v64

// pc2 performs the bit selections (PC2) described in HoAC table 7.4.
func pc2(in v64) v64
func pc2Vec2(in [2]v64) [2]v64
