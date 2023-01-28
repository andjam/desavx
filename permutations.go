//go:build amd64
// +build amd64

package desavx

// ip performs the initial permutation (IP) described in HoAC table 7.2.
func ip(in qw) qw
func ipVec2(in [2]qw) [2]qw

// ipInverse is the inverse (IP⁻¹) of the initial permutation.
func ipInverse(in qw) qw
func ipInverseVec2(in [2]qw) [2]qw

// e is the per round function E described in HoAC table 7.3.
func e(in qw) qw
func eVec2(in [2]qw) [2]qw

// p is the per round function P described in HoAC table 7.3.
func p(in qw) qw
func pVec2(in [2]qw) [2]qw

// pc1 performs the bit selections (PC1) described in HoAC table 7.4.
func pc1(in qw) qw
func pc1Vec2(in [2]qw) [2]qw

// pc2 performs the bit selections (PC2) described in HoAC table 7.4.
func pc2(in qw) qw
func pc2Vec2(in [2]qw) [2]qw
