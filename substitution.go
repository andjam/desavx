//go:build amd64
// +build amd64

package desavx

// substitution replaces a 48-bit input (stored in the lower 48 bits of in) with
// a 32-bit output (stored in the lower 32 bits of the output) mapping 6-bit
// groups in the input to 4-bit entries in the corresponding substitution boxes
// defined in table 7.8 of HoAC.
func substitution(in qw) qw
func substitutionVec2(in [2]qw) [2]qw
