//go:build !amd64 || purego

package serpent

// bulkBlocks has no vector kernel on this target (or under the purego tag):
// it does nothing and the portable four-block loops take everything.
func (c *serpentCipher) bulkBlocks(dst, src []byte, dec bool) int { return 0 }
