package tls_client

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/igor-lemon/utls/behavior"
	"math"
	"math/big"
)

func Int64ToInt(x int64) (int, error) {
	if x < math.MinInt || x > math.MaxInt {
		return 0, fmt.Errorf("int64 value %d out of int range [%d, %d]", x, math.MinInt, math.MaxInt)
	}
	return int(x), nil
}

// generateGREASESettingID generates a valid GREASE setting ID
// GREASE IDs are of the form 0x1f * N + 0x21 where N is random
// Chrome uses very large N values, producing setting IDs like 57836956465
func generateGREASESettingID() uint64 { return generateGREASESettingIDPolicy(behavior.Legacy()) }

// generateGREASESettingValue generates a random non-zero 32-bit value for GREASE
func generateGREASESettingValue() uint64 { return generateGREASESettingValuePolicy(behavior.Legacy()) }

func generateGREASESettingIDPolicy(pol behavior.Policy) uint64 {
	if pol == nil {
		return generateGREASESettingID()
	}
	min, max := pol.Uint("h3.grease_setting_n_min"), pol.Uint("h3.grease_setting_n_max")
	n, err := rand.Int(rand.Reader, new(big.Int).SetUint64(max-min+1))
	if err != nil {
		panic(err)
	}
	return 31*(min+n.Uint64()) + 33
}
func generateGREASESettingValuePolicy(pol behavior.Policy) uint64 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	v := binary.BigEndian.Uint32(b[:])
	if v == 0 && pol.Flag("h3.grease_setting_nonzero") {
		v = 1
	}
	return uint64(v)
}
