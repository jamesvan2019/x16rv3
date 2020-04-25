package main

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestX16RV3Hash(t *testing.T) {
	// qitmeer header bytes must equal 113 bytes
	data := []byte(`helloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhel`)
	res := Sum(data)
	fmt.Println(hex.EncodeToString(res))
}
