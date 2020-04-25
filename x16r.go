package main

// #cgo LDFLAGS: libx16r_hash.a
// #cgo CFLAGS: -Wincompatible-pointer-types -Wreturn-type
// #include "x16r.h"
import "C"
import (
	"encoding/hex"
	"fmt"
	"unsafe"
)

func Sum(data []byte) []byte {
	var res = make([]uint32, 8)
	C.x16r_hash(unsafe.Pointer(&data[0]), unsafe.Pointer(&res[0]))
	hexS := ""
	for i := 0; i < 8; i++ {
		hexS += fmt.Sprintf("%08x", res[i])
	}
	b, _ := hex.DecodeString(hexS)
	return b
}

func main() {
	b := []byte("helloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhel")
	h := Sum(b)
	fmt.Println(hex.EncodeToString(h))
}
