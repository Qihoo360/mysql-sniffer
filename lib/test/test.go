package main

/*
#cgo CFLAGS: -I .
#cgo LDFLAGS: -L . -llibnids.a

#include "nids.h"

int callOnMeGo_cgo(int in); // Forward declaration.
*/
import "C"

import (
	"fmt"
	"unsafe"
)

//export callOnMeGo
func callOnMeGo(in int) int {
	fmt.Printf("Go.callOnMeGo(): called with arg = %d\n", in)
	return in + 1
}

func main() {
	fmt.Printf("Go.main(): calling C function with callback to us\n")
	C.some_c_func((C.callback_fcn)(unsafe.Pointer(C.callOnMeGo_cgo)))

}
