# ShellGo
Simple Shellcode Loader tool

## Requeriments
- Need Golang installed (https://go.dev/doc/install)
- Disable AV or add a exclusion for file donut.exe (file for generate shellcode)

## Usage
```
go build ./ShellGo.go
./ShellGo.exe -a x64 -f file.exe -o output.exe

Examples:
  Use Stub of Fibers and encrypt with rc4
  ./ShellGo.exe -a x64  -e 2 -s 2 -f file.exe -o output.exe
    
   Use encrypt of Xor and stub default
  ./ShellGo.exe -a x64  -e 3 -f file.exe -o output.exe
for more help you can use the command --fullhelp
```


## How does it work?
The tool uses donut to generate the shellcode of the executable then according to the options it obfuscates the shellcode or encrypts and the shellcode with encryption is copied to a Golang stub and finally it is compiled.

Poc with Defender:
![photo_2023-02-27_20-13-58](https://user-images.githubusercontent.com/104540054/221710670-1e3fc569-65df-4837-84a7-5fe737fb9638.jpg)

### Credits
Thanks to TheWover for donut, https://github.com/TheWover/donut
