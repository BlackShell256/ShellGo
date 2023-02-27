# ShellGo
Simple Shellcode Loader tool

# Usage
```
go run ShellGo.go x64/x86 loader.bin output.exe
for more help you can use the command --fullhelp
```


## How does it work?
You tell the tool your shellcode .bin file and it obfuscates it by adding a random value to each byte, with that it compiles an executable that loads your obfuscated shellcode.

Poc with Defender:
![photo_2023-02-27_20-13-58](https://user-images.githubusercontent.com/104540054/221710670-1e3fc569-65df-4837-84a7-5fe737fb9638.jpg)
