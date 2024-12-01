
# EVTXHide

This project details Log Steganography techniques by tampering with Windows EVTX logs

## Installation

G++ must be installed

For more information: [GCC, the GNU Compiler Collection
](https://gcc.gnu.org/)

## Documentation

EVTXTool.exe must be in the same directory as wrapper.exe

.\wrapper.exe 

.\RUN.exe


```bash
  USAGE: ./wrapper.exe [options]
  -t Target filepath
  -f File to encode
  --executable Compiling back to executable
```


## Usage/Examples

To run .\wrapper.exe

```bash
  wrapper.exe -t C:\Windows\System32\winevt\logs\Security.evtx -f C:\Windows\System32\calc.exe --executable C:\Users\boop\Desktop\RUN.exe
```

To run .\RUN.exe 
```bash
  .\RUN.exe
```

Output of respective code:

.\wrapper.exe
```bash
Executable generated successfully: C:\Users\boop\Desktop\RUN.exe

```

.\RUN.exe
```bash
Executing command: cmd /c "C:\Windows\Temp\EVTXTool.exe -e -i "C:\Windows\System32\winevt\logs\Security.evtx" -o "C:\Windows\Temp\encoded.evtx" -f "C:\Windows\Temp\toEncode.txt" -s 27 -s 28"
The content has been successfully encoded and saved to: C:\Windows\Temp\encoded.evtx
Successfully terminated process with PID 12232.
File deleted successfully: C:\Windows\System32\winevt\logs\Security.evtx
File copied successfully from C:\Windows\Temp\encoded.evtx to C:\Windows\System32\winevt\logs\Security.evtx
Service started successfully.
Operation completed successfully.
```
## Contributing

Jeryl Loi, Josiah Rachmat, Lee Nicholas, Denzyl Thaddeus Er, Fong Kei Min