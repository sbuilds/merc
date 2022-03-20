# Docker build local python image

 docker build --no-cache  -t local/merc .

 # Docker compose start/stop




 docker image prune
 docker container prune
  docker volume prune

strings extraction

linux python continer with floss installed 
https://github.com/mandiant/flare-floss/blob/master/doc/usage.md
simple subprocess and capture 
s=subprocess.run(["floss", "-j", filename], capture_output=True)

decode_responses=True in client will change the response provided and the nesting I think

## pefile doesn't parse
* Windows new-style executable (NE) header.
* Linear Executables (LE) The Linear Executable (LX/LE) Format is the direct successor of the New Executable (NE) Format. It was superseded by the Portable Executable (PE) Format.
* Linear Executables (LX) Linear Executable is an executable file format in the EXE family. It was used by 32-bit OS/2, by some DOS extenders, and by Microsoft Windows VxD files. It is an extension of MS-DOS EXE, and a successor to NE (New Executable)

### Linear executable
Linear Executable is an executable file format in the EXE family. It was used by 32-bit OS/2, by some DOS extenders, and by Microsoft Windows VxD files. It is an extension of MS-DOS EXE, and a successor to NE (New Executable).

There are two main varieties of it: LX (32-bit), and LE (mixed 16/32-bit).

A Linear executable features a standard MZ header, with the e_lfanew field at offset 0x3C pointing to an LX/LE header instead of an NE header. The LX/LE headers have a different magic value than the NE header, namely "LX" and "LE".

There are some slight differences when reading LE file compared to reading LX file, like page map entries being 32bit wide for LE but 64bit wide for LX).

A Linear Executable file begins with the ASCII signature "MZ". At offset 60 is a 4-byte integer pointing to an "extended" header that begins with "LX" or "LE". For more information, see MS-DOS EXE.

http://www.textfiles.com/programming/FORMATS/lxexe.txt