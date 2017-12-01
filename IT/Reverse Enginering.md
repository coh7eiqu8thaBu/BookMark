# Reverse Enginering
*  Memory scanner for Linux https://github.com/scanmem/scanmem

## Binary analysis
* https://github.com/m4b/bingrep/
* This tools search for code cave in binaries (Elf, Mach-o, Pe), and inject code in them. https://github.com/Antonin-Deniau/cave_miner
* Automated static analysis tools for binary programs https://github.com/cmu-sei/pharos
* pestudio 8.68 now available at https://winitor.com/binaries.html  with more hints to ease malware initial assessment
* Reverse Engineering Cross Platform Disassembler: Panopticon https://n0where.net/reverse-engineering-cross-platform-disassembler-panopticon/ and https://github.com/das-labor/panopticon
* Convert Hex To Assembly Using Simple Python Script https://haiderm.com/convert-hex-assembly-using-simple-python-script/
*  Capstone disassembly/disassembler framework: Core (Arm, Arm64, M68K, Mips, PPC, Sparc, SystemZ, X86, X86_64, XCore) + bindings (Python, Java, Ocaml, PowerShell) http://www.capstone-engine.org/ https://github.com/aquynh/capstone/

## VM Analysis
* https://github.com/Cisco-Talos/pyrebox PyREBox is a Python scriptable Reverse Engineering sandbox. It is based on QEMU, and its goal is to aid reverse engineering by providing dynamic analysis and debugging capabilities from a different perspective. PyREBox allows to inspect a running QEMU VM, modify its memory or registers, and to instrument its execution, by creating simple scripts in python to automate any kind of analysis. QEMU (when working as a whole-system-emulator) emulates a complete system (CPU, memory, devices...). By using VMI techniques, it does not require to perform any modification into the guest operating system, as it transparently retrieves information from its memory at run-time.
* This project provides baseline virtual machines for creation of testing environments requiring primarily windows based targets. https://github.com/rapid7/metasploit-baseline-builder

## Registry
* New tool that compares snapshots of Windows Registry http://blog.nirsoft.net/2017/07/14/new-tool-that-compares-snapshots-of-windows-registry/

## Shell Code Mapper
* https://github.com/suraj-root/smap/ http://www.kitploit.com/2017/07/smap-shellcode-mapper.html

## Guide
* RE guide for beginners: Methodology and tools : https://0x00sec.org/t/re-guide-for-beginners-methodology-and-tools/2242 
* List of awesome reverse engineering resources https://github.com/wtsxDev/reverse-engineering

## SSL Proxy
* Decrypts and logs a process's SSL traffic. - https://github.com/google/ssl_logger

## Mobile
* [Mobile Application Reverse engineering and Analysis Framework](https://n0where.net/mobile-application-reverse-engineering-mara/) [GitHub](https://github.com/xtiankisutsa/MARA_Framework)
	* APK Reverse Engineering
	* APK Deobfuscation
	* APK Analysis
	* APK Manifest Analysis
	* 