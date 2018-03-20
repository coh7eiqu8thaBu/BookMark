Forensic and Incident Response
======

* DFF (Digital Forensics Framework) is a Forensics Framework coming with command line and graphical interfaces. - https://github.com/arxsys/dff et https://github.com/arxsys/dff/releases/tag/1.3.6
* PoSh-R2PowerShell - Rapid Response (PoSH-R2)... For the incident responder in you! https://github.com/WiredPulse/PoSh-R2
* PowerKrabsEtw is a PowerShell module built around the krabsetw APIs. It exposes a subset of functionality directly available in krabsetw and is meant to streamline ETW experimentation. https://github.com/zacbrown/PowerKrabsEtw
* Docker container in your browser: codetainer https://n0where.net/docker-container-codetainer/ https://github.com/codetainerapp/codetainer
* Post-Intrusion Concealment and Log Alteration - David Dittrich / The Honeynet Project / dittrich@cac.washington.edu https://staff.washington.edu/dittrich/talks/conceal/
* Detection and recovery of NSA’s covered up tracks https://blog.fox-it.com/2017/12/08/detection-and-recovery-of-nsas-covered-up-tracks/
* This site summarizes the results of examining logs recorded in Windows upon execution of the 49 tools which are likely to be used by the attacker that has infiltrated a network. The following logs were examined. Note that it was confirmed that traces of tool execution is most likely to be left in event logs. Accordingly, examination of event logs is the main focus here. https://jpcertcc.github.io/ToolAnalysisResultSheet/
* Research Report Released: Detecting Lateral Movement through Tracking Event Logs (Version 2) http://blog.jpcert.or.jp/2017/12/research-report-released-detecting-lateral-movement-through-tracking-event-logs-version-2.html
* SIFT – SANS Investigative Forensic Toolkit https://n0where.net/sift/ and [GitHub](https://github.com/sans-dfir/sift-bootstrap)
* Microsoft windows registry hive extraction library for Linux : https://github.com/libguestfs/hivex
* [Incident Response Forensic Framework: nightHawk Response](https://github.com/biggiesmallsAG/nightHawkResponse)
* [Remediation – Tools and utilities for remediation and incident-response handling](https://seclist.us/remediation-tools-and-utilities-for-remediation-and-incident-response-handling.html)
	* [jewelRunner.py - quickly analyze tcp/ip traffic for a target host and create host-based firewall rules in support of micro segmentation activities.](https://github.com/pjhartlieb/remediation)
* USB Detective
	* Article : https://df-stream.com/2018/03/usb-detective/
	* Tool : https://usbdetective.com/version-comparison/
* An easy-to-deploy virtual machine that can provide flexible man-in-the-middle capabilities. : https://github.com/praetorian-inc/mitm-vm


# Filesystem
* Heuristics File System Secret Search: blueflower https://n0where.net/heuristics-file-system-secret-search-blueflower/ https://github.com/veorq/blueflower
* fatcat - FAT Filesystems Explore, Extract, Repair, And Forensic Tool http://www.kitploit.com/2017/11/fatcat-fat-filesystems-explore-extract.html https://github.com/Gregwar/fatcat
* ZipJail is a usermode sandbox for unpacking archives using the unzip, rar, 7z, and unace utilities.  https://github.com/jbremer/tracy/tree/master/src/zipjail
* FSSB is a sandbox for your filesystem. With it, you can run any program and be assured that none of your files are modified in any way. However, the program will not know this - every change it attempts to make will be made safely in a sandbox while still allowing it to read existing files. This includes creating, modifying, renaming, and deleting files. https://github.com/adtac/fssb

# Documents
* Analyzing Malicious Documents Cheat Sheet 
	* https://zeltser.com/analyzing-malicious-documents/
	* https://zeltser.com/media/docs/analyzing-malicious-document-files.pdf
* LogViewer for viewing and searching large text files... https://github.com/woanware/LogViewer
* Extract Metadata From Files: ImageCat https://github.com/chrismattmann/imagecat

# Memory
* Memory Map Viewer https://github.com/zodiacon/KernelExplorer/releases/tag/memmapview-0.1-beta
* Acquiring a Memory Dump from Fleeting Malware https://digital-forensics.sans.org/blog/2017/11/27/acquiring-a-memory-dump-from-fleeting-malware

# Network
* Best pCap Tools : https://n0where.net/best-pcap-tools
* pcap-grapher - Create an intuitive and interactive graph of a client's IP traffic. https://github.com/yotamho/pcap-grapher
* Read a packet capture, extract HTTP requests and turn them into cURL commands for replay. https://github.com/jullrich/pcap2curl
* PcapViz - Visualize Network Topologies and Collect Graph Statistics Based on PCAP Files https://t.co/zT1jjoJTWn #Capture #DATA * Database https://t.co/8TYIB4U2Qd
* netstat without netstat https://staaldraad.github.io/2017/12/20/netstat-without-netstat/

# Android
* [Android Forensics with ADB](https://blog.nviso.be/2017/12/22/intercepting-https-traffic-from-apps-on-android-7-using-magisk-burp/)
* A Java 8 Jar & Android APK Reverse Engineering Suite (Decompiler, Editor, Debugger & More) 
	* https://bytecodeviewer.com
	* [GitHub](https://github.com/Konloch/bytecode-viewer)
* ab_decrypt.py, an educational python tool to decrypt Android backups https://github.com/lclevy/ab_decrypt
* Debugging arm apps with just qemu (no VM): 
	1 `qemu-arm-static -L /usr/arm-linux-gnueabi/ -g 1234 ../vuln &`
	2 Install pwndbg (https://github.com/bkerler/pwndbg  for add. fixes) or gef 
	3 `gdb-multiarch ../vuln` In GDB: set endian little, set architecture arm, target remote :1234
