Crypto
=======

# Library
* https://github.com/jedisct1/libsodium  A modern and easy-to-use crypto library. https://libsodium.org
* LibreCrypt: Transparent on-the-fly disk encryption for Windows. LUKS compatible. http://LibreCrypt.eu [GitHub](https://github.com/t-d-k/LibreCrypt)

# Use
* Comprendre les grands principes de la cryptologie et du chiffrement https://www.cnil.fr/fr/comprendre-les-grands-principes-de-la-cryptologie-et-du-chiffrement
* decrypt a password with an external key (usb)
```
password=$(gpg --batch --quiet --no-default-keyring --secret-keyring /media/usb/key.priv --decrypt <<EOF 
-----BEGIN PGP MESSAGE-----

hQEMA0CjbyauRLJ8AQgAkZT5gK8TrdH6cZEy+Ufl0PObGZJ1YEbshacZb88RlRB9
h2z+s/Bso5HQxNd5tzkwulvhmoGu6K6hpMXM3mbYl07jHF4qr+oWijDkdjHBVcn5
0mkpYO1riUf0HXIYnvCZq/4k/ajGZRm8EdDy2JIWuwiidQ18irp07UUNO+AB9mq8
5VXUjUN3tLTexg4sLZDKFYGRi4fyVrYKGsi0i5AEHKwn5SmTb3f1pa5yXbv68eYE
lCVfy51rBbG87UTycZ3gFQjf1UkNVbp0WV+RPEM9JR7dgR+9I8bKCuKLFLnGaqvc
beA3A6eMpzXQqsAg6GGo3PW6fMHqe1ZCvidi6e4a/dJDAbHq0XWp93qcwygnWeQW
Ozr1hr5mCa+QkUSymxiUrRncRhyqSP0ok5j4rjwSJu9vmHTEUapiyQMQaEIF2e2S
/NIWGg==
=uriR
-----END PGP MESSAGE-----
EOF)
```
* RTFM: A database of common, interesting or useful commands, in one handy referable form https://necurity.co.uk/osprog/2017-02-27-RTFM-Pythonized/ - https://github.com/leostat/rtfm
* Se faire une carte à puce OpenPGP https://rodolphe.breard.tf/post/se-faire-une-carte-a-puce-openpgp/
	* https://rodolphe.breard.tf/post/se-faire-une-carte-a-puce-openpgp/
	* https://fr.aliexpress.com/item/-/32856082491.html

# Protect my secret
* [DIY Portable Secrets Manager With a Raspberry Pi Zero and ARC](https://www.evilsocket.net/2017/12/07/DIY-Portable-Secrets-Manager-with-a-RPI-Zero-and-the-ARC-Project/)

# Decryption / encryption algorithms
* Principles and practice of x-raying, great and maybe the first article about this, by Peter Ferrie. https://vallejocc.files.wordpress.com/2017/08/x-raying.pdf
* XorSearch, by Didier Stevens. https://blog.didierstevens.com/programs/xorsearch/
* Decoding XOR shellcode without a Key, by Chris Jordan. https://playingwithothers.com/2012/12/20/decoding-xor-shellcode-without-a-key/
* UnXor, by Tomchop. https://github.com/tomchop/unxor
* Deobfuscating Embedded Malware using Probable-Plaintext Attacks (KANDI tool), by Christian Wressnegger, Frank Boldewin, and Konrad Rieck. https://www.tu-braunschweig.de/Medien-DB/sec/pubs/2013-raid.pdf
* [Attacking encrypted systems with qemu and volatility](https://diablohorn.com/2017/12/12/attacking-encrypted-systems-with-qemu-and-volatility/)

# Hide my Shell
*  Encrypted exploit delivery for the masses https://github.com/Mrgeffitas/Ironsquirrel

# Stegano
* Stego in TCP/IP made easy (Part-1): https://www.exploit-db.com/docs/40891.pdf  (pdf) 
* Part 2 - The Phantom Shell : https://www.exploit-db.com/docs/40897.pdf  (pdf)
* Python Steganography Tool: Matroschka https://github.com/fbngrm/Matroschka
* How to make high spatial frequency checkerboard + low frequency images: https://trmm.net/Checkerboard `convert -size 1024x1024 pattern:checkerboard -auto-level -level 0,100 cb.png; convert -resize x1024 -crop 1024x1024+0+0 -monochrome holly.jpg holly.png; composite -dissolve 90 cb.png holly.png out.png; convert +append cb.png holly.png tri.png`

# iPhone
* all crypto Key https://www.theiphonewiki.com/wiki/Category:IPhone_5s_(iPhone6,1)_Key_Page
* [Hacker Decrypts Apple's Secure Enclave Processor (SEP) Firmware](http://www.iclarified.com/62025/hacker-decrypts-apples-secure-enclave-processor-sep-firmware)
	* [img4lib](https://github.com/xerub/img4lib)
	* [SEP firmware split tool](https://gist.github.com/xerub/0161aacd7258d31c6a27584f90fa2e8c)
# Miselianous
* [list of useful commands, shells and notes related to OSCP](https://github.com/crsftw/OSCP-cheat-sheet)

# Crypto Money
## Ether
* https://etherscripter.com/0-5-1/ EtherScripter
