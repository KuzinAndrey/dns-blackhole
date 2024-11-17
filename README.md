# dns-blackhole

DNS blackhole server for resolve list of domain names to blackhole IP.
Can be used to block some ads, malware, pop-ups sites or similar tasks.

Idea for this project was inspired by OOM killer in ISC BIND with more
than 580 thousands of blocked domain names resolved into HTTP server with
plug page "This domain was blocked by your ISP".

DNS server has 8G of RAM, and `named` process consume about 6G of them,
any `rndc reload` become to crash.

This project act as light proxy to fast resolve all blocked domains into
blackhole IP, and request backend `named` which act as regular cache-only
without any authorised blocked zones (use low memory).


## Libevent modification

For support all types of DNS request i create commit [deafc965de47](https://github.com/KuzinAndrey/libevent/commit/deafc965de4747d5e8027ab0d5315d4564113850) and [PR 1753](https://github.com/libevent/libevent/pull/1753) in Libevent.

## Build local version of project

But for now use it as patches to build:
```shell
git clone -b new-dns-query-types https://github.com/KuzinAndrey/libevent
cp dns-blackhole.c libevent/sample/
cp cmake.patch libevent/
cd libevent
git apply cmake.patch && rm cmake.patch
mkdir build && cd build && cmake .. && make
```
If all going successful, then builded app appear in `build/bin` directory.

## Run application

Run help:
```
$ bin/dns-blackhole -h

DNS blackhole server for resolve list of domain names to blackhole IP.
Can be used to block some ads, malware, pop-ups sites or similar tasks.
Author: Kuzin Andrey <kuzinandrey@yandex.ru>
License: MIT
Vcs: https://github.com/KuzinAndrey/kavdbhp
Version: v0.1

Usage:
    bin/dns-blackhole [opts] <domains.txt>
Options:
    -h        - this help
    -v        - version
    -d        - debug mode (increase verbosity)
    -n <ip>   - add backend DNS server IP address as resolver (can be multiple time),
                if no any such option then try to use system configured NS servers
    -t <n>    - backend resolve timeout n*1000 microsec (default 10000)
    -4 <ip>   - blackhole IPv4 address
    -6 <ip6>  - blackhole IPv6 address
    -s        - act as the blackhole (up server on HTTP/80 and HTTPS/443 if -k/-c provided)
    -k <file> - SSL key file (for HTTPS), usually self signed
    -c <file> - SSL cert file (for HTTPS)
Data:
    <domain.txt> - text file with list of domain names (one name on line),
                   which resolve by server as blackhole IP
Signals:
    SIGHUP    - reload <domain.txt> file content (in run time)

```

Run for blocking domains from `example.txt` in blackhole IP `192.168.2.33`:
```
$ bin/dns-blackhole -d -4 192.168.2.33 ../../example.txt
Load 50 zones in memory:
    - inserted in hash: 50
    - skipped: 0
    - file size: 997
Libevent version: "2.2.1-alpha-dev" /home/avkuzin/github/libevent/sample/dns-blackhole.c:1228
Set system nameservers: 2
    [0] 8.8.8.8 (IPv4)
    [1] 8.8.4.4 (IPv4)
Blackhole IP: 192.168.2.33
DNS server listening on UDP port 53
DNS server listening on TCP port 53
Run server thread
Run resolver thread
....
```

And make some test requests:
```
avkuzin@note:~$ dig +noall +answer A yandex.ru @192.168.2.33
yandex.ru.		218	IN	A	77.88.44.55
yandex.ru.		218	IN	A	5.255.255.77
yandex.ru.		218	IN	A	77.88.55.88
avkuzin@note:~$ dig +noall +answer A csmax.ru @192.168.2.33
csmax.ru.		10	IN	A	192.168.2.33
avkuzin@note:~$ dig +noall +answer A yandex.ru @192.168.2.33
yandex.ru.		190	IN	A	5.255.255.77
yandex.ru.		190	IN	A	77.88.44.55
yandex.ru.		190	IN	A	77.88.55.88
avkuzin@note:~$ dig +noall +answer NS domain.com @192.168.2.33
domain.com.		86400	IN	NS	lee.ns.cloudflare.com.
domain.com.		86400	IN	NS	sarah.ns.cloudflare.com.
avkuzin@note:~$ dig +noall +answer TXT vk.com @192.168.2.33
vk.com.			900	IN	TXT	"wmail-verification: 646ff42e916a2be1aa86be6d3c742949"
vk.com.			900	IN	TXT	"_globalsign-domain-verification=YM9xQ7VIOTNzoxGpxAE1kwy28slNTGWXflmZgt73D9"
vk.com.			900	IN	TXT	"v=spf1 ip4:93.186.224.0/20 ip4:87.240.128.0/18 i" "p4:95.142.192.0/21 mx include:_spf.google.com in" "clude:_spf.mail.ru ~all"
vk.com.			900	IN	TXT	"yandex-verification: 0bb3aeafaf40a3fa"
vk.com.			900	IN	TXT	"LD6VaYCKete4UB5FIx7snCoJ8bt1nGdeCWe4my5HH5psRaTl" "zAmvc"
vk.com.			900	IN	TXT	"HARICA-fLc9OEonBmci43ogW3C"
vk.com.			900	IN	TXT	"google-site-verification=bQE4SQUYC7KTvk4XCaMdwF0e_tj-O-6ZXMfXW2a8mHY"
```

Logs on server console:
```
...

Run server thread
Run resolver thread
 -- Send blackhole A IP for csmax.ru /2/libevent/sample/dns-blackhole.c:415
 -- Try resolve A for yandex.ru /2/libevent/sample/dns-blackhole.c:423
 -- resolved A: 3 rec (ttl = 190) /2/libevent/sample/dns-blackhole.c:244
    0: 5.255.255.77 /2/libevent/sample/dns-blackhole.c:250
    1: 77.88.44.55 /2/libevent/sample/dns-blackhole.c:250
    2: 77.88.55.88 /2/libevent/sample/dns-blackhole.c:250
 -- send 3 IPv4 for yandex.ru... /2/libevent/sample/dns-blackhole.c:438
 -- Try resolve NS for domain.com /2/libevent/sample/dns-blackhole.c:453
 -- resolved NS: 2 rec (ttl = 86400) /2/libevent/sample/dns-blackhole.c:289
    0: lee.ns.cloudflare.com /2/libevent/sample/dns-blackhole.c:293
    1: sarah.ns.cloudflare.com /2/libevent/sample/dns-blackhole.c:293
 -- send 2 NS for domain.com... /2/libevent/sample/dns-blackhole.c:460
    0: lee.ns.cloudflare.com /2/libevent/sample/dns-blackhole.c:462
    1: sarah.ns.cloudflare.com /2/libevent/sample/dns-blackhole.c:462
 -- Try resolve TXT for vk.com /2/libevent/sample/dns-blackhole.c:582
 -- resolved TXT: 7 rec (ttl = 900) /2/libevent/sample/dns-blackhole.c:342
    0: wmail-verification: 646ff42e916a2be1aa86be6d3c742949 /2/libevent/sample/dns-blackhole.c:354
    1: _globalsign-domain-verification=YM9xQ7VIOTNzoxGpxAE1kwy28slNTGWXflmZgt73D9 /2/libevent/sample/dns-blackhole.c:354
    2: v=spf1 ip4:93.186.224.0/20 ip4:87.240.128.0/18 i /2/libevent/sample/dns-blackhole.c:354
    3: yandex-verification: 0bb3aeafaf40a3fa /2/libevent/sample/dns-blackhole.c:354
    4: LD6VaYCKete4UB5FIx7snCoJ8bt1nGdeCWe4my5HH5psRaTl /2/libevent/sample/dns-blackhole.c:354
    5: HARICA-fLc9OEonBmci43ogW3C /2/libevent/sample/dns-blackhole.c:354
    6: google-site-verification=bQE4SQUYC7KTvk4XCaMdwF0e_tj-O-6ZXMfXW2a8mHY /2/libevent/sample/dns-blackhole.c:354
 -- send 7 TXT for vk.com... /2/libevent/sample/dns-blackhole.c:590
    0[parts=1]: [wmail-verification: 646ff42e916a2be1aa86be6d3c742949] /2/libevent/sample/dns-blackhole.c:592
    1[parts=1]: [_globalsign-domain-verification=YM9xQ7VIOTNzoxGpxAE1kwy28slNTGWXflmZgt73D9] /2/libevent/sample/dns-blackhole.c:592
    2[parts=3]: [v=spf1 ip4:93.186.224.0/20 ip4:87.240.128.0/18 i] /2/libevent/sample/dns-blackhole.c:592
    3[parts=1]: [yandex-verification: 0bb3aeafaf40a3fa] /2/libevent/sample/dns-blackhole.c:592
    4[parts=2]: [LD6VaYCKete4UB5FIx7snCoJ8bt1nGdeCWe4my5HH5psRaTl] /2/libevent/sample/dns-blackhole.c:592
    5[parts=1]: [HARICA-fLc9OEonBmci43ogW3C] /2/libevent/sample/dns-blackhole.c:592
    6[parts=1]: [google-site-verification=bQE4SQUYC7KTvk4XCaMdwF0e_tj-O-6ZXMfXW2a8mHY] /2/libevent/sample/dns-blackhole.c:592
```

## TODO

[ ] - debug any error to prevent production server to crash
[ ] - try to remove wait resolver cycle and make it async
[ ] - known error somewhere in OpenSSL that prevent to crash if use HTTPS server

Crash log to analyze:
```
$ valgrind bin/dns-blackhole -s -k ../../prikey.pem -c ../../fullchain.pem -d -4 192.16
8.2.33 ../../example.txt
==23813== Memcheck, a memory error detector
==23813== Copyright (C) 2002-2024, and GNU GPL'd, by Julian Seward et al.
==23813== Using Valgrind-3.23.0 and LibVEX; rerun with -h for copyright info
==23813== Command: bin/dns-blackhole -s -k ../../prikey.pem -c ../../fullchain.pem -d -4 192.168.2.33 ../../example.txt
==23813== 
Load 50 zones in memory:
    - inserted in hash: 50
    - skipped: 0
    - file size: 997
Libevent version: "2.2.1-alpha-dev" /home/avkuzin/github/libevent/sample/dns-blackhole.c:1228
Set system nameservers: 2
    [0] 77.108.97.135 (IPv4)
    [1] 77.108.97.140 (IPv4)
Blackhole IP: 192.168.2.33
DNS server listening on UDP port 53
DNS server listening on TCP port 53
OpenSSL version: "OpenSSL 3.3.2 3 Sep 2024" /home/avkuzin/github/libevent/sample/dns-blackhole.c:1399
Run HTTPS server thread
Run HTTP server thread
Run server thread
Run resolver thread
==23813== 
==23813== Process terminating with default action of signal 13 (SIGPIPE)
==23813==    at 0x405E992: ??? (syscall_cp.s:29)
==23813==    by 0x405B616: __syscall_cp_c (pthread_cancel.c:33)
==23813==    by 0x4062AD6: write (write.c:6)
==23813==    by 0x4A5DECE: ??? (in /lib/libcrypto.so.3)
==23813==    by 0x4A54A43: ??? (in /lib/libcrypto.so.3)
==23813==    by 0x4A53655: ??? (in /lib/libcrypto.so.3)
==23813==    by 0x4A53937: BIO_write (in /lib/libcrypto.so.3)
==23813==    by 0x49224D0: ??? (in /lib/libssl.so.3)
==23813==    by 0x48D91ED: ??? (in /lib/libssl.so.3)
==23813==    by 0x493095C: ??? (in /lib/libssl.so.3)
==23813==    by 0x491B9BA: ??? (in /lib/libssl.so.3)
==23813==    by 0x491C369: ??? (in /lib/libssl.so.3)
==23813== 
==23813== HEAP SUMMARY:
==23813==     in use at exit: 1,081,881 bytes in 6,933 blocks
==23813==   total heap usage: 33,496 allocs, 26,563 frees, 11,647,074 bytes allocated
==23813== 
==23813== LEAK SUMMARY:
==23813==    definitely lost: 0 bytes in 0 blocks
==23813==    indirectly lost: 0 bytes in 0 blocks
==23813==      possibly lost: 67,770 bytes in 48 blocks
==23813==    still reachable: 1,014,111 bytes in 6,885 blocks
==23813==         suppressed: 0 bytes in 0 blocks
==23813== Rerun with --leak-check=full to see details of leaked memory
==23813== 
==23813== For lists of detected and suppressed errors, rerun with: -s
==23813== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
```
