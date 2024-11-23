#!/bin/sh

# make && valgrind --leak-check=full --show-reachable=yes bin/dns-blackhole example.txt
# make && bin/dns-blackhole example.txt

NS="192.168.2.33"

while read D; do
	for T in \
		SOA \
		TXT \
		NS \
		MX \
		A \
		AAAA \
	; do
		echo "[$D = $T]"
		dig +noall +answer $T $D @$NS
	done
done << EOF
yandex.ru
google.com
vk.com
fishki.net
domain.com
github.com
dataline.ru
EOF

# PTR address
while read H; do
	echo "[PTR = $H]"
	dig +noall +answer -x $H @$NS
done << EOF
8.8.8.8
8.8.4.4
1.1.1.1
77.88.8.8
77.88.8.1
5.255.255.70
EOF

# blocked names
while read H; do
	dig +noall +answer $H @$NS
done < example.txt
