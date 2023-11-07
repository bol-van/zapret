#!/bin/sh

EXEDIR="$(dirname "$0")"
EXEDIR="$(cd "$EXEDIR"; pwd)"
ZAPRET_BASE="$EXEDIR"

[ -f "$ZAPRET_BASE/config" ] && . "$ZAPRET_BASE/config"
. "$ZAPRET_BASE/common/base.sh"
. "$ZAPRET_BASE/common/dialog.sh"
. "$ZAPRET_BASE/common/elevate.sh"
. "$ZAPRET_BASE/common/fwtype.sh"
. "$ZAPRET_BASE/common/virt.sh"

[ -n "$QNUM" ] || QNUM=59780
[ -n "$TPPORT" ] || TPPORT=993
[ -n "$TPWS_UID" ] || TPWS_UID=1
[ -n "$TPWS_GID" ] || TPWS_GID=3003
[ -n "$NFQWS" ] || NFQWS="$ZAPRET_BASE/nfq/nfqws"
[ -n "$DVTWS" ] || DVTWS="$ZAPRET_BASE/nfq/dvtws"
[ -n "$TPWS" ] || TPWS="$ZAPRET_BASE/tpws/tpws"
[ -n "$MDIG" ] || MDIG="$ZAPRET_BASE/mdig/mdig"
DESYNC_MARK=0x20000000
[ -n "$IPFW_RULE_NUM" ] || IPFW_RULE_NUM=1
[ -n "$IPFW_DIVERT_PORT" ] || IPFW_DIVERT_PORT=59780
[ -n "$DOMAINS" ] || DOMAINS=rutracker.org
[ -n "$CURL_MAX_TIME" ] || CURL_MAX_TIME=3
[ -n "$MIN_TTL" ] || MIN_TTL=1
[ -n "$MAX_TTL" ] || MAX_TTL=12
[ -n "$USER_AGENT" ] || USER_AGENT="Mozilla"

HDRTEMP=/tmp/zapret-hdr.txt

NFT_TABLE=blockcheck

[ -n "$DNSCHECK_DNS" ] || DNSCHECK_DNS="8.8.8.8 1.1.1.1 77.88.8.1"
[ -n "$DNSCHECK_DOM" ] || DNSCHECK_DOM="pornhub.com putinhuylo.com rutracker.org www.torproject.org bbc.com"
DNSCHECK_DIG1=/tmp/dig1.txt
DNSCHECK_DIG2=/tmp/dig2.txt
DNSCHECK_DIGS=/tmp/digs.txt


killwait()
{
	# $1 - signal (-9, -2, ...)
	# $2 - pid
	kill $1 $2
	# suppress job kill message
	wait $2 2>/dev/null
}

exitp()
{
	local A

	echo
	echo press enter to continue
	read A
	exit $1
}

IPT()
{
	$IPTABLES -C "$@" >/dev/null 2>/dev/null || $IPTABLES -I "$@"
}
IPT_DEL()
{
	$IPTABLES -C "$@" >/dev/null 2>/dev/null && $IPTABLES -D "$@"
}
IPFW_ADD()
{
	ipfw -qf add $IPFW_RULE_NUM "$@"
}
IPFW_DEL()
{
	ipfw -qf delete $IPFW_RULE_NUM 2>/dev/null
}
ipt6_has_raw()
{
	ip6tables -nL -t raw >/dev/null 2>/dev/null
}
ipt6_has_frag()
{
	ip6tables -A OUTPUT -m frag 2>/dev/null || return 1
	ip6tables -D OUTPUT -m frag 2>/dev/null
}
ipt_has_nfq()
{
	# cannot just check /proc/net/ip_tables_targets because of iptables-nft or modules not loaded yet
	iptables -A OUTPUT -t mangle -p 255 -j NFQUEUE --queue-num $QNUM --queue-bypass 2>/dev/null || return 1
	iptables -D OUTPUT -t mangle -p 255 -j NFQUEUE --queue-num $QNUM --queue-bypass 2>/dev/null
	return 0
}
nft_has_nfq()
{
	local res=1
	nft delete table ${NFT_TABLE}_test 2>/dev/null
	nft add table ${NFT_TABLE}_test 2>/dev/null && {
		nft add chain ${NFT_TABLE}_test test
		nft add rule ${NFT_TABLE}_test test queue num $QNUM bypass 2>/dev/null && res=0
		nft delete table ${NFT_TABLE}_test
	}
	return $res
}

check_system()
{
	echo \* checking system

	UNAME=$(uname)
	SUBSYS=
	local s

	# can be passed FWTYPE=iptables to override default nftables preference
	case "$UNAME" in
		Linux)
			PKTWS="$NFQWS"
			PKTWSD=nfqws
			linux_fwtype
			[ "$FWTYPE" = iptables -o "$FWTYPE" = nftables ] || {
				echo firewall type $FWTYPE not supported in $UNAME
				exitp 5
			}
			;;
		FreeBSD)
			PKTWS="$DVTWS"
			PKTWSD=dvtws
			FWTYPE=ipfw
			[ -f /etc/platform ] && read SUBSYS </etc/platform
			;;
		*)
			echo $UNAME not supported
			exitp 5
	esac
	echo $UNAME${SUBSYS:+/$SUBSYS} detected
	echo firewall type is $FWTYPE
}

freebsd_module_loaded()
{
	# $1 - module name
	kldstat -qm "${1}"
}
freebsd_modules_loaded()
{
	# $1,$2,$3, ... - module names
	while [ -n "$1" ]; do
		freebsd_module_loaded $1 || return 1
		shift
	done
	return 0
}

check_prerequisites()
{
	echo \* checking prerequisites
	
	[ -x "$PKTWS" ] && [ -x "$TPWS" ] && [ -x "$MDIG" ] || {
		echo $PKTWS or $TPWS or $MDIG is not available. run \"$ZAPRET_BASE/install_bin.sh\" or make -C \"$ZAPRET_BASE\"
		exitp 6
	}

	local prog progs='curl'
	case "$UNAME" in
		Linux)
			case "$FWTYPE" in
				iptables)
					progs="$progs iptables ip6tables"
					ipt_has_nfq || {
						echo NFQUEUE iptables or ip6tables target is missing. pls install modules.
						exitp 6
					}
					;;
				nftables)
					nft_has_nfq || {
						echo nftables queue support is not available. pls install modules.
						exitp 6
					}
					;;
			esac
			;;
		FreeBSD)
			progs="$progs ipfw"
			freebsd_modules_loaded ipfw ipdivert || {
				echo ipfw or ipdivert kernel module not loaded
				exitp 6
			}
			[ "$(sysctl -qn net.inet.ip.fw.enable)" = 0 -o "$(sysctl -qn net.inet6.ip6.fw.enable)" = 0 ] && {
				echo ipfw is disabled. use : ipfw enable firewall
				exitp 6
			}
			;;
	esac

	for prog in $progs; do
		exists $prog || {
			echo $prog does not exist. please install
			exitp 6
		}
	done

	if exists nslookup; then
		LOOKUP=nslookup
	elif exists host; then
		LOOKUP=host
	else
		echo nslookup or host does not exist. please install
		exitp 6
	fi
}


curl_translate_code()
{
	# $1 - code
	printf $1
	case $1 in
		0) printf ": ok"
		;;
		1) printf ": unsupported protocol"
		;;
		2) printf ": early initialization code failed"
		;;
		3) printf ": the URL was not properly formatted"
		;;
		4) printf ": feature not supported by libcurl"
		;;
		5) printf ": could not resolve proxy"
		;;
		6) printf ": could not resolve host"
		;;
		7) printf ": could not connect"
		;;
		8) printf ": invalid server reply"
		;;
		9) printf ": remote access denied"
		;;
		27) printf ": out of memory"
		;;
		28) printf ": operation timed out"
		;;
		35) printf ": SSL connect error"
		;;
	esac
}
curl_supports_tls13()
{
	local r
	curl --tlsv1.3 -Is -o /dev/null http://$LOCALHOST_IPT:65535 2>/dev/null
	# return code 2 = init failed. likely bad command line options
	[ $? = 2 ] && return 1
	# curl can have tlsv1.3 key present but ssl library without TLS 1.3 support
	# this is online test because there's no other way to trigger library incompatibility case
	curl --tlsv1.3 --max-time $CURL_MAX_TIME -Is -o /dev/null https://w3.org 2>/dev/null
	r=$?
	[ $r != 4 -a $r != 35 ]
}

curl_supports_tlsmax()
{
	# supported only in OpenSSL and LibreSSL
	curl --version | grep -Fq -e OpenSSL -e LibreSSL -e GnuTLS || return 1
	# supported since curl 7.54
	curl --tls-max 1.2 -Is -o /dev/null http://$LOCALHOST_IPT:65535 2>/dev/null
	# return code 2 = init failed. likely bad command line options
	[ $? != 2 ]
}

hdrfile_http_code()
{
	# $1 - hdr file
	sed -nre '1,1 s/^HTTP\/1\.[0,1] ([0-9]+) .*$/\1/p' "$1"
}
hdrfile_location()
{
	# $1 - hdr file

	# some DPIs return CRLF line ending
	tr -d '\015' <"$1" | sed -nre 's/^[Ll][Oo][Cc][Aa][Tt][Ii][Oo][Nn]:[ 	]*([^ 	]*)[ 	]*$/\1/p'
}
curl_test_http()
{
	# $1 - ip version : 4/6
	# $2 - domain name
	local code loc
	curl -${1}SsD "$HDRTEMP" --max-time $CURL_MAX_TIME $CURL_OPT "http://$2" -o /dev/null 2>&1 || {
		code=$?
		rm -f "$HDRTEMP"
		return $code
	}
	code=$(hdrfile_http_code "$HDRTEMP")
	[ "$code" = 301 -o "$code" = 302 -o "$code" = 307 -o "$code" = 308 ] && {
		loc=$(hdrfile_location "$HDRTEMP")
		echo "$loc" | grep -qE "^https?://.*$2(/|$)" ||
		echo "$loc" | grep -vqE '^https?://' || {
			echo suspicious redirection $code to : $loc
			rm -f "$HDRTEMP"
			return 254
		}
	}
	rm -f "$HDRTEMP"
	[ "$code" = 400 ] && {
		# this can often happen if the server receives fake packets it should not receive
		echo http code $code. likely the server receives fakes.
		return 254
	}
	return 0
}
curl_test_https_tls12()
{
	# $1 - ip version : 4/6
	# $2 - domain name

	# do not use tls 1.3 to make sure server certificate is not encrypted
	curl -${1}ISs -A "$USER_AGENT" --max-time $CURL_MAX_TIME $CURL_OPT --tlsv1.2 $TLSMAX12 "https://$2" -o /dev/null 2>&1 
}
curl_test_https_tls13()
{
	# $1 - ip version : 4/6
	# $2 - domain name

	# force TLS1.3 mode
	curl -${1}ISs -A "$USER_AGENT" --max-time $CURL_MAX_TIME $CURL_OPT --tlsv1.3 $TLSMAX13 "https://$2" -o /dev/null 2>&1 
}

pktws_ipt_prepare()
{
	# $1 - port
	case "$FWTYPE" in
		iptables)
			# to avoid possible INVALID state drop
			IPT INPUT -p tcp --sport $1 ! --syn -j ACCEPT
			IPT OUTPUT -p tcp --dport $1 -m conntrack --ctstate INVALID -j ACCEPT
			if [ "$IPV" = 6 -a -n "$IP6_DEFRAG_DISABLE" ]; then
				# the only way to reliable disable ipv6 defrag. works only in 4.16+ kernels
				IPT OUTPUT -t raw -p tcp -m frag -j CT --notrack
			elif [ "$IPV" = 4 ]; then
				# enable fragments
				IPT OUTPUT -f -j ACCEPT
			fi
			IPT POSTROUTING -t mangle -p tcp --dport $1 -m mark ! --mark $DESYNC_MARK/$DESYNC_MARK -j NFQUEUE --queue-num $QNUM
			;;
		nftables)
			nft add table inet $NFT_TABLE
			[ "$IPV" = 6 -a -n "$IP6_DEFRAG_DISABLE" ] && {
				nft "add chain inet $NFT_TABLE predefrag { type filter hook output priority -402; }"
				nft "add rule inet $NFT_TABLE predefrag meta nfproto ipv${IPV} exthdr frag exists notrack"
			}
			nft "add chain inet $NFT_TABLE premangle { type filter hook output priority -152; }"
			nft "add rule inet $NFT_TABLE premangle meta nfproto ipv${IPV} tcp dport $1 mark and 0x40000000 != 0x40000000 queue num $QNUM"
			;;
		ipfw)
			IPFW_ADD divert $IPFW_DIVERT_PORT tcp from me to any $1 proto ip${IPV} out not diverted not sockarg
			;;
	esac
}
pktws_ipt_unprepare()
{
	# $1 - port
	case "$FWTYPE" in
		iptables)
			IPT_DEL POSTROUTING -t mangle -p tcp --dport $1 -m mark ! --mark $DESYNC_MARK/$DESYNC_MARK -j NFQUEUE --queue-num $QNUM

			IPT_DEL INPUT -p tcp --sport $1 ! --syn -j ACCEPT
			IPT_DEL OUTPUT -p tcp --dport $1 -m conntrack --ctstate INVALID -j ACCEPT
			if [ "$IPV" = 6 -a -n "$IP6_DEFRAG_DISABLE" ]; then
				IPT_DEL OUTPUT -t raw -p tcp -m frag -j CT --notrack
			elif [ "$IPV" = 4 ]; then
				IPT_DEL OUTPUT -f -j ACCEPT
			fi
			;;
		nftables)
			nft delete table inet $NFT_TABLE 2>/dev/null
			;;
		ipfw)
			IPFW_DEL
			;;
	esac
}
tpws_ipt_prepare()
{
	# $1 - port
	case "$FWTYPE" in
		iptables)
			IPT OUTPUT -t nat -p tcp --dport $1 -m owner ! --uid-owner $TPWS_UID -j DNAT --to $LOCALHOST_IPT:$TPPORT
			;;
		nftables)
			nft add table inet $NFT_TABLE
			# -101 = pre dstnat
			nft "add chain inet $NFT_TABLE output { type nat hook output priority -102; }"
			nft "add rule inet $NFT_TABLE output tcp dport $1 skuid != $TPWS_UID dnat ip${IPVV} to $LOCALHOST_IPT:$TPPORT"
			;;
		ipfw)
			IPFW_ADD fwd $LOCALHOST,$TPPORT tcp from me to any $1 proto ip${IPV} not uid $TPWS_UID
			;;
	esac
}
tpws_ipt_unprepare()
{
	# $1 - port
	case "$FWTYPE" in
		iptables)
			IPT_DEL OUTPUT -t nat -p tcp --dport $1 -m owner ! --uid-owner $TPWS_UID -j DNAT --to $LOCALHOST_IPT:$TPPORT
			;;
		nftables)
			nft delete table inet $NFT_TABLE 2>/dev/null
			;;
		ipfw)
			IPFW_DEL
			;;
	esac
}
pktws_start()
{
	case "$UNAME" in
		Linux)
			"$NFQWS" --uid $TPWS_UID:$TPWS_GID --dpi-desync-fwmark=$DESYNC_MARK --qnum=$QNUM "$@" >/dev/null &
			;;
		FreeBSD)
			"$DVTWS" --port=$IPFW_DIVERT_PORT "$@" >/dev/null &
			;;
	esac
	PID=$!
	# give some time to initialize
	minsleep
}
tpws_start()
{
	"$TPWS" --uid $TPWS_UID:$TPWS_GID --bind-addr=$LOCALHOST --port=$TPPORT "$@" >/dev/null &
	PID=$!
	# give some time to initialize
	minsleep
}
ws_kill()
{
	[ -z "$PID" ] || {
		killwait -9 $PID 2>/dev/null
		PID=
	}
}

curl_test()
{
	# $1 - test function
	# $2 - domain
	local code=0 n=0

	while [ $n -lt $REPEATS ]; do
		n=$(($n+1))
		[ $REPEATS -gt 1 ] && printf "[attempt $n] "
		$1 "$IPV" $2 && {
			[ $REPEATS -gt 1 ] && echo 'AVAILABLE'
			continue
		}
		code=$?
	done
	if [ $code = 254 ]; then
		echo "UNAVAILABLE"
	elif [ $code = 0 ]; then
		echo '!!!!! AVAILABLE !!!!!'
	else
		echo "UNAVAILABLE code=$code"
	fi
	return $code
}
ws_curl_test()
{
	# $1 - ws start function
	# $2 - test function
	# $3 - domain
	# $4,$5,$6, ... - ws params
	local code ws_start=$1 testf=$2 dom=$3
	shift
	shift
	shift
	$ws_start "$@"
	curl_test $testf $dom
	code=$?
	ws_kill
	return $code
}
tpws_curl_test()
{
	# $1 - test function
	# $2 - domain
	# $3,$4,$5, ... - tpws params
	echo - checking tpws $3 $4 $5 $6 $7 $8 $9
	ws_curl_test tpws_start "$@"
}
pktws_curl_test()
{
	# $1 - test function
	# $2 - domain
	# $3,$4,$5, ... - nfqws/dvtws params
	echo - checking $PKTWSD $3 $4 $5 $6 $7 $8 $9
	ws_curl_test pktws_start "$@"
}
xxxws_curl_test_update()
{
	# $1 - xxx_curl_test function
	# $2 - test function
	# $3 - domain
	# $4,$5,$6, ... - nfqws/dvtws params
	local code xxxf=$1 testf=$2 dom=$3
	shift
	shift
	shift
	$xxxf $testf $dom "$@"
	code=$?
	[ $code = 0 ] && strategy="${strategy:-$@}"
	return $code
}
pktws_curl_test_update()
{
	xxxws_curl_test_update pktws_curl_test "$@"
}
tpws_curl_test_update()
{
	xxxws_curl_test_update tpws_curl_test "$@"
}

report_append()
{
	NREPORT=${NREPORT:-0}
	eval REPORT_${NREPORT}=\"$@\"
	NREPORT=$(($NREPORT+1))
}
report_print()
{
	local n=0 s
	NREPORT=${NREPORT:-0}
	while [ $n -lt $NREPORT ]; do
		eval s=\"\${REPORT_$n}\"
		echo $s
		n=$(($n+1))
	done
}
report_strategy()
{
	# $1 - test function
	# $2 - domain
	# $3 - daemon
	echo
	if [ -n "$strategy" ]; then
		echo "!!!!! $1: working strategy found for ipv${IPV} $2 : $3 $strategy !!!!!"
		echo
		report_append "ipv${IPV} $2 $1 : $3 $strategy"
		return 0
	else
		echo "$1: $3 strategy for ipv${IPV} $2 not found"
		echo
		report_append "ipv${IPV} $2 $1 : $3 not working"
		return 1
	fi
}
pktws_check_domain_bypass()
{
	# $1 - test function
	# $2 - encrypted test : 1/0
	# $3 - domain

	local strategy tests='fake' ret ok ttls s f e desync pos fooling frag sec="$2"

	[ "$sec" = 0 ] && {
		for s in '--hostcase' '--hostspell=hoSt' '--hostnospace' '--domcase'; do
			pktws_curl_test_update $1 $3 $s
		done
	}

	s="--dpi-desync=split2"
	ok=0
	pktws_curl_test_update $1 $3 $s
	ret=$?
	[ "$ret" = 0 ] && ok=1
	[ "$ret" != 0 -o "$FORCE" = 1 ] && {
		[ "$sec" = 0 ] && pktws_curl_test_update $1 $3 $s --hostcase
		for pos in 1 3 4 5 10 50 100; do
			s="--dpi-desync=split2 --dpi-desync-split-pos=$pos"
			if pktws_curl_test_update $1 $3 $s; then
				ok=1
				break
			elif [ "$sec" = 0 ]; then
				pktws_curl_test_update $1 $3 $s --hostcase
			fi
		done
	}
	[ "$ok" = 1 ] || tests="$tests split fake,split2 fake,split"

	pktws_curl_test_update $1 $3 --dpi-desync=disorder2
	[ "$?" != 0 -o "$FORCE" = 1 ] && tests="$tests disorder fake,disorder2 fake,disorder"

	ttls=$(seq -s ' ' $MIN_TTL $MAX_TTL)
	for e in '' '--wssize 1:6'; do
		[ -n "$e" ] && {
			pktws_curl_test_update $1 $3 $e
			for desync in split2 disorder2; do
				pktws_curl_test_update $1 $3 --dpi-desync=$desync $e
			done
		}
		for desync in $tests; do
			s="--dpi-desync=$desync"
			for ttl in $ttls; do
				pktws_curl_test_update $1 $3 $s --dpi-desync-ttl=$ttl $e && break
			done
			f="badsum badseq md5sig"
			[ "$IPV" = 6 ] && f="$f hopbyhop hopbyhop2"
			for fooling in $f; do
				pktws_curl_test_update $1 $3 $s --dpi-desync-fooling=$fooling $e && [ "$fooling" = "md5sig" ] &&
					echo 'WARNING ! although md5sig fooling worked it will not work on all sites. it typically works only on linux servers.'
			done
		done
		[ "$IPV" = 6 ] && {
			f="hopbyhop hopbyhop,split2 hopbyhop,disorder2 destopt destopt,split2 destopt,disorder2"
			[ -n "$IP6_DEFRAG_DISABLE" ] && f="$f ipfrag1 ipfrag1,split2 ipfrag1,disorder2"
			for desync in $f; do
				pktws_curl_test_update $1 $3 --dpi-desync=$desync $e
			done
		}
		# do not do wssize test for http. it's useless
		[ "$sec" = 1 ] || break
	done

	[ "$IPV" = 4 -o -n "$IP6_DEFRAG_DISABLE" ] && {
		for frag in 24 32 40 64 80 104; do
			tests="ipfrag2"
			[ "$IPV" = 6 ] && tests="$tests hopbyhop,ipfrag2 destopt,ipfrag2"
			for desync in $tests; do
				pktws_curl_test_update $1 $3 --dpi-desync=$desync --dpi-desync-ipfrag-pos-tcp=$frag
			done
		done
	}

	report_strategy $1 $3 $PKTWSD
}
tpws_check_domain_bypass()
{
	# $1 - test function
	# $2 - encrypted test : 1/0
	# $3 - domain
	local s s2 pos strategy sec="$2"
	if [ "$sec" = 0 ]; then
		for s in '--hostcase' '--hostspell=hoSt' '--hostdot' '--hosttab' '--hostnospace' '--methodspace' '--methodeol' '--unixeol' \
			'--hostpad=1024' '--hostpad=2048' '--hostpad=4096' '--hostpad=8192' '--hostpad=16384' ; do
			tpws_curl_test_update $1 $3 $s
		done
		for s2 in '' '--disorder'; do
			for s in '--split-http-req=method' '--split-http-req=method --hostcase' '--split-http-req=host' '--split-http-req=host --hostcase' ; do
				tpws_curl_test_update $1 $3 $s $s2
			done
		done
	else
		for s2 in '' '--disorder'; do
			for pos in 1 2 3 4 5 10 50 100; do
				s="--split-pos=$pos"
				tpws_curl_test_update $1 $3 $s $s2 && break
			done
		done
		for s2 in '--tlsrec=sni' '--tlsrec=sni --split-pos=10' '--tlsrec=sni --split-pos=10 --disorder'; do
			tpws_curl_test_update $1 $3 $s2 && [ "$FORCE" != 1 ] && break
		done
	fi
	report_strategy $1 $3 tpws
}

check_domain()
{
	# $1 - test function
	# $2 - port
	# $3 - encrypted test : 1/0
	# $4 - domain

	local code c

	echo
	echo \* $1 ipv$IPV $4

	# in case was interrupted before
	pktws_ipt_unprepare $2
	tpws_ipt_unprepare $2
	ws_kill

	echo "- checking without DPI bypass"
	curl_test $1 $4 && {
		report_append "ipv${IPV} $4 $1 : working without bypass"
		[ "$FORCE" = 1 ] || return
	}
	code=$?
	for c in 1 2 3 4 6 27 ; do
		[ $code = $c ] && {
			report_append "ipv${IPV} $4 $1 : test aborted, no reason to continue. curl code $(curl_translate_code $code)"
			return
		}
	done

	echo
	if [ "$SUBSYS" = "pfSense" ] ; then
		echo "tpws tests are not possible on pfSense"
		report_append "ipv${IPV} $4 $1 : automated tpws tests are not possible on pfSense. check docs/bsd.txt"
	else
		echo preparing tpws redirection
		tpws_ipt_prepare $2

		tpws_check_domain_bypass $1 $3 $4

		echo clearing tpws redirection
		tpws_ipt_unprepare $2
	fi

	echo

	echo preparing $PKTWSD redirection
	pktws_ipt_prepare $2

	pktws_check_domain_bypass $1 $3 $4

	echo clearing $PKTWSD redirection
	pktws_ipt_unprepare $2
}
check_domain_http()
{
	# $1 - domain
	check_domain curl_test_http 80 0 $1
}
check_domain_https_tls12()
{
	# $1 - domain
	check_domain curl_test_https_tls12 443 1 $1
}
check_domain_https_tls13()
{
	# $1 - domain
	check_domain curl_test_https_tls13 443 1 $1
}

configure_ip_version()
{
	if [ "$IPV" = 6 ]; then
		LOCALHOST=::1
		LOCALHOST_IPT=[${LOCALHOST}]
		IPVV=6
	else
		IPTABLES=iptables
		LOCALHOST=127.0.0.1
		LOCALHOST_IPT=$LOCALHOST
		IPVV=
	fi
	IPTABLES=ip${IPVV}tables
}
configure_curl_opt()
{
	# wolfssl : --tlsv1.x mandates exact ssl version, tls-max not supported
	# openssl : --tlsv1.x means "version equal or greater", tls-max supported
	TLSMAX12=
	TLSMAX13=
	curl_supports_tlsmax && {
		TLSMAX12="--tls-max 1.2"
		TLSMAX13="--tls-max 1.3"
	}
	TLS13=
	curl_supports_tls13 && TLS13=1
}

linux_ipv6_defrag_can_be_disabled()
{
	linux_min_version 4 16
}

configure_defrag()
{
	IP6_DEFRAG_DISABLE=

	[ "$IPVS" = 4 ] && return

	[ "$UNAME" = "Linux" ] && {
		linux_ipv6_defrag_can_be_disabled || {
			echo "WARNING ! ipv6 defrag can only be effectively disabled in linux kernel 4.16+"
			echo "WARNING ! ipv6 ipfrag tests are disabled"
			echo
			return
		}
	}

	case "$FWTYPE" in
		iptables)
			if ipt6_has_raw ; then
				if ipt6_has_frag; then
					IP6_DEFRAG_DISABLE=1
				else
					echo "WARNING ! ip6tables does not have '-m frag' module, ipv6 ipfrag tests are disabled"
					echo
				fi
			else
				echo "WARNING ! ip6tables raw table is not available, ipv6 ipfrag tests are disabled"
				echo
			fi
			[ -n "$IP6_DEFRAG_DISABLE" ] && {
				local ipexe="$(readlink -f $(whichq ip6tables))"
				if contains "$ipexe" nft; then
					echo "WARNING ! ipv6 ipfrag tests may have no effect if ip6tables-nft is used. current ip6tables point to : $ipexe"
				else
					echo "WARNING ! ipv6 ipfrag tests may have no effect if ip6table_raw kernel module is not loaded with parameter : raw_before_defrag=1"
				fi
				echo
			}
			;;
		*)
			IP6_DEFRAG_DISABLE=1
			;;
	esac
}

ask_params()
{
	echo
	echo NOTE ! this test should be run with zapret or any other bypass software disabled, without VPN
	echo

	echo "specify domain(s) to test. multiple domains are space separated."
	printf "domain(s) (default: $DOMAINS) : "
	local dom
	read dom
	[ -n "$dom" ] && DOMAINS="$dom"

	printf "ip protocol version(s) - 4, 6 or 46 for both (default: 4) : "
	read IPVS
	[ -n "$IPVS" ] || IPVS=4
	[ "$IPVS" = 4 -o "$IPVS" = 6 -o "$IPVS" = 46 ] || {
		echo 'invalid ip version(s). should be 4, 6 or 46.'
		exitp 1
	}
	[ "$IPVS" = 46 ] && IPVS="4 6"

	configure_curl_opt

	ENABLE_HTTP=1
	ask_yes_no_var ENABLE_HTTP "check http"

	ENABLE_HTTPS_TLS12=1
	ask_yes_no_var ENABLE_HTTPS_TLS12 "check https tls 1.2"

	ENABLE_HTTPS_TLS13=0
	echo
	if [ -n "$TLS13" ]; then
		echo "TLS 1.3 is the new standard for encrypted communications over TCP"
		echo "its the most important feature for DPI bypass is encrypted TLS ServerHello"
		echo "more and more sites enable TLS 1.3 but still there're many sites with only TLS 1.2 support"
		echo "with TLS 1.3 more DPI bypass strategies can work but they may not apply to all sites"
		echo "if a strategy works with TLS 1.2 it will also work with TLS 1.3"
		echo "if nothing works with TLS 1.2 this test may find TLS1.3 only strategies"
		echo "make sure that $DOMAINS support TLS 1.3 otherwise all test will return an error"
		ask_yes_no_var ENABLE_HTTPS_TLS13 "check https tls 1.3"
	else
		echo "installed curl version does not support TLS 1.3 . tests disabled."
	fi

	IGNORE_CA=0
	CURL_OPT=
	[ $ENABLE_HTTPS_TLS13 = 1 -o $ENABLE_HTTPS_TLS12 = 1 ] && {
		echo
		echo "on limited systems like openwrt CA certificates might not be installed to preserve space"
		echo "in such a case curl cannot verify server certificate and you should either install ca-bundle or disable verification"
		echo "however disabling verification will break https check if ISP does MitM attack and substitutes server certificate"
		ask_yes_no_var IGNORE_CA "do not verify server certificate"
		[ "$IGNORE_CA" = 1 ] && CURL_OPT=-k
	}

	echo
	echo "sometimes ISPs use multiple DPIs or load balancing. bypass strategies may work unstable."
	printf "how many times to repeat each test (default: 1) : "
	read REPEATS
	REPEATS=$((0+${REPEATS:-1}))
	[ "$REPEATS" = 0 ] && {
		echo invalid repeat count
		exitp 1
	}

	echo
	FORCE=0
	ask_yes_no_var FORCE "do all tests despite of result ?"

	echo

	configure_defrag
}



pingtest()
{
	ping -c 1 -W 1 $1 >/dev/null
}
dnstest()
{
	# $1 - dns server. empty for system resolver
	"$LOOKUP" w3.org $1 >/dev/null 2>/dev/null
}
find_working_public_dns()
{
	local dns
	for dns in $DNSCHECK_DNS; do
		pingtest $dns && dnstest $dns && {
			PUBDNS=$dns
			return 0
		}
	done
	return 1
}
lookup4()
{
	# $1 - domain
	# $2 - DNS
	case "$LOOKUP" in
		nslookup)
			nslookup $1 $2 | sed -n '/Name:/,$p' | grep ^Address | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'
			;;
		host)
			host -t A $1 $2 | grep "has address" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'
			;;
	esac
}
check_dns_spoof()
{
	# $1 - domain
	# $2 - public DNS
	echo $1 | "$MDIG" --family=4 >"$DNSCHECK_DIG1"
	lookup4 $1 $2 >"$DNSCHECK_DIG2"
	# check whether system resolver returns anything other than public DNS
	grep -qvFf "$DNSCHECK_DIG2" "$DNSCHECK_DIG1"
}
check_dns_cleanup()
{
	rm -f "$DNSCHECK_DIG1" "$DNSCHECK_DIG2" "$DNSCHECK_DIGS" 2>/dev/null
}
check_dns()
{
	local C1 C2 dom

	echo \* checking DNS

	[ -f "$DNSCHECK_DIGS" ] && rm -f "$DNSCHECK_DIGS"

	dnstest || {
		echo -- DNS is not working. It's either misconfigured or blocked or you don't have inet access.
		return 1
	}
	echo system DNS is working

	if find_working_public_dns ; then
		echo comparing system resolver to public DNS : $PUBDNS
		for dom in $DNSCHECK_DOM; do
			if check_dns_spoof $dom $PUBDNS ; then
				echo $dom : MISMATCH
				echo -- system resolver :
				cat "$DNSCHECK_DIG1"
				echo -- $PUBDNS :
				cat "$DNSCHECK_DIG2"
				check_dns_cleanup
				echo -- POSSIBLE DNS HIJACK DETECTED. ZAPRET WILL NOT HELP YOU IN CASE DNS IS SPOOFED !!!
				echo -- DNS CHANGE OR DNSCRYPT MAY BE REQUIRED
				return 1
			else
				echo $dom : OK
				cat "$DNSCHECK_DIG1" >>"$DNSCHECK_DIGS"
			fi
		done
	else
		echo no working public DNS was found. looks like public DNS blocked.
		for dom in $DNSCHECK_DOM; do echo $dom; done | "$MDIG" --threads=10 --family=4 >"$DNSCHECK_DIGS"
	fi

	echo checking resolved IP uniqueness for : $DNSCHECK_DOM
	echo censor\'s DNS can return equal result for multiple blocked domains.
	C1=$(wc -l <"$DNSCHECK_DIGS")
	C2=$(sort -u "$DNSCHECK_DIGS" | wc -l)
	[ "$C1" -eq 0 ] &&
	{
		echo -- DNS is not working. It's either misconfigured or blocked or you don't have inet access.
		check_dns_cleanup
		return 1
	}
	[ "$C1" = "$C2" ] ||
	{
		echo system dns resolver has returned equal IPs for some domains checked above \($C1 total, $C2 unique\)
		echo non-unique IPs :
		sort "$DNSCHECK_DIGS" | uniq -d
		echo -- POSSIBLE DNS HIJACK DETECTED. ZAPRET WILL NOT HELP YOU IN CASE DNS IS SPOOFED !!!
		echo -- DNSCRYPT MAY BE REQUIRED
		check_dns_cleanup
		return 1
	}
	echo all resolved IPs are unique
	echo -- DNS looks good
	echo -- NOTE this check is Russia targeted. In your country other domains may be blocked.
	check_dns_cleanup
	return 0
}


unprepare_all()
{
	# make sure we are not in a middle state that impacts connectivity
	rm -f "$HDRTEMP"
	[ -n "$IPV" ] && {
		tpws_ipt_unprepare 80
		tpws_ipt_unprepare 443
		pktws_ipt_unprepare 80
		pktws_ipt_unprepare 443
	}
	ws_kill
}
sigint()
{
	echo
	echo terminating...
	unprepare_all
	exitp 1
}
sigpipe()
{
	# must not write anything here to stdout
	unprepare_all
	exit 1
}

fsleep_setup
fix_sbin_path
check_system
require_root
check_prerequisites
check_dns
check_virt
ask_params

PID=
NREPORT=
trap sigint INT
trap sigpipe PIPE
for dom in $DOMAINS; do
	for IPV in $IPVS; do
		configure_ip_version
		[ "$ENABLE_HTTP" = 1 ] && check_domain_http $dom
		[ "$ENABLE_HTTPS_TLS12" = 1 ] && check_domain_https_tls12 $dom
		[ "$ENABLE_HTTPS_TLS13" = 1 ] && check_domain_https_tls13 $dom
	done
done
trap - PIPE
trap - INT

echo
echo \* SUMMARY
report_print

exitp 0
