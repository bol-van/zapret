#!/bin/sh

EXEDIR="$(dirname "$0")"
EXEDIR="$(cd "$EXEDIR"; pwd)"
ZAPRET_BASE="$EXEDIR"

[ -n "$QNUM" ] || QNUM=59780
[ -n "$TPPORT" ] || TPPORT=993
[ -n "$TPWS_UID" ] || TPWS_UID=1
[ -n "$NFQWS" ] || NFQWS="$ZAPRET_BASE/nfq/nfqws"
[ -n "$DVTWS" ] || DVTWS="$ZAPRET_BASE/nfq/dvtws"
[ -n "$TPWS" ] || TPWS="$ZAPRET_BASE/tpws/tpws"
[ -n "$MDIG" ] || MDIG="$ZAPRET_BASE/mdig/mdig"
[ -n "$DESYNC_MARK" ] || DESYNC_MARK=0x40000000
[ -n "$IPFW_RULE_NUM" ] || IPFW_RULE_NUM=1
[ -n "$IPFW_DIVERT_PORT" ] || IPFW_DIVERT_PORT=59780
[ -n "$DOMAIN" ] || DOMAIN=rutracker.org
[ -n "$CURL_MAX_TIME" ] || CURL_MAX_TIME=5
[ -n "$MIN_TTL" ] || MIN_TTL=1
[ -n "$MAX_TTL" ] || MAX_TTL=12

HDRTEMP=/tmp/zapret-hdr.txt
ECHON="echo -n"

DNSCHECK_DNS="8.8.8.8 1.1.1.1 77.88.8.1"
DNSCHECK_DOM="pornhub.com putinhuylo.com rutracker.org nnmclub.to startmail.com"
DNSCHECK_DIG1=/tmp/dig1.txt
DNSCHECK_DIG2=/tmp/dig2.txt
DNSCHECK_DIGS=/tmp/digs.txt


exists()
{
	which $1 >/dev/null 2>/dev/null
}
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

read_yes_no()
{
	# $1 - default (Y/N)
	local A
	read A
	[ -z "$A" ] || ([ "$A" != "Y" ] && [ "$A" != "y" ] && [ "$A" != "N" ] && [ "$A" != "n" ]) && A=$1
	[ "$A" = "Y" ] || [ "$A" = "y" ] || [ "$A" = "1" ]
}
ask_yes_no()
{
	# $1 - default (Y/N or 0/1)
	# $2 - text
	local DEFAULT=$1
	[ "$1" = "1" ] && DEFAULT=Y
	[ "$1" = "0" ] && DEFAULT=N
	[ -z "$DEFAULT" ] && DEFAULT=N
	$ECHON "$2 (default : $DEFAULT) (Y/N) ? "
	read_yes_no $DEFAULT
}
ask_yes_no_var()
{
	# $1 - variable name for answer : 0/1
	# $2 - text
	local DEFAULT
	eval DEFAULT="\$$1"
	if ask_yes_no "$DEFAULT" "$2"; then
		eval $1=1
	else
		eval $1=0
	fi
}


require_root()
{
	local exe
	echo \* checking privileges
	[ $(id -u) -ne "0" ] && {
		echo root is required
		exe="$EXEDIR/$(basename "$0")"
		exists sudo && exec sudo "$exe"
		exists su && exec su root -c "$exe"
		echo su or sudo not found
		exitp 2
	}
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
	ipfw -qf delete $IPFW_RULE_NUM
}


check_system()
{
	echo \* checking system

	UNAME=$(uname)
	case "$UNAME" in
		Linux)
			PKTWS="$NFQWS"
			PKTWSD=nfqws
			;;
		FreeBSD)
			PKTWS="$DVTWS"
			PKTWSD=dvtws
			;;
		*)
			echo $UNAME not supported
			exitp 5
	esac
}

freebsd_module_loaded()
{
	# $1 - module name
	kldstat | grep -q "${1}.ko"
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

	local progs='curl'
	case "$UNAME" in
		Linux)
			progs="$progs iptables ip6tables"
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

curl_supports_tls13()
{
	curl --tlsv1.3 -Is -o /dev/null http://$LOCALHOST_IPT:65535 2>/dev/null
	# return code 2 = init failed. likely bad command line options
	[ $? = 2 ] && return 1
	# curl can have tlsv1.3 key present but ssl library without TLS 1.3 support
	# this is online test because there's no other way to trigger library incompatibility case
	curl --tlsv1.3 -Is -o /dev/null https://w3.org 2>/dev/null
	[ $? != 4 ]
}
curl_supports_tlsmax()
{
	# supported only in OpenSSL
	curl --version | grep -q OpenSSL || return 1
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
	tr -d '\015' <"$1" | sed -nre 's/^[Ll][Oo][Cc][Aa][Tt][Ii][Oo][Nn]:[ \t]*([^ \t]*)[ \t]*$/\1/p'
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
			echo suspicious redirection to : $loc
			rm -f "$HDRTEMP"
			return 254
		}
	}
	rm -f "$HDRTEMP"
	return 0
}
curl_test_https_tls12()
{
	# $1 - ip version : 4/6
	# $2 - domain name

	# prevent using QUIC if available in curl
	# do not use tls 1.3 to make sure server certificate is not encrypted
	curl -${1}Ss --max-time $CURL_MAX_TIME $CURL_OPT --http1.1 --tlsv1.2 $TLSMAX12 "https://$2" -o /dev/null 2>&1 
}
curl_test_https_tls13()
{
	# $1 - ip version : 4/6
	# $2 - domain name

	# prevent using QUIC if available in curl
	# force TLS1.3 mode
	curl -${1}Ss --max-time $CURL_MAX_TIME $CURL_OPT --http1.1 --tlsv1.3 $TLSMAX13 "https://$2" -o /dev/null 2>&1 
}

pktws_ipt_prepare()
{
	# $1 - port
	case "$UNAME" in
		Linux)
			IPT POSTROUTING -t mangle -p tcp --dport $1 -m mark ! --mark $DESYNC_MARK/$DESYNC_MARK -j NFQUEUE --queue-num $QNUM
			;;
		FreeBSD)
			IPFW_ADD divert $IPFW_DIVERT_PORT tcp from me to any 80,443 out not diverted not sockarg
			;;
	esac
}
pktws_ipt_unprepare()
{
	# $1 - port
	case "$UNAME" in
		Linux)
			IPT_DEL POSTROUTING -t mangle -p tcp --dport $1 -m mark ! --mark $DESYNC_MARK/$DESYNC_MARK -j NFQUEUE --queue-num $QNUM
			;;
		FreeBSD)
			IPFW_DEL
			;;
	esac
}
tpws_ipt_prepare()
{
	# $1 - port
	case "$UNAME" in
		Linux)
			IPT OUTPUT -t nat -p tcp --dport $1 -m owner ! --uid-owner $TPWS_UID -j DNAT --to $LOCALHOST_IPT:$TPPORT
			;;
		FreeBSD)
			if [ "$IPV" = 4 ]; then
				IPFW_ADD fwd 127.0.0.1,$TPPORT tcp from me to any 80,443 proto ip4 not uid $TPWS_UID
			else
				IPFW_ADD fwd ::1,$TPPORT tcp from me to any 80,443 proto ip6 not uid $TPWS_UID
			fi
			;;
	esac
}
tpws_ipt_unprepare()
{
	# $1 - port
	case "$UNAME" in
		Linux)
			IPT_DEL OUTPUT -t nat -p tcp --dport $1 -m owner ! --uid-owner $TPWS_UID -j DNAT --to $LOCALHOST_IPT:$TPPORT
			;;
		FreeBSD)
			IPFW_DEL
			;;
	esac
}
pktws_start()
{
	case "$UNAME" in
		Linux)
			"$NFQWS" --dpi-desync-fwmark=$DESYNC_MARK --qnum=$QNUM "$@" >/dev/null &
			;;
		FreeBSD)
			"$DVTWS" --port=$IPFW_DIVERT_PORT "$@" >/dev/null &
			;;
	esac
	PID=$!
}
tpws_start()
{
	"$TPWS" --uid $TPWS_UID:$TPWS_UID --bind-addr=$LOCALHOST --port=$TPPORT "$@" >/dev/null &
	PID=$!
	# give some time to initialize
	sleep 1
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
		[ $REPEATS -gt 1 ] && $ECHON "[attempt $n] "
		$1 $IPV $2 && {
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

pktws_check_domain_bypass()
{
	# $1 - test function
	# $2 - encrypted test : 1/0
	# $3 - domain

	local strategy tests='fake' ttls s sec="$2"

	[ "$sec" = 0 ] && {
		for s in '--hostcase' '--hostspell=hoSt' '--hostnospace' '--domcase'; do
			pktws_curl_test_update $1 $3 $s
		done
	}

	s="--dpi-desync=split2"
	pktws_curl_test_update $1 $3 $s || {
		tests="$tests split fake,split2 fake,split"
		[ "$sec" = 0 ] && pktws_curl_test_update $1 $3 $s --hostcase
		for pos in 1 3 4 5 10 50 100; do
			s="--dpi-desync=split2 --dpi-desync-split-pos=$pos"
			if pktws_curl_test_update $1 $3 $s; then
				break
			elif [ "$sec" = 0 ]; then
				pktws_curl_test_update $1 $3 $s --hostcase
			fi
		done
	}

	pktws_curl_test_update $1 $3 --dpi-desync=disorder2 || tests="$tests disorder fake,disorder2 fake,disorder"

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
			for fooling in badsum badseq md5sig; do
				pktws_curl_test_update $1 $3 $s --dpi-desync-fooling=$fooling $e && [ "$fooling" = "md5sig" ] &&
					echo 'WARNING ! although md5sig fooling worked it will not work on all sites. it typically works only on linux servers.'
			done
		done
		# do not do wssize test for http. it's useless
		[ "$sec" = 1 ] || break
	done

	echo
	if [ -n "$strategy" ]; then
		echo "!!!!! working strategy found : $PKTWSD $strategy !!!!!"
		return 0
	else
		echo 'working strategy not found'
		return 1
	fi
}
tpws_check_domain_bypass()
{
	# $1 - test function
	# $2 - encrypted test : 1/0
	# $3 - domain
	local s strategy sec="$2"
	if [ "$sec" = 0 ]; then
		for s in '--hostcase' '--hostspell=hoSt' '--split-http-req=method' '--split-http-req=method --hostcase' '--split-http-req=host' '--split-http-req=host --hostcase' \
			'--hostdot' '--hosttab' '--hostnospace' '--methodspace' '--methodeol' '--unixeol' \
			'--hostpad=1024' '--hostpad=2048' '--hostpad=4096' '--hostpad=8192' '--hostpad=16384'; do
			tpws_curl_test_update $1 $3 $s
		done
	else
		for pos in 1 2 3 4 5 10 50 100; do
			s="--split-pos=$pos"
			tpws_curl_test_update $1 $3 $s && break
		done
	fi
	echo
	if [ -n "$strategy" ]; then
		echo "!!!!! working strategy found : tpws $strategy !!!!!"
		return 0
	else
		echo 'working strategy not found'
		return 1
	fi
}

check_domain()
{
	# $1 - test function
	# $2 - port
	# $3 - encrypted test : 1/0
	# $4 - domain

	local code

	echo
	echo \* $1 $4

	# in case was interrupted before
	pktws_ipt_unprepare $2
	tpws_ipt_unprepare $2
	ws_kill

	echo "- checking without DPI bypass"
	curl_test $1 $4 && return
	code=$?
	for c in 1 2 3 4 6 27 ; do
		[ $code = $c ] && return
	done

	echo

	echo preparing tpws redirection
	tpws_ipt_prepare $2

	tpws_check_domain_bypass $1 $3 $4

	echo clearing tpws redirection
	tpws_ipt_unprepare $2

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
		IPTABLES=ip6tables
		LOCALHOST=::1
		LOCALHOST_IPT=[::1]
	else
		IPTABLES=iptables
		LOCALHOST=127.0.0.1
		LOCALHOST_IPT=127.0.0.1
	fi
}
configure_curl_opt()
{
	TLSMAX12=
	TLSMAX13=
	curl_supports_tlsmax && {
		TLSMAX12="--tls-max 1.2"
		TLSMAX13="--tls-max 1.3"
	}
	TLS13=
	curl_supports_tls13 && TLS13=1
}

ask_params()
{
	echo
	echo NOTE ! this test should be run with zapret or any other bypass software disabled, without VPN

	$ECHON "test this domain (default: $DOMAIN) : "
	local dom
	read dom
	[ -n "$dom" ] && DOMAIN=$dom

	$ECHON "ip protocol version - 4 or 6 (default: 4) : "
	read IPV
	[ -n "$IPV" ] || IPV=4
	[ "$IPV" = 4 -o "$IPV" = 6 ] || {
		echo invalid ip version. should be 4 or 6.
		exitp 1
	}
	configure_ip_version
	configure_curl_opt

	ENABLE_HTTP=1
	ask_yes_no_var ENABLE_HTTP "check http"

	[ -n "$TLSMAX12" ] || echo "WARNING ! your curl version or TLS library does not support tls-max option. TLS 1.2 tests may use TLS 1.3+ protocols"

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
		echo "make sure that $DOMAIN supports TLS 1.3 otherwise all test will return an error"
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
	$ECHON "how many times to repeat each test (default: 1) : "
	read REPEATS
	REPEATS=$((0+${REPEATS:-1}))
	[ "$REPEATS" = 0 ] && {
		echo invalid repeat count
		exitp 1
	}

	echo
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
	local C1 C2

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
	# make sure we are not in a middle state that impacts connectivity
	echo
	echo terminating...
	unprepare_all
	exitp 1
}
sigpipe()
{
	# make sure we are not in a middle state that impacts connectivity
	# must not write anything here to stdout
	unprepare_all
	exit 1
}

check_system
check_prerequisites
require_root
check_dns
ask_params

PID=
trap sigint INT
trap sigpipe PIPE
[ "$ENABLE_HTTP" = 1 ] && check_domain_http $DOMAIN
[ "$ENABLE_HTTPS_TLS12" = 1 ] && check_domain_https_tls12 $DOMAIN
[ "$ENABLE_HTTPS_TLS13" = 1 ] && check_domain_https_tls13 $DOMAIN
trap - PIPE
trap - INT

exitp 0
