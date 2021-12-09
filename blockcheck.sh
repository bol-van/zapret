#!/bin/sh

EXEDIR="$(dirname "$0")"
EXEDIR="$(cd "$EXEDIR"; pwd)"
ZAPRET_BASE="$EXEDIR"

[ -n "$QNUM" ] || QNUM=59780
[ -n "$TPPORT" ] || TPPORT=993
[ -n "$TPWS_UID" ] || TPWS_UID=1
[ -n "$NFQWS" ] || NFQWS="$ZAPRET_BASE/nfq/nfqws"
[ -n "$TPWS" ] || TPWS="$ZAPRET_BASE/tpws/tpws"
[ -n "$MDIG" ] || MDIG="$ZAPRET_BASE/mdig/mdig"
[ -n "$DESYNC_MARK" ] || DESYNC_MARK=0x40000000
DOMAIN=rutracker.org
CURL_MAX_TIME=5
MIN_TTL=1
MAX_TTL=12
HDRTEMP=/tmp/zapret-hdr.txt
ECHON="echo -n"

DNSCHECK_DNS="8.8.8.8 1.1.1.1 77.88.8.8"
DNSCHECK_DOM="pornhub.com putinhuylo.com rutracker.org nnmclub.to protonmail.com"
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
	echo \* checking privileges
	[ $(id -u) -ne "0" ] && {
		echo root is required
		exists sudo && exec sudo "$0"
		exists su && exec su -c "$0"
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


check_system()
{
	echo \* checking system

	local UNAME=$(uname)
	[ "$UNAME" = "Linux" ] || {
		echo $UNAME not supported
		exitp 5
	}
}

check_prerequisites()
{
	echo \* checking prerequisites

	[ -x "$NFQWS" ] && [ -x "$TPWS" ] && [ -x "$MDIG" ] || {
		echo $NFQWS or $MDIG or $TPWS is not available. run $ZAPRET_BASE/install_bin.sh
		exitp 6
	}

	for prog in iptables ip6tables curl; do
		exists $prog || {
			echo $prog does not exist. please install
			exitp 6
		}
	done
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
curl_test_https()
{
	# $1 - ip version : 4/6
	# $2 - domain name

	# prevent using QUIC if available in curl
	curl -${1}Ss --max-time $CURL_MAX_TIME $CURL_OPT --http1.1 "https://$2" -o /dev/null 2>&1 
}

nfqws_ipt_prepare()
{
	# $1 - port
	IPT POSTROUTING -t mangle -p tcp --dport $1 -m mark ! --mark $DESYNC_MARK/$DESYNC_MARK -j NFQUEUE --queue-num $QNUM
}
nfqws_ipt_unprepare()
{
	# $1 - port
	IPT_DEL POSTROUTING -t mangle -p tcp --dport $1 -m mark ! --mark $DESYNC_MARK/$DESYNC_MARK -j NFQUEUE --queue-num $QNUM
}
tpws_ipt_prepare()
{
	# $1 - port
	IPT OUTPUT -t nat -p tcp --dport $1 -m owner ! --uid-owner $TPWS_UID -j DNAT --to $LOCALHOST_IPT:$TPPORT
}
tpws_ipt_unprepare()
{
	# $1 - port
	IPT_DEL OUTPUT -t nat -p tcp --dport $1 -m owner ! --uid-owner $TPWS_UID -j DNAT --to $LOCALHOST_IPT:$TPPORT
}
nfqws_start()
{
	"$NFQWS" --dpi-desync-fwmark=$DESYNC_MARK --qnum=$QNUM "$@" >/dev/null &
	PID=$!
}
tpws_start()
{
	"$TPWS" --uid $TPWS_UID:$TPWS_UID --bind-addr=$LOCALHOST --port=$TPPORT "$@" >/dev/null &
	PID=$!
	# give some time to initialize
	sleep 1
}

curl_test()
{
	# $1 - test function
	# $2 - domain
	$1 $IPV $2 && {
		echo '!!!!! AVAILABLE !!!!!'
		return 0
	}
	local code=$?
	if [ $code = 254 ]; then
		echo UNAVAILABLE
	else
		echo UNAVAILABLE code=$code
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
	# let some time for tpws to initialize
	curl_test $testf $dom
	code=$?
	killwait -9 $PID
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
nfqws_curl_test()
{
	# $1 - test function
	# $2 - domain
	# $3,$4,$5, ... - nfqws params
	echo - checking nfqws $3 $4 $5 $6 $7 $8 $9
	ws_curl_test nfqws_start "$@"
}
nfqws_check_domain_bypass()
{
	# $1 - test function
	# $2 - encrypted test : 1/0
	# $3 - domain

	local strategy tests='fake' ttls s sec="$2" found

	[ "$sec" = 0 ] && {
		for s in '--hostcase' '--hostspell=hoSt' '--hostnospace' '--domcase'; do
			nfqws_curl_test $1 $3 $s && strategy="${strategy:-$s}"
		done
	}

	s="--dpi-desync=split2"
	if nfqws_curl_test $1 $3 $s; then
		strategy="${strategy:-$s}"
	else
		tests="$tests split fake,split2 fake,split"
		[ "$sec" = 0 ] && {
			s="$s --hostcase"
			nfqws_curl_test $1 $3 $s && strategy="${strategy:-$s}"
		}
		for pos in 1 2 4 5 10 50 100; do
			s="--dpi-desync=split2 --dpi-desync-split-pos=$pos"
			if nfqws_curl_test $1 $3 $s; then
				strategy="${strategy:-$s}"
				break
			else
				[ "$sec" = 0 ] && {
					s="$s --hostcase"
					nfqws_curl_test $1 $3 $s && strategy="${strategy:-$s}"
				}
			fi
		done
	fi

	s="--dpi-desync=disorder2"
	if nfqws_curl_test $1 $3 $s; then
		strategy="${strategy:-$s}" 
	else
		tests="$tests disorder fake,disorder2 fake,disorder"
	fi

	ttls=$(seq -s ' ' $MIN_TTL $MAX_TTL)
	for desync in $tests; do
		found=0
		for ttl in $ttls; do
			s="--dpi-desync=$desync --dpi-desync-ttl=$ttl"
			nfqws_curl_test $1 $3 $s && {
				found=1
				strategy="${strategy:-$s}"
				break
			}
		done
		[ "$sec" = 1 ] && [ "$found" = 0 ] && {
			for ttl in $ttls; do
				s="--dpi-desync=$desync --dpi-desync-ttl=$ttl --wssize 1:6"
				nfqws_curl_test $1 $3 $s && {
					found=1
					strategy="${strategy:-$s}"
					break
				}
			done
		}
		for fooling in badsum md5sig badseq; do
			s="--dpi-desync=$desync --dpi-desync-fooling=$fooling"
			if nfqws_curl_test $1 $3 $s ; then
				strategy="${strategy:-$s}"
				[ "$fooling" = "md5sig" ] && echo 'WARNING ! although md5sig fooling worked it will not work on all sites. it typically works only on linux servers.'
			else
				[ "$sec" = 1 ] && {
					s="$s --wssize 1:6"
					nfqws_curl_test $1 $3 $s && {
						strategy="${strategy:-$s}"
						[ "$fooling" = "md5sig" ] && echo 'WARNING ! although md5sig fooling worked it will not work on all sites. it typically works only on linux servers.'
					}
				}
			fi
		done
	done

	echo
	if [ -n "$strategy" ]; then
		echo "!!!!! working strategy found : nfqws $strategy !!!!!"
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
			tpws_curl_test $1 $3 $s && strategy="${strategy:-$s}"
		done
	else
		for pos in 1 2 3 4 5 10 50 100; do
			s="--split-pos=$pos"
			tpws_curl_test $1 $3 $s && {
				strategy="${strategy:-$s}"
				break
			}
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
	nfqws_ipt_unprepare $2
	tpws_ipt_unprepare $2
	killall nfqws tpws 2>/dev/null

	echo "- checking without DPI bypass"
	curl_test $1 $4 && return
	code=$?
	for c in 1 2 3 4 6 27 ; do
		[ $code = $c ] && return
	done

	echo preparing tpws redirection
	tpws_ipt_prepare $2

	tpws_check_domain_bypass $1 $3 $4

	echo clearing tpws redirection
	tpws_ipt_unprepare $2

	echo

	echo preparing nfqws redirection
	nfqws_ipt_prepare $2

	nfqws_check_domain_bypass $1 $3 $4

	echo clearing nfqws redirection
	nfqws_ipt_unprepare $2
}
check_domain_http()
{
	# $1 - domain
	check_domain curl_test_http 80 0 $1
}
check_domain_https()
{
	# $1 - domain
	check_domain curl_test_https 443 1 $1
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

ask_params()
{
	echo
	echo NOTE ! this test should be run with zapret or any other bypass software disabled, without VPN
	echo NOTE ! this test will kill all nfqws and tpws processes. if you have already set up zapret you will need to restart it after test is complete.

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

	ENABLE_HTTP=1
	ask_yes_no_var ENABLE_HTTP "check http"

	ENABLE_HTTPS=1
	ask_yes_no_var ENABLE_HTTPS "check https"

	IGNORE_CA=0
	CURL_OPT=
	[ "$ENABLE_HTTPS" = "1" ] && {
		echo on limited systems like openwrt CA certificates might not be installed to preserve space
		echo in such a case curl cannot verify server certificate and you should either install ca-bundle or disable verification
		echo however disabling verification will break https check if ISP does MitM attack and substitutes server certificate
		ask_yes_no_var IGNORE_CA "do not verify server certificate"
		[ "$IGNORE_CA" = 1 ] && CURL_OPT=-k
	}
}



pingtest()
{
	ping -c 1 -W 1 $1 >/dev/null
}
dnstest()
{
	# $1 - dns server. empty for system resolver
	nslookup w3.org $1 >/dev/null 2>/dev/null
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
check_dns_spoof()
{
	# $1 - domain
	# $2 - public DNS
	echo $1 | "$EXEDIR/mdig/mdig" --family=4 >"$DNSCHECK_DIG1"
	nslookup $1 $2 | sed -n '/Name:/,$p' | grep ^Address | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' >"$DNSCHECK_DIG2"
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
		for dom in $DNSCHECK_DOM; do echo $dom; done | "$EXEDIR/mdig/mdig" --threads=10 --family=4 >"$DNSCHECK_DIGS"
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


sigint()
{
	# make sure we are not in a middle state that impacts connectivity
	echo
	echo terminating...
	[ -n "$IPV" ] && {
		tpws_ipt_unprepare 80
		tpws_ipt_unprepare 443
		nfqws_ipt_unprepare 80
		nfqws_ipt_unprepare 443
	}
	killall nfqws tpws 2>/dev/null
	exitp 1
}

trap 'sigint' 2

check_system
check_prerequisites
require_root
check_dns
ask_params

[ "$ENABLE_HTTP" = 1 ] && check_domain_http $DOMAIN
[ "$ENABLE_HTTPS" = 1 ] && check_domain_https $DOMAIN

exitp 0
