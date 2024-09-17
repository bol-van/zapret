#!/bin/sh

EXEDIR="$(dirname "$0")"
EXEDIR="$(
	cd "$EXEDIR" || exit
	pwd
)"
ZAPRET_BASE=${ZAPRET_BASE:-"$EXEDIR"}
ZAPRET_RW=${ZAPRET_RW:-"$ZAPRET_BASE"}
ZAPRET_CONFIG=${ZAPRET_CONFIG:-"$ZAPRET_RW/config"}
ZAPRET_CONFIG_DEFAULT="$ZAPRET_BASE/config.default"

CURL=${CURL:-curl}

[ -f "$ZAPRET_CONFIG" ] || {
	[ -f "$ZAPRET_CONFIG_DEFAULT" ] && {
		ZAPRET_CONFIG_DIR="$(dirname "$ZAPRET_CONFIG")"
		[ -d "$ZAPRET_CONFIG_DIR" ] || mkdir -p "$ZAPRET_CONFIG_DIR"
		cp "$ZAPRET_CONFIG_DEFAULT" "$ZAPRET_CONFIG"
	}
}
[ -f "$ZAPRET_CONFIG" ] && . "$ZAPRET_CONFIG"
. "$ZAPRET_BASE/common/base.sh"
. "$ZAPRET_BASE/common/dialog.sh"
. "$ZAPRET_BASE/common/elevate.sh"
. "$ZAPRET_BASE/common/fwtype.sh"
. "$ZAPRET_BASE/common/virt.sh"

QNUM=${QNUM:-59780}
SOCKS_PORT=${SOCKS_PORT:-1993}
TPWS_UID=${TPWS_UID:-1}
TPWS_GID=${TPWS_GID:-3003}
NFQWS=${NFQWS:-${ZAPRET_BASE}/nfq/nfqws}
DVTWS=${DVTWS:-${ZAPRET_BASE}/nfq/dvtws}
WINWS=${WINWS:-${ZAPRET_BASE}/nfq/winws}
TPWS=${TPWS:-${ZAPRET_BASE}/tpws/tpws}
MDIG=${MDIG:-${ZAPRET_BASE}/mdig/mdig}
DESYNC_MARK=0x10000000
IPFW_RULE_NUM=${IPFW_RULE_NUM:-1}
IPFW_DIVERT_PORT=${IPFW_DIVERT_PORT:-59780}
DOMAINS=${DOMAINS:-rutracker.org}
CURL_MAX_TIME=${CURL_MAX_TIME:-2}
CURL_MAX_TIME_QUIC=${CURL_MAX_TIME_QUIC:-$CURL_MAX_TIME}
MIN_TTL=${MIN_TTL:-1}
MAX_TTL=${MAX_TTL:-12}
USER_AGENT=${USER_AGENT:-Mozilla}
HTTP_PORT=${HTTP_PORT:-80}
HTTPS_PORT=${HTTPS_PORT:-443}
QUIC_PORT=${QUIC_PORT:-443}
UNBLOCKED_DOM=${UNBLOCKED_DOM:-iana.org}
[ "$CURL_VERBOSE" = 1 ] && CURL_CMD=1

HDRTEMP=/tmp/zapret-hdr.txt

NFT_TABLE=blockcheck

DNSCHECK_DNS=${DNSCHECK_DNS:-8.8.8.8 1.1.1.1 77.88.8.1}
DNSCHECK_DOM=${DNSCHECK_DOM:-pornhub.com ntc.party rutracker.org www.torproject.org bbc.com}
DNSCHECK_DIG1=/tmp/dig1.txt
DNSCHECK_DIG2=/tmp/dig2.txt
DNSCHECK_DIGS=/tmp/digs.txt

unset PF_STATUS
PF_RULES_SAVE=/tmp/pf-zapret-save.conf

unset ALL_PROXY

killwait() {
	# $1 - signal (-9, -2, ...)
	# $2 - pid
	kill "$1" "$2"
	# suppress job kill message
	wait "$2" 2>/dev/null
}

exitp() {
	local A

	echo
	echo press enter to continue
	read A
	exit "$1"
}

pf_is_avail() {
	[ -c /dev/pf ]
}
pf_status() {
	pfctl -qsi | sed -nre "s/^Status: ([^ ]+).*$/\1/p"
}
pf_is_enabled() {
	[ "$(pf_status)" = Enabled ]
}
pf_save() {
	PF_STATUS=0
	pf_is_enabled && PF_STATUS=1
	[ "$UNAME" = "OpenBSD" ] && pfctl -sr >"$PF_RULES_SAVE"
}
pf_restore() {
	[ -n "$PF_STATUS" ] || return
	case "$UNAME" in
	OpenBSD)
		if [ -f "$PF_RULES_SAVE" ]; then
			pfctl -qf "$PF_RULES_SAVE"
		else
			echo | pfctl -qf -
		fi
		;;
	Darwin)
		# it's not possible to save all rules in the right order. hard to reorder. if not ordered pf will refuse to load conf.
		pfctl -qf /etc/pf.conf
		;;
	esac
	if [ "$PF_STATUS" = 1 ]; then
		pfctl -qe
	else
		pfctl -qd
	fi
}
pf_clean() {
	rm -f "$PF_RULES_SAVE"
}
opf_dvtws_anchor() {
	# $1 - tcp/udp
	# $2 - port
	local family=inet
	[ "$IPV" = 6 ] && family=inet6
	echo "set reassemble no"
	[ "$1" = tcp ] && echo "pass in quick $family proto $1 from port $2 flags SA/SA divert-packet port $IPFW_DIVERT_PORT no state"
	echo "pass in  quick $family proto $1 from port $2 no state"
	echo "pass out quick $family proto $1 to   port $2 divert-packet port $IPFW_DIVERT_PORT no state"
	echo "pass"
}
opf_prepare_dvtws() {
	# $1 - tcp/udp
	# $2 - port
	opf_dvtws_anchor "$1" "$2" | pfctl -qf -
	pfctl -qe
}

cleanup() {
	case "$UNAME" in
	OpenBSD)
		pf_clean
		;;
	esac
}

IPT() {
	$IPTABLES -C "$@" >/dev/null 2>/dev/null || $IPTABLES -I "$@"
}
IPT_DEL() {
	$IPTABLES -C "$@" >/dev/null 2>/dev/null && $IPTABLES -D "$@"
}
IPT_ADD_DEL() {
	on_off_function IPT IPT_DEL "$@"
}
IPFW_ADD() {
	ipfw -qf add "$IPFW_RULE_NUM" "$@"
}
IPFW_DEL() {
	ipfw -qf delete "$IPFW_RULE_NUM" 2>/dev/null
}
ipt6_has_raw() {
	ip6tables -nL -t raw >/dev/null 2>/dev/null
}
ipt6_has_frag() {
	ip6tables -A OUTPUT -m frag 2>/dev/null || return 1
	ip6tables -D OUTPUT -m frag 2>/dev/null
}
ipt_has_nfq() {
	# cannot just check /proc/net/ip_tables_targets because of iptables-nft or modules not loaded yet
	iptables -A OUTPUT -t mangle -p 255 -j NFQUEUE --queue-num "$QNUM" --queue-bypass 2>/dev/null || return 1
	iptables -D OUTPUT -t mangle -p 255 -j NFQUEUE --queue-num "$QNUM" --queue-bypass 2>/dev/null
	return 0
}
nft_has_nfq() {
	local res=1
	nft delete table ${NFT_TABLE}_test 2>/dev/null
	nft add table ${NFT_TABLE}_test 2>/dev/null && {
		nft add chain ${NFT_TABLE}_test test
		nft add rule ${NFT_TABLE}_test test queue num "$QNUM" bypass 2>/dev/null && res=0
		nft delete table ${NFT_TABLE}_test
	}
	return $res
}
mdig_vars() {
	# $1 - ip version 4/6
	# $2 - hostname

	hostvar=$(echo "$2" | sed -e 's/[\.-]/_/g')
	cachevar=DNSCACHE_${hostvar}_$1
	countvar=${cachevar}_COUNT
	eval count=\$"${countvar}"
}
mdig_cache() {
	# $1 - ip version 4/6
	# $2 - hostname
	local hostvar cachevar countvar count ip ips
	mdig_vars "$@"
	[ -n "$count" ] || {
		# Windows version of mdig outputs 0D0A line ending. remove 0D.
		ips="$(echo "$2" | "$MDIG" --family="$1" | tr -d '\r' | xargs)"
		[ -n "$ips" ] || return 1
		count=0
		for ip in $ips; do
			eval "${cachevar}"_$count="$ip"
			count=$(($count + 1))
		done
		eval "$countvar"=$count
	}
	return 0
}
mdig_resolve() {
	# $1 - ip version 4/6
	# $2 - hostname

	local hostvar cachevar countvar count ip n
	mdig_vars "$@"
	if [ -n "$count" ]; then
		n=$(random 0 $(($count - 1)))
		eval ip=\$"${cachevar}"_"$n"
		echo "$ip"
		return 0
	else
		mdig_cache "$@" && mdig_resolve "$@"
	fi
}
mdig_resolve_all() {
	# $1 - ip version 4/6
	# $2 - hostname

	local hostvar cachevar countvar count ip ips n
	mdig_vars "$@"
	if [ -n "$count" ]; then
		n=0
		while [ "$n" -le "$count" ]; do
			eval ip=\$"${cachevar}"_$n
			if [ -n "$ips" ]; then
				ips="$ips $ip"
			else
				ips="$ip"
			fi
			n=$(($n + 1))
		done
		echo "$ips"
		return 0
	else
		mdig_cache "$@" && mdig_resolve_all "$@"
	fi
}

netcat_setup() {
	[ -n "$NCAT" ] || {
		if exists ncat; then
			NCAT=ncat
		elif exists nc; then
			# busybox netcat does not support any required options
			is_linked_to_busybox nc && return 1
			NCAT=nc
		else
			return 1
		fi
	}
	return 0

}
netcat_test() {
	# $1 - ip
	# $2 - port
	local cmd
	netcat_setup && {
		cmd="$NCAT -z -w 1 $1 $2"
		echo "$cmd"
		$cmd 2>&1
	}
}

check_system() {
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
			echo firewall type "$FWTYPE" not supported in "$UNAME"
			exitp 5
		}
		;;
	FreeBSD)
		PKTWS="$DVTWS"
		PKTWSD=dvtws
		FWTYPE=ipfw
		[ -f /etc/platform ] && read SUBSYS </etc/platform
		;;
	OpenBSD)
		PKTWS="$DVTWS"
		PKTWSD=dvtws
		FWTYPE=opf
		;;
	Darwin)
		PKTWS="$DVTWS"
		PKTWSD=dvtws
		FWTYPE=mpf
		;;
	CYGWIN*)
		UNAME=CYGWIN
		PKTWS="$WINWS"
		PKTWSD=winws
		FWTYPE=windivert
		;;
	*)
		echo "$UNAME" not supported
		exitp 5
		;;
	esac
	echo "$UNAME"${SUBSYS:+/$SUBSYS} detected
	echo firewall type is "$FWTYPE"
}

freebsd_module_loaded() {
	# $1 - module name
	kldstat -qm "${1}"
}
freebsd_modules_loaded() {
	# $1,$2,$3, ... - module names
	while [ -n "$1" ]; do
		freebsd_module_loaded "$1" || return 1
		shift
	done
	return 0
}

check_prerequisites() {
	echo \* checking prerequisites

	[ "$UNAME" = Darwin -o -x "$PKTWS" ] && [ "$UNAME" = CYGWIN -o -x "$TPWS" ] && [ -x "$MDIG" ] || {
		local target
		case $UNAME in
		Darwin)
			target="mac"
			;;
		OpenBSD)
			target="bsd"
			;;
		esac
		echo "$PKTWS" or "$TPWS" o"r $MD"IG is not available. ru"n \"$ZAPRET_"BASE/install_bin.sh\" or \`make -C \""$ZAPRET_BASE"\" $target\`
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
			echo ipfw is disabled. use: ipfw enable firewall
			exitp 6
		}
		pf_is_avail && {
			pf_save
			[ "$SUBSYS" = "pfSense" ] && {
				# pfsense's ipfw may not work without these workarounds
				sysctl net.inet.ip.pfil.outbound=ipfw,pf 2>/dev/null
				sysctl net.inet.ip.pfil.inbound=ipfw,pf 2>/dev/null
				sysctl net.inet6.ip6.pfil.outbound=ipfw,pf 2>/dev/null
				sysctl net.inet6.ip6.pfil.inbound=ipfw,pf 2>/dev/null
				pfctl -qd
				pfctl -qe
				pf_restore
			}
		}
		;;
	OpenBSD | Darwin)
		progs="$progs pfctl"
		pf_is_avail || {
			echo pf is not available
			exitp 6
		}
		# no divert sockets in macOS
		[ "$UNAME" = "Darwin" ] && SKIP_PKTWS=1
		pf_save
		;;
	CYGWIN)
		SKIP_TPWS=1
		;;
	esac

	for prog in $progs; do
		exists "$prog" || {
			echo "$prog" does not exist. please install
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

curl_translate_code() {
	# $1 - code
	printf "$1"
	case $1 in
	0)
		printf ": ok"
		;;
	1)
		printf ": unsupported protocol"
		;;
	2)
		printf ": early initialization code failed"
		;;
	3)
		printf ": the URL was not properly formatted"
		;;
	4)
		printf ": feature not supported by libcurl"
		;;
	5)
		printf ": could not resolve proxy"
		;;
	6)
		printf ": could not resolve host"
		;;
	7)
		printf ": could not connect"
		;;
	8)
		printf ": invalid server reply"
		;;
	9)
		printf ": remote access denied"
		;;
	27)
		printf ": out of memory"
		;;
	28)
		printf ": operation timed out"
		;;
	35)
		printf ": SSL connect error"
		;;
	esac
}
curl_supports_tls13() {
	local r
	$CURL --tlsv1.3 -Is -o /dev/null --max-time 1 http://127.0.0.1:65535 2>/dev/null
	# return code 2 = init failed. likely bad command line options
	[ $? = 2 ] && return 1
	# curl can have TLSv1.3 key present but SSL library without TLS 1.3 support
	# this is online test because there's no other way to trigger library incompatibility case
	$CURL --tlsv1.3 --max-time "$CURL_MAX_TIME" -Is -o /dev/null https://w3.org 2>/dev/null
	r=$?
	[ $r != 4 -a $r != 35 ]
}

curl_supports_tlsmax() {
	# supported only in OpenSSL and LibreSSL
	$CURL --version | grep -Fq -e OpenSSL -e LibreSSL -e BoringSSL -e GnuTLS -e quictls || return 1
	# supported since curl 7.54
	$CURL --tls-max 1.2 -Is -o /dev/null --max-time 1 http://127.0.0.1:65535 2>/dev/null
	# return code 2 = init failed. likely bad command line options
	[ $? != 2 ]
}

curl_supports_connect_to() {
	$CURL --connect-to 127.0.0.1:: -o /dev/null --max-time 1 http://127.0.0.1:65535 2>/dev/null
	[ "$?" != 2 ]
}

curl_supports_http3() {
	# if it has HTTP3: curl: (3) HTTP/3 requested for non-HTTPS URL
	# otherwise: curl: (2) option --http3-only: is unknown
	$CURL --connect-to 127.0.0.1:: -o /dev/null --max-time 1 --http3-only http://127.0.0.1:65535 2>/dev/null
	[ "$?" != 2 ]
}

hdrfile_http_code() {
	# $1 - hdr file
	sed -nre '1,1 s/^HTTP\/1\.[0,1] ([0-9]+) .*$/\1/p' "$1"
}
hdrfile_location() {
	# $1 - hdr file

	# some DPIs return CRLF line ending
	tr -d '\015' <"$1" | sed -nre 's/^[Ll][Oo][Cc][Aa][Tt][Ii][Oo][Nn]:[ 	]*([^ 	]*)[ 	]*$/\1/p'
}

curl_with_subst_ip() {
	# $1 - domain
	# $2 - port
	# $3 - IP
	# $4+ - curl params
	local connect_to="--connect-to $1::[$3]${2:+:$2}" arg
	shift
	shift
	shift
	[ "$CURL_VERBOSE" = 1 ] && arg="-v"
	[ "$CURL_CMD" = 1 ] && echo "$CURL" ${arg:+$arg }"$connect_to" "$@"
	ALL_PROXY="$ALL_PROXY" $CURL ${arg:+$arg }"$connect_to" "$@"
}
curl_with_dig() {
	# $1 - IP version: 4/6
	# $2 - domain name
	# $3 - port
	# $4+ - curl params
	local dom="$2" por"t"="""$3"
	local ip=$(mdig_resolve "$1" "$dom")
	shift
	shift
	shift
	if [ -n "$ip" ]; then
		curl_with_subst_ip "$dom" "$port" "$ip" "$@"
	else
		return 6
	fi
}
curl_probe() {
	# $1 - IP version: 4/6
	# $2 - domain name
	# $3 - port
	# $4 - subst IP
	# $5+ - curl params
	local ipv="$1" dom="$2" port="$3" subst="$4"
	shift
	shift
	shift
	shift
	if [ -n "$subst" ]; then
		curl_with_subst_ip "$dom" "$port" "$subst" "$@"
	else
		curl_with_dig "$ipv" "$dom" "$port" "$@"
	fi
}
curl_test_http() {
	# $1 - IP version: 4/6
	# $2 - domain name
	# $3 - subst IP
	# $4 - "detail" - detail info

	local code loc
	curl_probe "$1" "$2" "$HTTP_PORT" "$3" -SsD "$HDRTEMP" -A "$USER_AGENT" --max-time "$CURL_MAX_TIME" "$CURL_OPT" "http://$2" -o /dev/null 2>&1 || {
		code=$?
		rm -f "$HDRTEMP"
		return "$code"
	}
	if [ "$4" = "detail" ]; then
		head -n 1 "$HDRTEMP"
		grep "^[lL]ocation:" "$HDRTEMP"
	else
		code=$(hdrfile_http_code "$HDRTEMP")
		[ "$code" = 301 -o "$code" = 302 -o "$code" = 307 -o "$code" = 308 ] && {
			loc=$(hdrfile_location "$HDRTEMP")
			echo "$loc" | grep -qE "^https?://.*$2(/|$)" ||
				echo "$loc" | grep -vqE '^https?://' || {
				echo suspicious redirection "$code" to: "$loc"
				rm -f "$HDRTEMP"
				return 254
			}
		}
	fi
	rm -f "$HDRTEMP"
	[ "$code" = 400 ] && {
		# this can often happen if the server receives fake packets it should not receive
		echo HTTP code "$code". likely the server receives fakes.
		return 254
	}
	return 0
}
curl_test_https_tls12() {
	# $1 - IP version: 4/6
	# $2 - domain name
	# $3 - subst IP

	# do not use TLS 1.3 to make sure server certificate is not encrypted
	curl_probe "$1" "$2" "$HTTPS_PORT" "$3" -ISs -A "$USER_AGENT" --max-time "$CURL_MAX_TIME" "$CURL_OPT" --tlsv1.2 "$TLSMAX12" "https://$2" -o /dev/null 2>&1
}
curl_test_https_tls13() {
	# $1 - IP version: 4/6
	# $2 - domain name
	# $3 - subst IP

	# force TLS1.3 mode
	curl_probe "$1" "$2" "$HTTPS_PORT" "$3" -ISs -A "$USER_AGENT" --max-time "$CURL_MAX_TIME" "$CURL_OPT" --tlsv1.3 "$TLSMAX13" "https://$2" -o /dev/null 2>&1
}

curl_test_http3() {
	# $1 - IP version: 4/6
	# $2 - domain name

	# force QUIC only mode without TCP
	curl_with_dig "$1" "$2" "$QUIC_PORT" -ISs -A "$USER_AGENT" --max-time "$CURL_MAX_TIME_QUIC" --http3-only "$CURL_OPT" "https://$2" -o /dev/null 2>&1
}

ipt_scheme() {
	# $1 - 1 - add, 0 - del
	# $2 - tcp/udp
	# $3 - port

	IPT_ADD_DEL "$1" OUTPUT -t mangle -p "$2" --dport "$3" -m mark ! --mark $DESYNC_MARK/$DESYNC_MARK -j NFQUEUE --queue-num "$QNUM"
	# to avoid possible INVALID state drop
	[ "$2" = tcp ] && IPT_ADD_DEL "$1" INPUT -p "$2" --sport "$3" ! --syn -j ACCEPT
	# for strategies with incoming packets involved (autottl)
	IPT_ADD_DEL "$1" OUTPUT -p "$2" --dport "$3" -m conntrack --ctstate INVALID -j ACCEPT
	if [ "$IPV" = 6 -a -n "$IP6_DEFRAG_DISABLE" ]; then
		# the only way to reliable disable IPv6 defrag. works only in 4.16+ kernels
		IPT_ADD_DEL "$1" OUTPUT -t raw -p "$2" -m frag -j CT --notrack
	elif [ "$IPV" = 4 ]; then
		# enable fragments
		IPT_ADD_DEL "$1" OUTPUT -f -j ACCEPT
	fi
	# enable everything generated by nfqws (works only in OUTPUT, not in FORWARD)
	# raw table may not be present
	IPT_ADD_DEL "$1" OUTPUT -t raw -m mark --mark $DESYNC_MARK/$DESYNC_MARK -j CT --notrack
}
nft_scheme() {
	# $1 - tcp/udp
	# $2 - port
	nft add table inet $NFT_TABLE
	nft "add chain inet $NFT_TABLE postnat { type filter hook output priority 102; }"
	nft "add rule inet $NFT_TABLE postnat meta nfproto ipv${IPV} $1 dport $2 mark and $DESYNC_MARK != $DESYNC_MARK queue num $QNUM"
	# for strategies with incoming packets involved (autottl)
	nft "add chain inet $NFT_TABLE prenat { type filter hook prerouting priority -102; }"
	# enable everything generated by nfqws (works only in OUTPUT, not in FORWARD)
	nft "add chain inet $NFT_TABLE predefrag { type filter hook output priority -402; }"
	nft "add rule inet $NFT_TABLE predefrag meta nfproto ipv${IPV} mark and $DESYNC_MARK !=0 notrack"
}

pktws_ipt_prepare() {
	# $1 - tcp/udp
	# $2 - port
	case "$FWTYPE" in
	iptables)
		ipt_scheme 1 "$1" "$2"
		;;
	nftables)
		nft_scheme "$1" "$2"
		;;
	ipfw)
		# disable PF to avoid interferences
		pf_is_avail && pfctl -qd
		IPFW_ADD divert "$IPFW_DIVERT_PORT" "$1" from me to any "$2" proto ip"${IPV}" out not diverted not sockarg
		;;
	opf)
		opf_prepare_dvtws "$1" "$2"
		;;
	windivert)
		WF="--wf-l3=ipv${IPV} --wf-${1}=$2"
		;;

	esac
}
pktws_ipt_unprepare() {
	# $1 - tcp/udp
	# $2 - port
	case "$FWTYPE" in
	iptables)
		ipt_scheme 0 "$1" "$2"
		;;
	nftables)
		nft delete table inet $NFT_TABLE 2>/dev/null
		;;
	ipfw)
		IPFW_DEL
		pf_is_avail && pf_restore
		;;
	opf)
		pf_restore
		;;
	windivert)
		unset WF
		;;
	esac
}

pktws_ipt_prepare_tcp() {
	# $1 - port

	pktws_ipt_prepare tcp "$1"

	case "$FWTYPE" in
	iptables)
		# for autottl
		IPT INPUT -t mangle -p tcp --sport "$1" -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:1 -j NFQUEUE --queue-num "$QNUM"
		;;
	nftables)
		# for autottl
		nft "add rule inet $NFT_TABLE prenat meta nfproto ipv${IPV} tcp sport $1 ct original packets 1 queue num $QNUM"
		;;
	ipfw)
		# for autottl mode
		IPFW_ADD divert "$IPFW_DIVERT_PORT" tcp from any "$1" to me proto ip"${IPV}" tcpflags syn,ack in not diverted not sockarg
		;;
	esac
}
pktws_ipt_unprepare_tcp() {
	# $1 - port

	pktws_ipt_unprepare tcp "$1"

	case "$FWTYPE" in
	iptables)
		IPT_DEL INPUT -t mangle -p tcp --sport "$1" -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:1 -j NFQUEUE --queue-num "$QNUM"
		;;
	esac
}
pktws_ipt_prepare_udp() {
	# $1 - port

	pktws_ipt_prepare udp "$1"
}
pktws_ipt_unprepare_udp() {
	# $1 - port

	pktws_ipt_unprepare udp "$1"
}

pktws_start() {
	case "$UNAME" in
	Linux)
		"$NFQWS" --uid "$TPWS_UID":"$TPWS_GID" --dpi-desync-fwmark="$DESYNC_MARK" --qnum="$QNUM" "$@" >/dev/null &
		;;
	FreeBSD | OpenBSD)
		"$DVTWS" --port="$IPFW_DIVERT_PORT" "$@" >/dev/null &
		;;
	CYGWIN)
		"$WINWS" "$WF" "$@" >/dev/null &
		;;
	esac
	PID=$!
	# give some time to initialize
	minsleep
}
tpws_start() {
	"$TPWS" --uid "$TPWS_UID":"$TPWS_GID" --socks --bind-addr=127.0.0.1 --port="$SOCKS_PORT" "$@" >/dev/null &
	PID=$!
	# give some time to initialize
	minsleep
}
ws_kill() {
	[ -z "$PID" ] || {
		killwait -9 "$PID" 2>/dev/null
		PID=
	}
}

check_domain_port_block() {
	# $1 - domain
	# $2 - port
	local ip ips
	echo
	echo \* port block tests ipv"$IPV" "$1":"$2"
	if netcat_setup; then
		ips=$(mdig_resolve_all "$IPV" "$1")
		if [ -n "$ips" ]; then
			for ip in $ips; do
				if netcat_test "$ip" "$2"; then
					echo "$ip" connects
				else
					echo "$ip" does not connect. netcat code $?
				fi
			done
		else
			echo "ipv${IPV} $1 does not resolve"
		fi
	else
		echo suitable netcat not found. busybox nc is not supported. pls install nmap ncat or openbsd netcat.
	fi
}

curl_test() {
	# $1 - test function
	# $2 - domain
	# $3 - subst ip
	# $4 - param of test function
	local code=0 n=0

	while [ $n -lt $REPEATS ]; do
		n=$(($n + 1))
		[ $REPEATS -gt 1 ] && printf "[attempt $n] "
		if $1 "$IPV" "$2" "$3" "$4"; then
			[ $REPEATS -gt 1 ] && echo 'AVAILABLE'
		else
			code=$?
			[ "$SCANLEVEL" = quick ] && break
		fi
	done
	[ "$4" = detail ] || {
		if [ $code = 254 ]; then
			echo "UNAVAILABLE"
		elif [ $code = 0 ]; then
			echo '!!!!! AVAILABLE !!!!!'
		else
			echo "UNAVAILABLE code=$code"
		fi
	}
	return $code
}
ws_curl_test() {
	# $1 - ws start function
	# $2 - test function
	# $3 - domain
	# $4,$5,$6, ... - ws params
	local code ws_start="$1" testf="$2" dom="$3"
	shift
	shift
	shift
	$ws_start "$@"
	curl_test "$testf" "$dom"
	code=$?
	ws_kill
	return "$code"
}
tpws_curl_test() {
	# $1 - test function
	# $2 - domain
	# $3,$4,$5, ... - tpws params
	echo - checking tpws "$3" "$4" "$5" "$6" "$7" "$8" "$9"
	local ALL_PROXY="socks5://127.0.0.1:$SOCKS_PORT"
	ws_curl_test tpws_start "$@"
}
pktws_curl_test() {
	# $1 - test function
	# $2 - domain
	# $3,$4,$5, ... - nfqws/dvtws params
	echo - checking "$PKTWSD" ${WF:+$WF }"$3" "$4" "$5" "$6" "$7" "$8" "$9"
	ws_curl_test pktws_start "$@"
}
xxxws_curl_test_update() {
	# $1 - xxx_curl_test function
	# $2 - test function
	# $3 - domain
	# $4,$5,$6, ... - nfqws/dvtws params
	local code xxxf="$1" testf="$2" dom="$3"
	shift
	shift
	shift
	$xxxf "$testf" "$dom" "$@"
	code=$?
	[ $code = 0 ] && strategy="${strategy:-$@}"
	return $code
}
pktws_curl_test_update() {
	xxxws_curl_test_update pktws_curl_test "$@"
}
tpws_curl_test_update() {
	xxxws_curl_test_update tpws_curl_test "$@"
}

report_append() {
	NREPORT=${NREPORT:-0}
	eval REPORT_"${NREPORT}"=\"$@\"
	NREPORT=$(($NREPORT + 1))
}
report_print() {
	local n=0 s
	NREPORT=${NREPORT:-0}
	while [ $n -lt "$NREPORT" ]; do
		eval s=\"\${REPORT_$n}\"
		echo "$s"
		n=$(($n + 1))
	done
}
report_strategy() {
	# $1 - test function
	# $2 - domain
	# $3 - daemon
	echo
	if [ -n "$strategy" ]; then
		echo "!!!!! $1: working strategy found for ipv${IPV} $2 : $3 $strategy !!!!!"
		echo
		report_append "ipv${IPV} $2 $1 : $3 ${WF:+$WF }$strategy"
		return 0
	else
		echo "$1: $3 strategy for ipv${IPV} $2 not found"
		echo
		report_append "ipv${IPV} $2 $1 : $3 not working"
		return 1
	fi
}
test_has_split() {
	contains "$1" split || contains "$1" disorder
}
test_has_fake() {
	contains "$1" fake
}
warn_fool() {
	case "$1" in
	md5sig) echo 'WARNING ! although md5sig fooling worked it will not work on all sites. it typically works only on Linux servers.' ;;
	datanoack) echo 'WARNING ! although datanoack fooling worked it may break NAT and may only work with external IP. Additionally it may require nftables to work correctly.' ;;
	esac
}
pktws_curl_test_update_vary() {
	# $1 - test function
	# $2 - encrypted test: 0 = plain, 1 - encrypted with server reply risk, 2 - encrypted without server reply risk
	# $3 - domain
	# $4 - desync mode
	# $5,$6,... - strategy

	local testf="$1" sec="$2" domain="$3" desync="$4" zerofake split fake

	shift
	shift
	shift
	shift

	zerofake=http
	[ "$sec" = 0 ] || zerofake=tls
	zerofake="--dpi-desync-fake-$zerofake=0x00000000"

	for fake in '' $zerofake; do
		for split in '' '--dpi-desync-split-pos=1'; do
			pktws_curl_test_update "$testf" "$domain" --dpi-desync="$desync" "$@" "$fake" $split && return 0
			# split-pos=1 is meaningful for DPIs searching for 16 03 in TLS. no reason to apply to HTTP
			[ "$sec" = 1 ] || break
			test_has_split "$desync" || break
		done
		test_has_fake "$desync" || break
	done

	return 1
}

pktws_check_domain_http_bypass_() {
	# $1 - test function
	# $2 - encrypted test: 0 = plain, 1 - encrypted with server reply risk, 2 - encrypted without server reply risk
	# $3 - domain

	local tests='fake' ret ok ttls s f e desync pos fooling frag sec="$2" delta hostcase

	[ "$sec" = 0 ] && {
		for s in '--hostcase' '--hostspell=hoSt' '--hostnospace' '--domcase'; do
			pktws_curl_test_update "$1" "$3" $s
		done
	}

	s="--dpi-desync=split2"
	ok=0
	pktws_curl_test_update "$1" "$3" $s
	ret=$?
	[ "$ret" = 0 ] && {
		[ "$SCANLEVEL" = quick ] && return
		ok=1
	}
	[ "$ret" != 0 -o "$SCANLEVEL" = force ] && {
		if [ "$sec" = 0 ]; then
			pktws_curl_test_update "$1" "$3" $s --hostcase && {
				[ "$SCANLEVEL" = quick ] && return
				ok=1
			}
			for pos in method host; do
				for hostcase in '' '--hostcase'; do
					pktws_curl_test_update "$1" "$3" $s --dpi-desync-split-http-req=$pos $hostcase && {
						[ "$SCANLEVEL" = quick ] && return
						ok=1
					}
				done
			done
		else
			for pos in sni sniext; do
				pktws_curl_test_update "$1" "$3" $s --dpi-desync-split-tls=$pos && {
					[ "$SCANLEVEL" = quick ] && return
					ok=1
				}
			done
		fi
		for pos in 1 3 4 5 10 50; do
			s="--dpi-desync=split2 --dpi-desync-split-pos=$pos"
			if pktws_curl_test_update "$1" "$3" "$s"; then
				[ "$SCANLEVEL" = quick ] && return
				ok=1
				[ "$SCANLEVEL" = force ] || break
			elif [ "$sec" = 0 ]; then
				pktws_curl_test_update "$1" "$3" "$s" --hostcase && [ "$SCANLEVEL" = quick ] && return
			fi
		done
	}
	[ "$ok" = 1 -a "$SCANLEVEL" != force ] || tests="$tests split fake,split2 fake,split"

	pktws_curl_test_update "$1" "$3" --dpi-desync=disorder2
	ret=$?
	[ "$ret" = 0 -a "$SCANLEVEL" = quick ] && return
	[ "$ret" != 0 -o "$SCANLEVEL" = force ] && {
		pktws_curl_test_update "$1" "$3" --dpi-desync=disorder2 --dpi-desync-split-pos=1
		ret=$?
		[ "$ret" = 0 -a "$SCANLEVEL" = quick ] && return
	}
	[ "$ret" != 0 -o "$SCANLEVEL" = force ] && tests="$tests disorder fake,disorder2 fake,disorder"

	ttls=$(seq -s ' ' "$MIN_TTL" "$MAX_TTL")
	for e in '' '--wssize 1:6'; do
		[ -n "$e" ] && {
			pktws_curl_test_update "$1" "$3" "$e" && [ "$SCANLEVEL" = quick ] && return
			for desync in split2 disorder2; do
				pktws_curl_test_update_vary "$1" "$2" "$3" $desync "$e" && [ "$SCANLEVEL" = quick ] && return
			done
		}
		for desync in $tests; do
			for ttl in $ttls; do
				pktws_curl_test_update_vary "$1" "$2" "$3" "$desync" --dpi-desync-ttl="$ttl" "$e" && {
					[ "$SCANLEVEL" = quick ] && return
					break
				}
			done
			f=
			[ "$UNAME" = "OpenBSD" ] || f="badsum"
			f="$f badseq datanoack md5sig"
			[ "$IPV" = 6 ] && f="$f hopbyhop hopbyhop2"
			for fooling in $f; do
				pktws_curl_test_update_vary "$1" "$2" "$3" "$desync" --dpi-desync-fooling="$fooling" "$e" && {
					warn_fool "$fooling"
					[ "$SCANLEVEL" = quick ] && return
				}
			done
		done
		[ "$IPV" = 6 ] && {
			f="hopbyhop hopbyhop,split2 hopbyhop,disorder2 destopt destopt,split2 destopt,disorder2"
			[ -n "$IP6_DEFRAG_DISABLE" ] && f="$f ipfrag1 ipfrag1,split2 ipfrag1,disorder2"
			for desync in $f; do
				pktws_curl_test_update_vary "$1" "$2" "$3" "$desync" "$e" && [ "$SCANLEVEL" = quick ] && return
			done
		}

		for desync in split2 disorder2; do
			s="--dpi-desync=$desync"
			if [ "$sec" = 0 ]; then
				for pos in method host; do
					pktws_curl_test_update "$1" "$3" $s --dpi-desync-split-seqovl=1 --dpi-desync-split-http-req=$pos "$e" && [ "$SCANLEVEL" = quick ] && return
				done
			else
				for pos in sni sniext; do
					pktws_curl_test_update "$1" "$3" $s --dpi-desync-split-seqovl=1 --dpi-desync-split-tls=$pos "$e" && [ "$SCANLEVEL" = quick ] && return
				done
			fi
			for pos in 2 3 4 5 10 50; do
				pktws_curl_test_update "$1" "$3" $s --dpi-desync-split-seqovl=$(($pos - 1)) --dpi-desync-split-pos=$pos "$e" && [ "$SCANLEVEL" = quick ] && return
			done
			[ "$sec" != 0 -a $desync = split2 ] && {
				pktws_curl_test_update "$1" "$3" $s --dpi-desync-split-seqovl=336 --dpi-desync-split-seqovl-pattern="$ZAPRET_BASE/files/fake/tls_clienthello_iana_org.bin" "$e" && [ "$SCANLEVEL" = quick ] && return
			}
		done

		for desync in $tests; do
			ok=0
			for delta in 1 2 3 4 5; do
				pktws_curl_test_update_vary "$1" "$2" "$3" "$desync" --dpi-desync-ttl=1 --dpi-desync-autottl=$delta "$e" && ok=1
			done
			[ "$ok" = 1 ] &&
				{
					echo "WARNING ! although autottl worked it requires testing on multiple domains to find out reliable delta"
					echo "WARNING ! if a reliable delta cannot be found it's a good idea not to use autottl"
					[ "$SCANLEVEL" = quick ] && return
				}
		done

		s="http_iana_org.bin"
		[ "$sec" = 0 ] || s="tls_clienthello_iana_org.bin"
		for desync in syndata syndata,split2 syndata,disorder2; do
			pktws_curl_test_update_vary "$1" "$2" "$3" $desync "$e" && [ "$SCANLEVEL" = quick ] && return
			pktws_curl_test_update_vary "$1" "$2" "$3" $desync --dpi-desync-fake-syndata="$ZAPRET_BASE/files/fake/$s" "$e" && [ "$SCANLEVEL" = quick ] && return
		done

		# do not do wssize test for HTTP and TLS 1.3. it's useless
		[ "$sec" = 1 ] || break
	done
}
pktws_check_domain_http_bypass() {
	# $1 - test function
	# $2 - encrypted test: 0 = plain, 1 - encrypted with server reply risk, 2 - encrypted without server reply risk
	# $3 - domain

	local strategy
	pktws_check_domain_http_bypass_ "$@"
	report_strategy "$1" "$3" $PKTWSD
}

pktws_check_domain_http3_bypass_() {
	# $1 - test function
	# $2 - domain

	local f desync frag tests rep

	for rep in '' 2 5 10 20; do
		pktws_curl_test_update "$1" "$2" --dpi-desync=fake ${rep:+--dpi-desync-repeats=$rep} && [ "$SCANLEVEL" != force ] && {
			[ "$SCANLEVEL" = quick ] && return
			break
		}
	done

	[ "$IPV" = 6 ] && {
		f="hopbyhop destopt"
		[ -n "$IP6_DEFRAG_DISABLE" ] && f="$f ipfrag1"
		for desync in $f; do
			pktws_curl_test_update "$1" "$2" --dpi-desync="$desync" && [ "$SCANLEVEL" = quick ] && return
		done
	}

	# OpenBSD has checksum issues with fragmented packets
	[ "$UNAME" != "OpenBSD" ] && [ "$IPV" = 4 -o -n "$IP6_DEFRAG_DISABLE" ] && {
		for frag in 8 16 24 32 40 64; do
			tests="ipfrag2"
			[ "$IPV" = 6 ] && tests="$tests hopbyhop,ipfrag2 destopt,ipfrag2"
			for desync in $tests; do
				pktws_curl_test_update "$1" "$2" --dpi-desync="$desync" --dpi-desync-ipfrag-pos-udp=$frag && [ "$SCANLEVEL" = quick ] && return
			done
		done
	}

}
pktws_check_domain_http3_bypass() {
	# $1 - test function
	# $2 - domain

	local strategy
	pktws_check_domain_http3_bypass_ "$@"
	report_strategy "$1" "$2" $PKTWSD
}
warn_mss() {
	[ -n "$1" ] && echo 'WARNING ! although mss worked it may not work on all sites and will likely cause significant slowdown. it may only be required for TLS1.2, not TLS1.3'
	return 0
}

tpws_check_domain_http_bypass_() {
	# $1 - test function
	# $2 - encrypted test: 0 = plain, 1 - encrypted with server reply risk, 2 - encrypted without server reply risk
	# $3 - domain

	local s mss s2 s3 pos sec="$2"
	if [ "$sec" = 0 ]; then
		for s in '--hostcase' '--hostspell=hoSt' '--hostdot' '--hosttab' '--hostnospace' '--domcase' \
			'--hostpad=1024' '--hostpad=2048' '--hostpad=4096' '--hostpad=8192' '--hostpad=16384'; do
			tpws_curl_test_update "$1" "$3" $s && [ "$SCANLEVEL" = quick ] && return
		done
		for s2 in '' '--oob' '--disorder' '--oob --disorder'; do
			for s in '--split-http-req=method' '--split-http-req=method --hostcase' '--split-http-req=host' '--split-http-req=host --hostcase'; do
				tpws_curl_test_update "$1" "$3" "$s" "$s2" && [ "$SCANLEVEL" = quick ] && return
			done
		done
		for s in '--methodspace' '--unixeol' '--methodeol'; do
			tpws_curl_test_update "$1" "$3" $s && [ "$SCANLEVEL" = quick ] && return
		done
	else
		for mss in '' 88; do
			s3=${mss:+--mss=$mss --mss-pf=$HTTPS_PORT}
			for s2 in '' '--oob' '--disorder' '--oob --disorder'; do
				for pos in sni sniext; do
					s="--split-tls=$pos"
					tpws_curl_test_update "$1" "$3" $s "$s2" "$s3" && warn_mss "$s3" && [ "$SCANLEVEL" != force ] && {
						[ "$SCANLEVEL" = quick ] && return
						break
					}
				done
				for pos in 1 2 3 4 5 10 50; do
					s="--split-pos=$pos"
					tpws_curl_test_update "$1" "$3" $s "$s2" "$s3" && warn_mss "$s3" && [ "$SCANLEVEL" != force ] && {
						[ "$SCANLEVEL" = quick ] && return
						break
					}
				done
			done
			for s2 in '--tlsrec=sni' '--tlsrec=sni --split-tls=sni' '--tlsrec=sni --split-tls=sni --oob' \
				'--tlsrec=sni --split-tls=sni --disorder' '--tlsrec=sni --split-tls=sni --oob --disorder' \
				'--tlsrec=sni --split-pos=1' '--tlsrec=sni --split-pos=1 --oob' '--tlsrec=sni --split-pos=1 --disorder' \
				'--tlsrec=sni --split-pos=1 --oob --disorder'; do
				tpws_curl_test_update "$1" "$3" "$s2" "$s3" && warn_mss "$s3" && [ "$SCANLEVEL" != force ] && {
					[ "$SCANLEVEL" = quick ] && return
					break
				}
			done
			# only Linux supports mss
			[ "$UNAME" = Linux -a "$sec" = 1 ] || break
		done
	fi
}
tpws_check_domain_http_bypass() {
	# $1 - test function
	# $2 - encrypted test: 0 = plain, 1 - encrypted with server reply risk, 2 - encrypted without server reply risk
	# $3 - domain

	local strategy
	tpws_check_domain_http_bypass_ "$@"
	report_strategy "$1" "$3" tpws
}

check_dpi_ip_block() {
	# $1 - test function
	# $2 - domain

	local blocked_dom="$2"
	local blocked_ip blocked_ips unblocked_ip

	echo
	echo "- IP block tests (requires manual interpretation)"

	echo "> testing $UNBLOCKED_DOM on it's original ip"
	if curl_test "$1" "$UNBLOCKED_DOM"; then
		unblocked_ip=$(mdig_resolve "$IPV" "$UNBLOCKED_DOM")
		[ -n "$unblocked_ip" ] || {
			echo "$UNBLOCKED_DOM" does not resolve. tests not possible.
			return 1
		}

		echo "> testing $blocked_dom on $unblocked_ip ($UNBLOCKED_DOM)"
		curl_test "$1" "$blocked_dom" "$unblocked_ip" detail

		blocked_ips=$(mdig_resolve_all "$IPV" "$blocked_dom")
		for blocked_ip in $blocked_ips; do
			echo "> testing $UNBLOCKED_DOM on $blocked_ip ($blocked_dom)"
			curl_test "$1" "$UNBLOCKED_DOM" "$blocked_ip" detail
		done
	else
		echo "$UNBLOCKED_DOM" is not available. skipping this test.
	fi
}

curl_has_reason_to_continue() {
	# $1 - curl return code
	for c in 1 2 3 4 6 27; do
		[ "$1" = $c ] && return 1
	done
	return 0
}

check_domain_prolog() {
	# $1 - test function
	# $2 - port
	# $3 - domain

	local code

	echo
	echo \* "$1" ipv"$IPV" "$3"

	echo "- checking without DPI bypass"
	curl_test "$1" "$3" && {
		report_append "ipv${IPV} $3 $1: working without bypass"
		[ "$SCANLEVEL" = force ] || return 1
	}
	code=$?
	curl_has_reason_to_continue $code || {
		report_append "ipv${IPV} $3 $1: test aborted, no reason to continue. curl code $(curl_translate_code $code)"
		return 1
	}
	return 0
}
check_domain_http_tcp() {
	# $1 - test function
	# $2 - port
	# $3 - encrypted test: 0 = plain, 1 - encrypted with server reply risk, 2 - encrypted without server reply risk
	# $4 - domain

	# in case was interrupted before
	pktws_ipt_unprepare_tcp "$2"
	ws_kill

	check_domain_prolog "$1" "$2" "$4" || return

	check_dpi_ip_block "$1" "$4"

	[ "$SKIP_TPWS" = 1 ] || {
		echo
		tpws_check_domain_http_bypass "$1" "$3" "$4"
	}

	[ "$SKIP_PKTWS" = 1 ] || {
		echo
		echo preparing $PKTWSD redirection
		pktws_ipt_prepare_tcp "$2"

		pktws_check_domain_http_bypass "$1" "$3" "$4"

		echo clearing $PKTWSD redirection
		pktws_ipt_unprepare_tcp "$2"
	}
}
check_domain_http_udp() {
	# $1 - test function
	# $2 - port
	# $3 - domain

	# in case was interrupted before
	pktws_ipt_unprepare_udp "$2"
	ws_kill

	check_domain_prolog "$1" "$2" "$3" || return

	[ "$SKIP_PKTWS" = 1 ] || {
		echo
		echo preparing $PKTWSD redirection
		pktws_ipt_prepare_udp "$2"

		pktws_check_domain_http3_bypass "$1" "$3"

		echo clearing $PKTWSD redirection
		pktws_ipt_unprepare_udp "$2"
	}
}

check_domain_http() {
	# $1 - domain
	check_domain_http_tcp curl_test_http 80 0 "$1"
}
check_domain_https_tls12() {
	# $1 - domain
	check_domain_http_tcp curl_test_https_tls12 443 1 "$1"
}
check_domain_https_tls13() {
	# $1 - domain
	check_domain_http_tcp curl_test_https_tls13 443 2 "$1"
}
check_domain_http3() {
	# $1 - domain
	check_domain_http_udp curl_test_http3 443 "$1"
}

configure_ip_version() {
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
configure_curl_opt() {
	# wolfssl: --tlsv1.x mandates exact SSL version, tls-max not supported
	# openssl: --tlsv1.x means "version equal or greater", tls-max supported
	TLSMAX12=
	TLSMAX13=
	curl_supports_tlsmax && {
		TLSMAX12="--tls-max 1.2"
		TLSMAX13="--tls-max 1.3"
	}
	TLS13=
	curl_supports_tls13 && TLS13=1
	HTTP3=
	curl_supports_http3 && HTTP3=1
}

linux_ipv6_defrag_can_be_disabled() {
	linux_min_version 4 16
}

configure_defrag() {
	IP6_DEFRAG_DISABLE=

	[ "$IPVS" = 4 ] && return

	[ "$UNAME" = "Linux" ] && {
		linux_ipv6_defrag_can_be_disabled || {
			echo "WARNING ! IPv6 defrag can only be effectively disabled in Linux kernel 4.16+"
			echo "WARNING ! IPv6 ipfrag tests are disabled"
			echo
			return
		}
	}

	case "$FWTYPE" in
	iptables)
		if ipt6_has_raw; then
			if ipt6_has_frag; then
				IP6_DEFRAG_DISABLE=1
			else
				echo "WARNING ! ip6tables does not have '-m frag' module, IPv6 ipfrag tests are disabled"
				echo
			fi
		else
			echo "WARNING ! ip6tables raw table is not available, IPv6 ipfrag tests are disabled"
			echo
		fi
		[ -n "$IP6_DEFRAG_DISABLE" ] && {
			local ipexe="$(readlink -f $(whichq ip6tables))"
			if contains "$ipexe" nft; then
				echo "WARNING ! IPv6 ipfrag tests may have no effect if ip6tables-nft is used. current ip6tables point to: $ipexe"
			else
				echo "WARNING ! IPv6 ipfrag tests may have no effect if ip6table_raw kernel module is not loaded with parameter: raw_before_defrag=1"
			fi
			echo
		}
		;;
	*)
		IP6_DEFRAG_DISABLE=1
		;;
	esac
}

ask_params() {
	echo
	echo NOTE ! this test should be run with zapret or any other bypass software disabled, without VPN
	echo

	curl_supports_connect_to || {
		echo "installed curl does not support --connect-to option. pls install at least curl 7.49"
		echo "current curl version:"
		$CURL --version
		exitp 1
	}

	echo "specify domain(s) to test. multiple domains are space separated."
	printf "domain(s) (default: $DOMAINS): "
	local dom
	read dom
	[ -n "$dom" ] && DOMAINS="$dom"

	local IPVS_def=4
	# Yandex public DNS
	pingtest 6 2a02:6b8::feed:0ff && IPVS_def=46
	printf "ip protocol version(s) - 4, 6 or 46 for both (default: $IPVS_def): "
	read IPVS
	[ -n "$IPVS" ] || IPVS=$IPVS_def
	[ "$IPVS" = 4 -o "$IPVS" = 6 -o "$IPVS" = 46 ] || {
		echo 'invalid ip version(s). should be 4, 6 or 46.'
		exitp 1
	}
	[ "$IPVS" = 46 ] && IPVS="4 6"

	configure_curl_opt

	ENABLE_HTTP=1
	echo
	ask_yes_no_var ENABLE_HTTP "check HTTP"

	ENABLE_HTTPS_TLS12=1
	echo
	ask_yes_no_var ENABLE_HTTPS_TLS12 "check HTTPS TLS 1.2"

	ENABLE_HTTPS_TLS13=0
	echo
	if [ -n "$TLS13" ]; then
		echo "TLS 1.3 uses encrypted ServerHello. DPI cannot check domain name in server response."
		echo "This can allow more bypass strategies to work."
		echo "What works for TLS 1.2 will also work for TLS 1.3 but not vice versa."
		echo "Most sites nowadays support TLS 1.3 but not all. If you can't find a strategy for TLS 1.2 use this test."
		echo "TLS 1.3 only strategy is better than nothing."
		ask_yes_no_var ENABLE_HTTPS_TLS13 "check HTTPS TLS 1.3"
	else
		echo "installed curl version does not support TLS 1.3 . tests disabled."
	fi

	ENABLE_HTTP3=0
	echo
	if [ -n "$HTTP3" ]; then
		echo "make sure target domain(s) support QUIC or result will be negative in any case"
		ENABLE_HTTP3=1
		ask_yes_no_var ENABLE_HTTP3 "check HTTP3 QUIC"
	else
		echo "installed curl version does not support HTTP3 QUIC. tests disabled."
	fi

	IGNORE_CA=0
	CURL_OPT=
	[ $ENABLE_HTTPS_TLS13 = 1 -o $ENABLE_HTTPS_TLS12 = 1 ] && {
		echo
		echo "on limited systems like OpenWrt CA certificates might not be installed to preserve space"
		echo "in such a case curl cannot verify server certificate and you should either install ca-bundle or disable verification"
		echo "however disabling verification will break HTTPS check if ISP does MitM attack and substitutes server certificate"
		ask_yes_no_var IGNORE_CA "do not verify server certificate"
		[ "$IGNORE_CA" = 1 ] && CURL_OPT=-k
	}

	echo
	echo "sometimes ISPs use multiple DPIs or load balancing. bypass strategies may work unstable."
	printf "how many times to repeat each test (default: 1): "
	read REPEATS
	REPEATS=$((0 + ${REPEATS:-1}))
	[ "$REPEATS" = 0 ] && {
		echo invalid repeat count
		exitp 1
	}

	echo
	echo quick - scan as fast as possible to reveal any working strategy
	echo standard - do investigation what works on your DPI
	echo force - scan maximum despite of result
	SCANLEVEL=${SCANLEVEL:-standard}
	ask_list SCANLEVEL "quick standard force" "$SCANLEVEL"
	# disable tpws checks by default in quick mode
	[ "$SCANLEVEL" = quick -a -z "$SKIP_TPWS" ] && SKIP_TPWS=1

	echo

	configure_defrag
}

ping_with_fix() {
	local ret
	$PING "$2" "$1" >/dev/null 2>/dev/null
	ret=$?
	# can be because of unsupported -4 option
	if [ "$ret" = 2 -o "$ret" = 64 ]; then
		ping "$2" "$1" >/dev/null
	else
		return $ret
	fi
}

pingtest() {
	# $1 - IP version: 4 or 6
	# $2 - domain or IP

	# ping command can vary a lot. some implementations have -4/-6 options. others don.t
	# WARNING ! macOS ping6 command does not have timeout option. ping6 will fail

	local PING=ping ret
	if [ "$1" = 6 ]; then
		if exists ping6; then
			PING=ping6
		else
			PING="ping -6"
		fi
	else
		if [ "$UNAME" = Darwin -o "$UNAME" = FreeBSD -o "$UNAME" = OpenBSD ]; then
			# ping by default pings IPv4, ping6 only pings IPv6
			# in FreeBSD -4/-6 options are supported, in others not
			PING=ping
		else
			# this can be Linux or cygwin
			# in Linux it's not possible for sure to figure out if it supports -4/-6. only try and check for result code=2 (invalid option)
			PING="ping -4"
		fi
	fi
	case "$UNAME" in
	Darwin)
		$PING -c 1 -t 1 "$2" >/dev/null 2>/dev/null
		# WARNING ! macOS ping6 command does not have timeout option. ping6 will fail. but without timeout is not an option.
		;;
	OpenBSD)
		$PING -c 1 -w 1 "$2" >/dev/null
		;;
	CYGWIN)
		if starts_with "$(which ping)" /cygdrive; then
			# cygwin does not have own ping by default. use Windows PING.
			$PING -n 1 -w 1000 "$2" >/dev/null
		else
			ping_with_fix "$2" '-c 1 -w 1'
		fi
		;;
	*)
		ping_with_fix "$2" '-c 1 -W 1'
		;;
	esac
}
dnstest() {
	# $1 - DNS server. empty for system resolver
	"$LOOKUP" w3.org "$1" >/dev/null 2>/dev/null
}
find_working_public_dns() {
	local dns
	for dns in $DNSCHECK_DNS; do
		pingtest 4 "$dns" && dnstest "$dns" && {
			PUBDNS=$dns
			return 0
		}
	done
	return 1
}
lookup4() {
	# $1 - domain
	# $2 - DNS
	case "$LOOKUP" in
	nslookup)
		if is_linked_to_busybox nslookup; then
			nslookup "$1" "$2" 2>/dev/null | sed -e '1,3d' -nre 's/^.*:[^0-9]*(([0-9]{1,3}\.){3}[0-9]{1,3}).*$/\1/p'
		else
			nslookup "$1" "$2" 2>/dev/null | sed -e '1,3d' -nre 's/^[^0-9]*(([0-9]{1,3}\.){3}[0-9]{1,3}).*$/\1/p'
		fi
		;;
	host)
		host -t A "$1" "$2" | grep "has address" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'
		;;
	esac
}
check_dns_spoof() {
	# $1 - domain
	# $2 - public DNS

	# Windows version of mdig outputs 0D0A line ending. remove 0D.
	echo "$1" | "$MDIG" --family=4 | tr -d '\r' >"$DNSCHECK_DIG1"
	lookup4 "$1" "$2" >"$DNSCHECK_DIG2"
	# check whether system resolver returns anything other than public DNS
	grep -qvFf "$DNSCHECK_DIG2" "$DNSCHECK_DIG1"
}
check_dns_cleanup() {
	rm -f "$DNSCHECK_DIG1" "$DNSCHECK_DIG2" "$DNSCHECK_DIGS" 2>/dev/null
}
check_dns() {
	local C1 C2 dom

	echo \* checking DNS

	[ -f "$DNSCHECK_DIGS" ] && rm -f "$DNSCHECK_DIGS"

	dnstest || {
		echo "-- DNS is not working. It's either misconfigured or blocked or you don't have inet access."
		return 1
	}
	echo system DNS is working

	if find_working_public_dns; then
		echo comparing system resolver to public DNS: "$PUBDNS"
		for dom in $DNSCHECK_DOM; do
			if check_dns_spoof "$dom" "$PUBDNS"; then
				echo "$dom": MISMATCH
				echo -- system resolver:
				cat "$DNSCHECK_DIG1"
				echo -- "$PUBDNS":
				cat "$DNSCHECK_DIG2"
				check_dns_cleanup
				echo -- POSSIBLE DNS HIJACK DETECTED. ZAPRET WILL NOT HELP YOU IN CASE DNS IS SPOOFED !!!
				echo -- DNS CHANGE OR DNSCRYPT MAY BE REQUIRED
				return 1
			else
				echo "$dom": OK
				cat "$DNSCHECK_DIG1" >>"$DNSCHECK_DIGS"
			fi
		done
	else
		echo no working public DNS was found. looks like public DNS blocked.
		for dom in $DNSCHECK_DOM; do echo "$dom"; done | "$MDIG" --threads=10 --family=4 >"$DNSCHECK_DIGS"
	fi

	echo checking resolved IP uniqueness for: "$DNSCHECK_DOM"
	echo censor\'s DNS can return equal result for multiple blocked domains.
	C1=$(wc -l <"$DNSCHECK_DIGS")
	C2=$(sort -u "$DNSCHECK_DIGS" | wc -l)
	[ "$C1" -eq 0 ] &&
		{
			echo "-- DNS is not working. It's either misconfigured or blocked or you don't have inet access."
			check_dns_cleanup
			return 1
		}
	[ "$C1" = "$C2" ] ||
		{
			echo system DNS resolver has returned equal IPs for some domains checked above \("$C1" total, "$C2" unique\)
			echo non-unique IPs:
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

unprepare_all() {
	# make sure we are not in a middle state that impacts connectivity
	rm -f "$HDRTEMP"
	[ -n "$IPV" ] && {
		pktws_ipt_unprepare_tcp 80
		pktws_ipt_unprepare_tcp 443
		pktws_ipt_unprepare_udp 443
	}
	ws_kill
	cleanup
}
sigint() {
	echo
	echo terminating...
	unprepare_all
	exitp 1
}
sigint_cleanup() {
	cleanup
	exit 1
}
sigsilent() {
	# must not write anything here to stdout
	unprepare_all
	exit 1
}

fsleep_setup
fix_sbin_path
check_system
[ "$UNAME" = CYGWIN ] || require_root
check_prerequisites
trap sigint_cleanup INT
[ "$SKIP_DNSCHECK" = 1 ] || check_dns
check_virt
ask_params
trap - INT

PID=
NREPORT=
unset WF
trap sigint INT
trap sigsilent PIPE
trap sigsilent HUP
for dom in $DOMAINS; do
	for IPV in $IPVS; do
		configure_ip_version
		[ "$ENABLE_HTTP" = 1 ] && {
			check_domain_port_block "$dom" "$HTTP_PORT"
			check_domain_http "$dom"
		}
		[ "$ENABLE_HTTPS_TLS12" = 1 -o "$ENABLE_HTTPS_TLS13" = 1 ] && check_domain_port_block "$dom" "$HTTPS_PORT"
		[ "$ENABLE_HTTPS_TLS12" = 1 ] && check_domain_https_tls12 "$dom"
		[ "$ENABLE_HTTPS_TLS13" = 1 ] && check_domain_https_tls13 "$dom"
		[ "$ENABLE_HTTP3" = 1 ] && check_domain_http3 "$dom"
	done
done
trap - HUP
trap - PIPE
trap - INT

cleanup

echo
echo \* SUMMARY
report_print
echo
echo "Please note this SUMMARY does not guarantee a magic pill for you to copy/paste and be happy."
echo "Understanding how strategies work is very desirable."
echo "This knowledge allows to understand better which strategies to prefer and which to avoid if possible, how to combine strategies."
echo "Blockcheck does it's best to prioritize good strategies but it's not bullet-proof."
echo "It was designed not as magic pill maker but as a DPI bypass test tool."

exitp 0
