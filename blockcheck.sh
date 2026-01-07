#!/bin/sh

EXEDIR="$(dirname "$0")"
EXEDIR="$(cd "$EXEDIR"; pwd)"
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

DOMAINS_DEFAULT=${DOMAINS_DEFAULT:-rutracker.org}
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
CURL_MAX_TIME=${CURL_MAX_TIME:-2}
CURL_MAX_TIME_QUIC=${CURL_MAX_TIME_QUIC:-$CURL_MAX_TIME}
CURL_MAX_TIME_DOH=${CURL_MAX_TIME_DOH:-2}
MIN_TTL=${MIN_TTL:-1}
MAX_TTL=${MAX_TTL:-12}
USER_AGENT=${USER_AGENT:-Mozilla}
HTTP_PORT=${HTTP_PORT:-80}
HTTPS_PORT=${HTTPS_PORT:-443}
QUIC_PORT=${QUIC_PORT:-443}
UNBLOCKED_DOM=${UNBLOCKED_DOM:-iana.org}
PARALLEL_OUT=/tmp/zapret_parallel

HDRTEMP=/tmp/zapret-hdr

NFT_TABLE=blockcheck

DNSCHECK_DNS=${DNSCHECK_DNS:-8.8.8.8 1.1.1.1 77.88.8.1}
DNSCHECK_DOM=${DNSCHECK_DOM:-pornhub.com ntc.party rutracker.org www.torproject.org bbc.com}
DOH_SERVERS=${DOH_SERVERS:-"https://cloudflare-dns.com/dns-query https://dns.google/dns-query https://dns.quad9.net/dns-query https://dns.adguard.com/dns-query https://common.dot.dns.yandex.net/dns-query"}
DNSCHECK_DIG1=/tmp/dig1.txt
DNSCHECK_DIG2=/tmp/dig2.txt
DNSCHECK_DIGS=/tmp/digs.txt

IPSET_FILE=/tmp/blockcheck_ipset.txt

unset PF_STATUS
PF_RULES_SAVE=/tmp/pf-zapret-save.conf

unset ALL_PROXY

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

	[ "$BATCH" = 1 ] || {
		echo
		echo press enter to continue
		read A
	}
	exit $1
}

pf_is_avail()
{
	[ -c /dev/pf ]
}
pf_status()
{
	pfctl -qsi  | sed -nre "s/^Status: ([^ ]+).*$/\1/p"
}
pf_is_enabled()
{
	[ "$(pf_status)" = Enabled ]
}
pf_save()
{
	PF_STATUS=0
	pf_is_enabled && PF_STATUS=1
	[ "$UNAME" = "OpenBSD" ] && pfctl -sr >"$PF_RULES_SAVE"
}
pf_restore()
{
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
pf_clean()
{
	rm -f "$PF_RULES_SAVE"
}
opf_dvtws_anchor()
{
	# $1 - tcp/udp
	# $2 - port
	# $3 - ip list
	local iplist family=inet
	[ "$IPV" = 6 ] && family=inet6
	make_comma_list iplist "$3"
	echo "set reassemble no"
	[ "$1" = tcp ] && echo "pass in quick $family proto $1 from {$iplist} port $2 flags SA/SA divert-packet port $IPFW_DIVERT_PORT no state"
	echo "pass in  quick $family proto $1 from {$iplist} port $2 no state"
	echo "pass out quick $family proto $1 to   {$iplist} port $2 divert-packet port $IPFW_DIVERT_PORT no state"
	echo "pass"
}
opf_prepare_dvtws()
{
	# $1 - tcp/udp
	# $2 - port
	# $3 - ip list
	opf_dvtws_anchor $1 $2 "$3" | pfctl -qf -
	pfctl -qe
}

cleanup()
{
	case "$UNAME" in
		OpenBSD)
		    pf_clean
		    ;;
	esac
}

IPT()
{
	$IPTABLES -C "$@" >/dev/null 2>/dev/null || $IPTABLES -I "$@"
}
IPT_DEL()
{
	$IPTABLES -C "$@" >/dev/null 2>/dev/null && $IPTABLES -D "$@"
}
IPT_ADD_DEL()
{
	on_off_function IPT IPT_DEL "$@"
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

doh_resolve()
{
	# $1 - ip version 4/6
	# $2 - hostname
	# $3 - doh server URL. use $DOH_SERVER if empty
	$MDIG --family=$1 --dns-make-query=$2 | $CURL --max-time $CURL_MAX_TIME_DOH -s --data-binary @- -H "Content-Type: application/dns-message" "${3:-$DOH_SERVER}" | $MDIG --dns-parse-query
}
doh_find_working()
{
	local doh

	[ -n "$DOH_SERVER" ] && return 0
	echo "* searching working DoH server"
	DOH_SERVER=
	for doh in $DOH_SERVERS; do
		echo -n "$doh : "
		if doh_resolve 4 iana.org $doh >/dev/null 2>/dev/null; then
			echo OK
			DOH_SERVER="$doh"
			return 0
		else
			echo FAIL
		fi
	done
	echo all DoH servers failed
	return 1
}

mdig_vars()
{
	# $1 - ip version 4/6
	# $2 - hostname

	hostvar=$(echo $2 | sed -e 's/[\.-]/_/g')
	cachevar=DNSCACHE_${hostvar}_$1
	countvar=${cachevar}_COUNT
	eval count=\$${countvar}
}
mdig_cache()
{
	# $1 - ip version 4/6
	# $2 - hostname
	local hostvar cachevar countvar count ip ips
	mdig_vars "$@"
	[ -n "$count" ] || {
		# windows version of mdig outputs 0D0A line ending. remove 0D.
		if [ "$SECURE_DNS" = 1 ]; then
			ips="$(echo $2 | doh_resolve $1 $2 | tr -d '\r' | xargs)"
		else
			ips="$(echo $2 | "$MDIG" --family=$1 | tr -d '\r' | xargs)"
		fi
		[ -n "$ips" ] || return 1
		count=0
		for ip in $ips; do
			eval ${cachevar}_$count=$ip
			count=$(($count+1))
		done
		eval $countvar=$count
	}
	return 0
}
mdig_resolve()
{
	# $1 - ip version 4/6
	# $2 - hostname

	local hostvar cachevar countvar count ip n
	mdig_vars "$@"
	if [ -n "$count" ]; then
		n=$(random 0 $(($count-1)))
		eval ip=\$${cachevar}_$n
		echo $ip
		return 0
	else
		mdig_cache "$@" && mdig_resolve "$@"
	fi
}
mdig_resolve_all()
{
	# $1 - ip version 4/6
	# $2 - hostname

	local hostvar cachevar countvar count ip ips n
	mdig_vars "$@"
	if [ -n "$count" ]; then
		n=0
		while [ "$n" -le $count ]; do
			eval ip=\$${cachevar}_$n
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

netcat_setup()
{
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
netcat_test()
{
	# $1 - ip
	# $2 - port
	local cmd
	netcat_setup && {
		cmd="$NCAT -z -w 2 $1 $2"
		echo $cmd
		$cmd 2>&1
	}
}

tpws_can_fix_seg()
{
	# fix-seg requires kernel 4.6+
	"$TPWS" --port 1 --dry-run --fix-seg >/dev/null 2>/dev/null
}

check_system()
{
	echo \* checking system

	UNAME=$(uname)
	SUBSYS=
	FIX_SEG=
	local s

	# can be passed FWTYPE=iptables to override default nftables preference
	case "$UNAME" in
		Linux)
			PKTWS="$NFQWS"
			PKTWSD=nfqws
			if [ -x "$TPWS" ] ; then
				if tpws_can_fix_seg ; then
					echo tpws supports --fix-seg on this system
					FIX_SEG='--fix-seg'
				else
					echo tpws does not support --fix-seg on this system
				fi
			fi
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
			# ts fooling requires timestamps. they are disabled by default in windows.
			echo enabling tcp timestamps
			netsh interface tcp set global timestamps=enabled >/dev/null
			;;
		*)
			echo $UNAME not supported
			exitp 5
	esac
	echo $UNAME${SUBSYS:+/$SUBSYS} detected
	echo -n 'kernel: '
	if [ -f "/proc/version" ]; then
		cat /proc/version
	else
		uname -a
	fi
	echo firewall type is $FWTYPE
	echo CURL=$CURL
	$CURL --version
}

zp_already_running()
{
	case "$UNAME" in
		CYGWIN)
			win_process_exists $PKTWSD || win_process_exists goodbyedpi
			;;
		*)
			process_exists $PKTWSD || process_exists tpws
	esac
}
check_already()
{
	echo \* checking already running DPI bypass processes
	if zp_already_running; then
		echo "!!! WARNING. some dpi bypass processes already running !!!"
		echo "!!! WARNING. blockcheck requires all DPI bypass methods disabled !!!"
		echo "!!! WARNING. pls stop all dpi bypass instances that may interfere with blockcheck !!!"
	fi
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
	
	[ "$SKIP_PKTWS" = 1 -o "$UNAME" = Darwin -o -x "$PKTWS" ] && [ "$SKIP_TPWS" = 1 -o "$UNAME" = CYGWIN -o -x "$TPWS" ] && [ -x "$MDIG" ] || {
		local target
		case $UNAME in
			Darwin)
				target="mac"
				;;
			OpenBSD)
				target="bsd"
				;;
		esac
		echo $PKTWS or $TPWS or $MDIG is not available. run \"$ZAPRET_BASE/install_bin.sh\" or \`make -C \"$ZAPRET_BASE\" $target\`
		exitp 6
	}

	local prog progs='curl'
	[ "$SKIP_PKTWS" = 1 ] || {
		case "$UNAME" in
			Linux)
				case "$FWTYPE" in
					iptables)
						ipt_has_nfq || {
							echo NFQUEUE iptables or ip6tables target is missing. pls install modules.
							exitp 6
						}
						progs="$progs iptables ip6tables"
						;;
					nftables)
						nft_has_nfq || {
							echo nftables queue support is not available. pls install modules.
							exitp 6
						}
						progs="$progs nft"
						;;
				esac
				;;
			FreeBSD)
				freebsd_modules_loaded ipfw ipdivert || {
					echo ipfw or ipdivert kernel module not loaded
						exitp 6
				}
				[ "$(sysctl -qn net.inet.ip.fw.enable)" = 0 -o "$(sysctl -qn net.inet6.ip6.fw.enable)" = 0 ] && {
					echo ipfw is disabled. use : ipfw enable firewall
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
				progs="$progs ipfw"
				;;
			OpenBSD|Darwin)
				pf_is_avail || {
					echo pf is not available
					exitp 6
				}
				pf_save
				progs="$progs pfctl"
				;;
		esac
	}

	case "$UNAME" in
		CYGWIN)
			SKIP_TPWS=1
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
	$CURL --tlsv1.3 -Is -o /dev/null --max-time 1 http://127.0.0.1:65535 2>/dev/null
	# return code 2 = init failed. likely bad command line options
	[ $? = 2 ] && return 1
	# curl can have tlsv1.3 key present but ssl library without TLS 1.3 support
	# this is online test because there's no other way to trigger library incompatibility case
	$CURL --tlsv1.3 --max-time 1 -Is -o /dev/null https://iana.org 2>/dev/null
	r=$?
	[ $r != 4 -a $r != 35 ]
}

curl_supports_tlsmax()
{
	# supported only in OpenSSL and LibreSSL
	$CURL --version | grep -Fq -e OpenSSL -e LibreSSL -e BoringSSL -e GnuTLS -e quictls || return 1
	# supported since curl 7.54
	$CURL --tls-max 1.2 -Is -o /dev/null --max-time 1 http://127.0.0.1:65535 2>/dev/null
	# return code 2 = init failed. likely bad command line options
	[ $? != 2 ]
}

curl_supports_connect_to()
{
	$CURL --connect-to 127.0.0.1:: -o /dev/null --max-time 1 http://127.0.0.1:65535 2>/dev/null
	[ "$?" != 2 ]
}

curl_supports_http3()
{
	# if it has http3 : curl: (3) HTTP/3 requested for non-HTTPS URL
	# otherwise : curl: (2) option --http3-only: is unknown
	$CURL --connect-to 127.0.0.1:: -o /dev/null --max-time 1 --http3-only http://127.0.0.1:65535 2>/dev/null
	[ "$?" != 2 ]
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

curl_with_subst_ip()
{
	# $1 - domain
	# $2 - port
	# $3 - ip
	# $4+ - curl params
	local ip="$3"
	case "$ip" in
		*:*) ip="[$ip]" ;;
	esac
	local connect_to="--connect-to $1::$ip${2:+:$2}" arg
	shift ; shift ; shift
	[ "$CURL_VERBOSE" = 1 ] && arg="-v"
	[ "$CURL_CMD" = 1 ] && echo $CURL ${arg:+$arg }$connect_to "$@"
	ALL_PROXY="$ALL_PROXY" $CURL ${arg:+$arg }$connect_to "$@"
}
curl_with_dig()
{
	# $1 - ip version : 4/6
	# $2 - domain name
	# $3 - port
	# $4+ - curl params
	local dom=$2 port=$3
	local ip=$(mdig_resolve $1 $dom)
	shift ; shift ; shift
	if [ -n "$ip" ]; then
		curl_with_subst_ip $dom $port $ip "$@"
	else
		return 6
	fi
}
curl_probe()
{
	# $1 - ip version : 4/6
	# $2 - domain name
	# $3 - port
	# $4 - subst ip
	# $5+ - curl params
	local ipv=$1 dom=$2 port=$3 subst=$4
	shift; shift; shift; shift
	if [ -n "$subst" ]; then
		curl_with_subst_ip $dom $port $subst "$@"
	else
		curl_with_dig $ipv $dom $port "$@"
	fi
}
curl_test_http()
{
	# $1 - ip version : 4/6
	# $2 - domain name
	# $3 - subst ip
	# $4 - "detail" - detail info

	local code loc hdrt="${HDRTEMP}_${!:-$$}.txt"
	curl_probe $1 $2 $HTTP_PORT "$3" -SsD "$hdrt" -A "$USER_AGENT" --max-time $CURL_MAX_TIME $CURL_OPT "http://$2" -o /dev/null 2>&1 || {
		code=$?
		rm -f "$hdrt"
		return $code
	}
	if [ "$4" = "detail" ] ; then
		head -n 1 "$hdrt"
		grep "^[lL]ocation:" "$hdrt"
	else
		code=$(hdrfile_http_code "$hdrt")
		[ "$code" = 301 -o "$code" = 302 -o "$code" = 307 -o "$code" = 308 ] && {
			loc=$(hdrfile_location "$hdrt")
			echo "$loc" | grep -qE "^https?://.*$2(/|$)" ||
			echo "$loc" | grep -vqE '^https?://' || {
				echo suspicious redirection $code to : $loc
				rm -f "$hdrt"
				return 254
			}
		}
	fi
	rm -f "$hdrt"
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
	# $3 - subst ip

	# do not use tls 1.3 to make sure server certificate is not encrypted
	curl_probe $1 $2 $HTTPS_PORT "$3" -ISs -A "$USER_AGENT" --max-time $CURL_MAX_TIME $CURL_OPT --tlsv1.2 $TLSMAX12 "https://$2" -o /dev/null 2>&1
}
curl_test_https_tls13()
{
	# $1 - ip version : 4/6
	# $2 - domain name
	# $3 - subst ip

	# force TLS1.3 mode
	curl_probe $1 $2 $HTTPS_PORT "$3" -ISs -A "$USER_AGENT" --max-time $CURL_MAX_TIME $CURL_OPT --tlsv1.3 $TLSMAX13 "https://$2" -o /dev/null 2>&1
}

curl_test_http3()
{
	# $1 - ip version : 4/6
	# $2 - domain name

	# force QUIC only mode without tcp
	curl_with_dig $1 $2 $QUIC_PORT -ISs -A "$USER_AGENT" --max-time $CURL_MAX_TIME_QUIC --http3-only $CURL_OPT "https://$2" -o /dev/null 2>&1
}

ipt_aux_scheme()
{
	# $1 - 1 - add , 0 - del
	# $2 - tcp/udp
	# $3 - port

	# to avoid possible INVALID state drop
	[ "$2" = tcp ] && IPT_ADD_DEL $1 INPUT -p $2 --sport $3 ! --syn -j ACCEPT

	local icmp_filter="-p icmp -m icmp --icmp-type"
	[ "$IPV" = 6 ] && icmp_filter="-p icmpv6 -m icmp6 --icmpv6-type"
	IPT_ADD_DEL $1 INPUT $icmp_filter time-exceeded -m connmark --mark $DESYNC_MARK/$DESYNC_MARK -j DROP 

	# for strategies with incoming packets involved (autottl)
	IPT_ADD_DEL $1 OUTPUT -p $2 --dport $3 -m conntrack --ctstate INVALID -j ACCEPT
	if [ "$IPV" = 6 -a -n "$IP6_DEFRAG_DISABLE" ]; then
		# the only way to reliable disable ipv6 defrag. works only in 4.16+ kernels
		IPT_ADD_DEL $1 OUTPUT -t raw -p $2 -m frag -j CT --notrack
	elif [ "$IPV" = 4 ]; then
		# enable fragments
		IPT_ADD_DEL $1 OUTPUT -f -j ACCEPT
	fi
	# enable everything generated by nfqws (works only in OUTPUT, not in FORWARD)
	# raw table may not be present
	IPT_ADD_DEL $1 OUTPUT -t raw -m mark --mark $DESYNC_MARK/$DESYNC_MARK -j CT --notrack
}
ipt_scheme()
{
	# $1 - tcp/udp
	# $2 - port
	# $3 - ip list

	local ip

	$IPTABLES -t mangle -N blockcheck_output 2>/dev/null
	$IPTABLES -t mangle -F blockcheck_output
	IPT OUTPUT -t mangle -j blockcheck_output

	# prevent loop
	$IPTABLES -t mangle -A blockcheck_output -m mark --mark $DESYNC_MARK/$DESYNC_MARK -j RETURN
	$IPTABLES -t mangle -A blockcheck_output ! -p $1 -j RETURN
	$IPTABLES -t mangle -A blockcheck_output -p $1 ! --dport $2 -j RETURN

	for ip in $3; do
		$IPTABLES -t mangle -A blockcheck_output -d $ip -j CONNMARK --or-mark $DESYNC_MARK
		$IPTABLES -t mangle -A blockcheck_output -d $ip -j NFQUEUE --queue-num $QNUM
	done

	ipt_aux_scheme 1 $1 $2
}
nft_scheme()
{
	# $1 - tcp/udp
	# $2 - port
	# $3 - ip list

	local iplist ipver=$IPV
	[ "$IPV" = 6 ] || ipver=
	make_comma_list iplist $3

	nft add table inet $NFT_TABLE
	nft "add chain inet $NFT_TABLE postnat { type filter hook output priority 102; }"
	nft "add rule inet $NFT_TABLE postnat meta nfproto ipv${IPV} $1 dport $2 mark and $DESYNC_MARK == 0 ip${ipver} daddr {$iplist} ct mark set ct mark or $DESYNC_MARK queue num $QNUM"
	# for strategies with incoming packets involved (autottl)
	nft "add chain inet $NFT_TABLE prenat { type filter hook prerouting priority -102; }"
	# enable everything generated by nfqws (works only in OUTPUT, not in FORWARD)
	nft "add chain inet $NFT_TABLE predefrag { type filter hook output priority -402; }"
	nft "add rule inet $NFT_TABLE predefrag meta nfproto ipv${IPV} mark and $DESYNC_MARK !=0 notrack"
	[ "$IPV" = 4 ] && {
		nft "add rule inet $NFT_TABLE prenat icmp type time-exceeded ct mark and $DESYNC_MARK != 0 drop"
		nft "add rule inet $NFT_TABLE prenat icmp type time-exceeded ct state invalid drop"
	}
	[ "$IPV" = 6 ] && {
		nft "add rule inet $NFT_TABLE prenat icmpv6 type time-exceeded ct mark and $DESYNC_MARK != 0 drop"
		nft "add rule inet $NFT_TABLE prenat icmpv6 type time-exceeded ct state invalid drop"
	}
}

pktws_ipt_prepare()
{
	# $1 - tcp/udp
	# $2 - port
	# $3 - ip list

	local ip

	case "$FWTYPE" in
		iptables)
			ipt_scheme $1 $2 "$3"
			;;
		nftables)
			nft_scheme $1 $2 "$3"
			;;
		ipfw)
			# disable PF to avoid interferences
			pf_is_avail && pfctl -qd
			for ip in $3; do
				IPFW_ADD divert $IPFW_DIVERT_PORT $1 from me to $ip $2 proto ip${IPV} out not diverted
			done
			;;
		opf)
			opf_prepare_dvtws $1 $2 "$3"
			;;
		windivert)
			WF="--wf-l3=ipv${IPV} --wf-${1}=$2"
			rm -f "$IPSET_FILE"
			for ip in $3; do
				echo $ip >>"$IPSET_FILE"
			done
			;;

	esac
}
pktws_ipt_unprepare()
{
	# $1 - tcp/udp
	# $2 - port

	case "$FWTYPE" in
		iptables)
			ipt_aux_scheme 0 $1 $2
			IPT_DEL OUTPUT -t mangle -j blockcheck_output
			$IPTABLES -t mangle -F blockcheck_output 2>/dev/null
			$IPTABLES -t mangle -X blockcheck_output 2>/dev/null
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
			rm -f "$IPSET_FILE"
			;;
	esac
}

pktws_ipt_prepare_tcp()
{
	# $1 - port
	# $2 - ip list

	local ip iplist ipver

	pktws_ipt_prepare tcp $1 "$2"

	# for autottl mode
	case "$FWTYPE" in
		iptables)
			$IPTABLES -N blockcheck_input -t mangle 2>/dev/null
			$IPTABLES -F blockcheck_input -t mangle 2>/dev/null
			IPT INPUT -t mangle -j blockcheck_input
			$IPTABLES -t mangle -A blockcheck_input ! -p tcp -j RETURN
			$IPTABLES -t mangle -A blockcheck_input -p tcp ! --sport $1 -j RETURN
			$IPTABLES -t mangle -A blockcheck_input -p tcp ! --tcp-flags SYN,ACK SYN,ACK -j RETURN
			for ip in $2; do
				$IPTABLES -A blockcheck_input -t mangle -s $ip -j NFQUEUE --queue-num $QNUM
			done
			;;
		nftables)
			ipver=$IPV
			[ "$IPV" = 6 ] || ipver=
			make_comma_list iplist $2
			nft "add rule inet $NFT_TABLE prenat meta nfproto ipv${IPV} tcp sport $1 tcp flags & (syn | ack) == (syn | ack) ip${ipver} saddr {$iplist} queue num $QNUM"
			;;
		ipfw)
			for ip in $2; do
				IPFW_ADD divert $IPFW_DIVERT_PORT tcp from $ip $1 to me proto ip${IPV} tcpflags syn,ack in not diverted
			done
			;;
	esac
}
pktws_ipt_unprepare_tcp()
{
	# $1 - port
	
	pktws_ipt_unprepare tcp $1

	case "$FWTYPE" in
		iptables)
			IPT_DEL INPUT -t mangle -j blockcheck_input
			$IPTABLES -t mangle -F blockcheck_input 2>/dev/null
			$IPTABLES -t mangle -X blockcheck_input 2>/dev/null
			;;
	esac
}
pktws_ipt_prepare_udp()
{
	# $1 - port
	# $2 - ip list

	pktws_ipt_prepare udp $1 "$2"
}
pktws_ipt_unprepare_udp()
{
	# $1 - port
	
	pktws_ipt_unprepare udp $1
}

pktws_start()
{
	case "$UNAME" in
		Linux)
			"$NFQWS" --uid $TPWS_UID:$TPWS_GID --dpi-desync-fwmark=$DESYNC_MARK --qnum=$QNUM "$@" >/dev/null &
			;;
		FreeBSD|OpenBSD)
			"$DVTWS" --port=$IPFW_DIVERT_PORT "$@" >/dev/null &
			;;
		CYGWIN)
			"$WINWS" $WF --ipset="$IPSET_FILE" "$@" >/dev/null &
			;;
	esac
	PID=$!
	# give some time to initialize
	minsleep
}
tpws_start()
{
	local uid
	[ -n "$HAVE_ROOT" ] && uid="--uid $TPWS_UID:$TPWS_GID"
	"$TPWS" $uid --socks --bind-addr=127.0.0.1 --port=$SOCKS_PORT "$@" >/dev/null &
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

check_domain_port_block()
{
	# $1 - domain
	# $2 - port
	local ip ips
	echo
	echo \* port block tests ipv$IPV $1:$2
	if netcat_setup; then
		ips=$(mdig_resolve_all $IPV $1)
		if [ -n "$ips" ]; then
			for ip in $ips; do
				if netcat_test $ip $2; then
					echo $ip connects
				else
					echo $ip does not connect. netcat code $?
				fi
			done
		else
			echo "ipv${IPV} $1 does not resolve"
		fi
	else
		echo suitable netcat not found. busybox nc is not supported. pls install nmap ncat or openbsd netcat.
	fi
}

curl_test()
{
	# $1 - test function
	# $2 - domain
	# $3 - subst ip
	# $4 - param of test function
	local code=0 n=0 p pids

	if [ "$PARALLEL" = 1 ]; then
		rm -f "${PARALLEL_OUT}"*
		for n in $(seq -s ' ' 1 $REPEATS); do
			$1 "$IPV" $2 $3 "$4" >"${PARALLEL_OUT}_$n" &
			pids="${pids:+$pids }$!"
		done
		n=1
		for p in $pids; do
			[ $REPEATS -gt 1 ] && printf "[attempt $n] "
			if wait $p; then
				[ $REPEATS -gt 1 ] && echo 'AVAILABLE'
			else
				code=$?
				cat "${PARALLEL_OUT}_$n"
			fi
			n=$(($n+1))
		done
		rm -f "${PARALLEL_OUT}"*
	else
		while [ $n -lt $REPEATS ]; do
			n=$(($n+1))
			[ $REPEATS -gt 1 ] && printf "[attempt $n] "
			if $1 "$IPV" $2 $3 "$4" ; then
				[ $REPEATS -gt 1 ] && echo 'AVAILABLE'
			else
				code=$?
				[ "$SCANLEVEL" = quick ] && break
			fi
		done
	fi
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
	echo - $1 ipv$IPV $2 : tpws $3 $4 $5 $6 $7 $8 $9${TPWS_EXTRA:+ $TPWS_EXTRA}${TPWS_EXTRA_1:+ "$TPWS_EXTRA_1"}${TPWS_EXTRA_2:+ "$TPWS_EXTRA_2"}${TPWS_EXTRA_3:+ "$TPWS_EXTRA_3"}${TPWS_EXTRA_4:+ "$TPWS_EXTRA_4"}${TPWS_EXTRA_5:+ "$TPWS_EXTRA_5"}${TPWS_EXTRA_6:+ "$TPWS_EXTRA_6"}${TPWS_EXTRA_7:+ "$TPWS_EXTRA_7"}${TPWS_EXTRA_8:+ "$TPWS_EXTRA_8"}${TPWS_EXTRA_9:+ "$TPWS_EXTRA_9"}
	local ALL_PROXY="socks5://127.0.0.1:$SOCKS_PORT"
	ws_curl_test tpws_start "$@"${TPWS_EXTRA:+ $TPWS_EXTRA}${TPWS_EXTRA_1:+ "$TPWS_EXTRA_1"}${TPWS_EXTRA_2:+ "$TPWS_EXTRA_2"}${TPWS_EXTRA_3:+ "$TPWS_EXTRA_3"}${TPWS_EXTRA_4:+ "$TPWS_EXTRA_4"}${TPWS_EXTRA_5:+ "$TPWS_EXTRA_5"}${TPWS_EXTRA_6:+ "$TPWS_EXTRA_6"}${TPWS_EXTRA_7:+ "$TPWS_EXTRA_7"}${TPWS_EXTRA_8:+ "$TPWS_EXTRA_8"}${TPWS_EXTRA_9:+ "$TPWS_EXTRA_9"}
	local testf=$1 dom=$2 strategy code=$?
	[ "$code" = 0 ] && {
		shift; shift;
		strategy="$@"
		strategy_append_extra_tpws
		report_append "ipv${IPV} $dom $testf : tpws ${WF:+$WF }$strategy"
	}
	return $code
}
pktws_curl_test()
{
	# $1 - test function
	# $2 - domain
	# $3,$4,$5, ... - nfqws/dvtws params
	local testf=$1 dom=$2 strategy code

	shift; shift;
	echo - $testf ipv$IPV $dom : $PKTWSD ${WF:+$WF }${PKTWS_EXTRA_PRE:+$PKTWS_EXTRA_PRE }${PKTWS_EXTRA_PRE_1:+"$PKTWS_EXTRA_PRE_1" }${PKTWS_EXTRA_PRE_2:+"$PKTWS_EXTRA_PRE_2" }${PKTWS_EXTRA_PRE_3:+"$PKTWS_EXTRA_PRE_3" }${PKTWS_EXTRA_PRE_4:+"$PKTWS_EXTRA_PRE_4" }${PKTWS_EXTRA_PRE_5:+"$PKTWS_EXTRA_PRE_5" }${PKTWS_EXTRA_PRE_6:+"$PKTWS_EXTRA_PRE_6" }${PKTWS_EXTRA_PRE_7:+"$PKTWS_EXTRA_PRE_7" }${PKTWS_EXTRA_PRE_8:+"$PKTWS_EXTRA_PRE_8" }${PKTWS_EXTRA_PRE_9:+"$PKTWS_EXTRA_PRE_9" }$@${PKTWS_EXTRA:+ $PKTWS_EXTRA}${PKTWS_EXTRA_1:+ "$PKTWS_EXTRA_1"}${PKTWS_EXTRA_2:+ "$PKTWS_EXTRA_2"}${PKTWS_EXTRA_3:+ "$PKTWS_EXTRA_3"}${PKTWS_EXTRA_4:+ "$PKTWS_EXTRA_4"}${PKTWS_EXTRA_5:+ "$PKTWS_EXTRA_5"}${PKTWS_EXTRA_6:+ "$PKTWS_EXTRA_6"}${PKTWS_EXTRA_7:+ "$PKTWS_EXTRA_7"}${PKTWS_EXTRA_8:+ "$PKTWS_EXTRA_8"}${PKTWS_EXTRA_9:+ "$PKTWS_EXTRA_9"}
	ws_curl_test pktws_start $testf $dom ${PKTWS_EXTRA_PRE:+$PKTWS_EXTRA_PRE }${PKTWS_EXTRA_PRE_1:+"$PKTWS_EXTRA_PRE_1" }${PKTWS_EXTRA_PRE_2:+"$PKTWS_EXTRA_PRE_2" }${PKTWS_EXTRA_PRE_3:+"$PKTWS_EXTRA_PRE_3" }${PKTWS_EXTRA_PRE_4:+"$PKTWS_EXTRA_PRE_4" }${PKTWS_EXTRA_PRE_5:+"$PKTWS_EXTRA_PRE_5" }${PKTWS_EXTRA_PRE_6:+"$PKTWS_EXTRA_PRE_6" }${PKTWS_EXTRA_PRE_7:+"$PKTWS_EXTRA_PRE_7" }${PKTWS_EXTRA_PRE_8:+"$PKTWS_EXTRA_PRE_8" }${PKTWS_EXTRA_PRE_9:+"$PKTWS_EXTRA_PRE_9" }"$@"${PKTWS_EXTRA:+ $PKTWS_EXTRA}${PKTWS_EXTRA_1:+ "$PKTWS_EXTRA_1"}${PKTWS_EXTRA_2:+ "$PKTWS_EXTRA_2"}${PKTWS_EXTRA_3:+ "$PKTWS_EXTRA_3"}${PKTWS_EXTRA_4:+ "$PKTWS_EXTRA_4"}${PKTWS_EXTRA_5:+ "$PKTWS_EXTRA_5"}${PKTWS_EXTRA_6:+ "$PKTWS_EXTRA_6"}${PKTWS_EXTRA_7:+ "$PKTWS_EXTRA_7"}${PKTWS_EXTRA_8:+ "$PKTWS_EXTRA_8"}${PKTWS_EXTRA_9:+ "$PKTWS_EXTRA_9"}

	code=$?
	[ "$code" = 0 ] && {
		strategy="$@"
		strategy_append_extra_pktws
		report_append "ipv${IPV} $dom $testf : $PKTWSD ${WF:+$WF }$strategy"
	}
	return $code
}

strategy_append_extra_pktws()
{
	strategy="${strategy:+${PKTWS_EXTRA_PRE:+$PKTWS_EXTRA_PRE }${PKTWS_EXTRA_PRE_1:+"$PKTWS_EXTRA_PRE_1" }${PKTWS_EXTRA_PRE_2:+"$PKTWS_EXTRA_PRE_2" }${PKTWS_EXTRA_PRE_3:+"$PKTWS_EXTRA_PRE_3" }${PKTWS_EXTRA_PRE_4:+"$PKTWS_EXTRA_PRE_4" }${PKTWS_EXTRA_PRE_5:+"$PKTWS_EXTRA_PRE_5" }${PKTWS_EXTRA_PRE_6:+"$PKTWS_EXTRA_PRE_6" }${PKTWS_EXTRA_PRE_7:+"$PKTWS_EXTRA_PRE_7" }${PKTWS_EXTRA_PRE_8:+"$PKTWS_EXTRA_PRE_8" }${PKTWS_EXTRA_PRE_9:+"$PKTWS_EXTRA_PRE_9" }$strategy${PKTWS_EXTRA:+ $PKTWS_EXTRA}${PKTWS_EXTRA_1:+ "$PKTWS_EXTRA_1"}${PKTWS_EXTRA_2:+ "$PKTWS_EXTRA_2"}${PKTWS_EXTRA_3:+ "$PKTWS_EXTRA_3"}${PKTWS_EXTRA_4:+ "$PKTWS_EXTRA_4"}${PKTWS_EXTRA_5:+ "$PKTWS_EXTRA_5"}${PKTWS_EXTRA_6:+ "$PKTWS_EXTRA_6"}${PKTWS_EXTRA_7:+ "$PKTWS_EXTRA_7"}${PKTWS_EXTRA_8:+ "$PKTWS_EXTRA_8"}${PKTWS_EXTRA_9:+ "$PKTWS_EXTRA_9"}}"
}
strategy_append_extra_tpws()
{
	strategy="${strategy:+${PKTWS_EXTRA_PRE:+$PKTWS_EXTRA_PRE }${PKTWS_EXTRA_PRE_1:+"$PKTWS_EXTRA_PRE_1" }${PKTWS_EXTRA_PRE_2:+"$PKTWS_EXTRA_PRE_2" }${PKTWS_EXTRA_PRE_3:+"$PKTWS_EXTRA_PRE_3" }${PKTWS_EXTRA_PRE_4:+"$PKTWS_EXTRA_PRE_4" }${PKTWS_EXTRA_PRE_5:+"$PKTWS_EXTRA_PRE_5" }${PKTWS_EXTRA_PRE_6:+"$PKTWS_EXTRA_PRE_6" }${PKTWS_EXTRA_PRE_7:+"$PKTWS_EXTRA_PRE_7" }${PKTWS_EXTRA_PRE_8:+"$PKTWS_EXTRA_PRE_8" }${PKTWS_EXTRA_PRE_9:+"$PKTWS_EXTRA_PRE_9" }$strategy${TPWS_EXTRA:+ $TPWS_EXTRA}${TPWS_EXTRA_1:+ "$TPWS_EXTRA_1"}${TPWS_EXTRA_2:+ "$TPWS_EXTRA_2"}${TPWS_EXTRA_3:+ "$TPWS_EXTRA_3"}${TPWS_EXTRA_4:+ "$TPWS_EXTRA_4"}${TPWS_EXTRA_5:+ "$TPWS_EXTRA_5"}${TPWS_EXTRA_6:+ "$TPWS_EXTRA_6"}${TPWS_EXTRA_7:+ "$TPWS_EXTRA_7"}${TPWS_EXTRA_8:+ "$TPWS_EXTRA_8"}${TPWS_EXTRA_9:+ "$TPWS_EXTRA_9"}}"
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
		# trim spaces at the end
		strategy="$(echo "$strategy" | xargs)"
		echo "!!!!! $1: working strategy found for ipv${IPV} $2 : $3 $strategy !!!!!"
		echo
#		report_append "ipv${IPV} $2 $1 : $3 ${WF:+$WF }$strategy"
		return 0
	else
		echo "$1: $3 strategy for ipv${IPV} $2 not found"
		echo
		report_append "ipv${IPV} $2 $1 : $3 not working"
		return 1
	fi
}
test_has_split()
{
	contains "$1" split || contains "$1" disorder
}
test_has_fakedsplit()
{
	contains "$1" fakedsplit || contains "$1" fakeddisorder
}
test_has_fake()
{
	[ "$1" = fake ] || starts_with "$1" fake,
}
warn_fool()
{
	case "$1" in
		md5sig) echo 'WARNING ! although md5sig fooling worked it will not work on all sites. it typically works only on linux servers.'
			[ "$2" = "fakedsplit" -o "$2" = "fakeddisorder" ] && \
				echo "WARNING ! fakedsplit/fakeddisorder with md5sig fooling and low split position causes MTU overflow with multi-segment TLS (kyber)"
			;;
		datanoack) echo 'WARNING ! although datanoack fooling worked it may break NAT and may only work with external IP. Additionally it may require nftables to work correctly.' ;;
		ts) echo 'WARNING ! although ts fooling worked it will not work without timestamps being enabled in the client OS. In windows timestamps are DISABLED by default.'
	esac
}
pktws_curl_test_update_vary()
{
	# $1 - test function
	# $2 - encrypted test : 0 = plain, 1 - encrypted with server reply risk, 2 - encrypted without server reply risk
	# $3 - domain
	# $4 - desync mode
	# $5,$6,... - strategy

	local testf=$1 sec=$2 domain=$3 desync=$4 proto splits= pos fake ret=1
	local fake1=- fake2=- fake3=-
	
	shift; shift; shift; shift
	
	proto=http
	[ "$sec" = 0 ] || proto=tls
	test_has_fake $desync && {
		fake1="--dpi-desync-fake-$proto=0x00000000"
		[ "$sec" = 0 ] || {
			fake2="--dpi-desync-fake-tls=0x00000000 --dpi-desync-fake-tls=! --dpi-desync-fake-tls-mod=rnd,rndsni,dupsid"
			fake3="--dpi-desync-fake-tls-mod=rnd,dupsid,rndsni,padencap"
		}
	}
	if test_has_fakedsplit $desync ; then
		splits="method+2 midsld"
		[ "$sec" = 0 ] || splits="1 midsld"
	elif test_has_split $desync ; then
		splits="method+2 midsld"
		[ "$sec" = 0 ] || splits="1 midsld 1,midsld"
	fi
	for fake in '' "$fake1" "$fake2" "$fake3" ; do
		[ "$fake" = "-" ] && continue
		if [ -n "$splits" ]; then
			for pos in $splits ; do
				pktws_curl_test_update $testf $domain --dpi-desync=$desync "$@" --dpi-desync-split-pos=$pos $fake && {
					[ "$SCANLEVEL" = force ] || return 0
					ret=0
				}
			done
		else
			pktws_curl_test_update $testf $domain --dpi-desync=$desync "$@" $fake && {
				[ "$SCANLEVEL" = force ] || return 0
				ret=0
			}
		fi
	done

	return $ret
}

pktws_check_domain_http_bypass_()
{
	# $1 - test function
	# $2 - encrypted test : 0 = plain, 1 - encrypted with server reply risk, 2 - encrypted without server reply risk
	# $3 - domain

	local ok ttls s f f2 e desync pos fooling frag sec="$2" delta orig splits
	local need_split need_disorder need_fakedsplit need_fakeddisorder need_fake need_wssize
	local splits_http='method+2 midsld method+2,midsld'
	local splits_tls='2 1 sniext+1 sniext+4 host+1 midsld 1,midsld 1,sniext+1,host+1,midsld-2,midsld,midsld+2,endhost-1'

	[ "$sec" = 0 ] && {
		for s in '--hostcase' '--hostspell=hoSt' '--hostnospace' '--domcase' '--methodeol'; do
			pktws_curl_test_update $1 $3 $s && [ "$SCANLEVEL" = quick ] && return
		done
	}

	ttls=$(seq -s ' ' $MIN_TTL $MAX_TTL)
	need_wssize=1
	for e in '' '--wssize 1:6'; do
		need_split=
		need_disorder=

		[ -n "$e" ] && {
			pktws_curl_test_update $1 $3 $e && [ "$SCANLEVEL" = quick ] && return
		}

		for desync in multisplit multidisorder; do
			ok=0
			splits="$splits_http"
			[ "$sec" = 0 ] || splits="$splits_tls"
			for pos in $splits; do
				pktws_curl_test_update $1 $3 --dpi-desync=$desync --dpi-desync-split-pos=$pos $e && {
					[ "$SCANLEVEL" = quick ] && return
					ok=1
					need_wssize=0
					[ "$SCANLEVEL" = force ] || break
				}
			done
			[ "$ok" = 1 -a "$SCANLEVEL" != force ] || {
				case $desync in
					multisplit)
						need_split=1
						;;
					multidisorder)
						need_disorder=1
						;;
				esac
			}
		done

		need_fakedsplit=1
		need_fakeddisorder=1
		need_fake=1
		for desync in fake ${need_split:+fakedsplit fake,multisplit fake,fakedsplit} ${need_disorder:+fakeddisorder fake,multidisorder fake,fakeddisorder}; do
			[ "$need_fake" = 0 ] && test_has_fake "$desync" && continue
			[ "$need_fakedsplit" = 0 ] && contains "$desync" fakedsplit && continue
			[ "$need_fakeddisorder" = 0 ] && contains "$desync" fakeddisorder && continue
			ok=0
			for ttl in $ttls; do
				pktws_curl_test_update_vary $1 $2 $3 $desync --dpi-desync-ttl=$ttl $e && {
					[ "$SCANLEVEL" = quick ] && return
					ok=1
					need_wssize=0
					break
				}
			done
			# only skip tests if TTL succeeded. do not skip if TTL failed but fooling succeeded
			[ $ok = 1 -a "$SCANLEVEL" != force ] && {
				[ "$desync" = fake ] && need_fake=0
				[ "$desync" = fakedsplit ] && need_fakedsplit=0
				[ "$desync" = fakeddisorder ] && need_fakeddisorder=0
			}
			f=
			[ "$UNAME" = "OpenBSD" ] || f="badsum"
			f="$f badseq datanoack ts md5sig"
			[ "$IPV" = 6 ] && f="$f hopbyhop hopbyhop2"
			for fooling in $f; do
				ok=0
				pktws_curl_test_update_vary $1 $2 $3 $desync --dpi-desync-fooling=$fooling $e && {
					warn_fool $fooling $desync
					[ "$SCANLEVEL" = quick ] && return
					need_wssize=0
					ok=1
				}
				[ "$fooling" = md5sig ] && {
					[ "$ok" = 1 -a "$SCANLEVEL" != force ] && continue
					pktws_curl_test_update_vary $1 $2 $3 $desync --dpi-desync-fooling=$fooling --dup=1 --dup-cutoff=n2 --dup-fooling=md5sig $e && {
						warn_fool $fooling $desync
						echo "HINT ! To avoid possible 1 sec server response delay use --dup-ttl or --dup-autottl and block ICMP time exceeded"
						[ "$SCANLEVEL" = quick ] && return
						need_wssize=0
					}
				}
			done
		done

		[ "$IPV" = 6 ] && {
			f="hopbyhop ${need_split:+hopbyhop,multisplit} ${need_disorder:+hopbyhop,multidisorder} destopt ${need_split:+destopt,multisplit} ${need_disorder:+destopt,multidisorder}"
			[ -n "$IP6_DEFRAG_DISABLE" ] && f="$f ipfrag1 ${need_split:+ ipfrag1,multisplit} ${need_disorder:+ ipfrag1,multidisorder}"
			for desync in $f; do
				pktws_curl_test_update_vary $1 $2 $3 $desync $e && {
					[ "$SCANLEVEL" = quick ] && return
					need_wssize=0
				}
			done
		}

		[ "$need_split" = 1 ] && {
			# relative markers can be anywhere, even in subsequent packets. first packet can be MTU-full.
			# make additional split pos "10" to guarantee enough space for seqovl and likely to be before midsld,sniext,...
			# method is always expected in the beginning of the first packet
			f="method+2 method+2,midsld"
			[ "$sec" = 0 ] || f="10 10,sniext+1 10,sniext+4 10,midsld"
			for pos in $f; do
				pktws_curl_test_update $1 $3 --dpi-desync=multisplit --dpi-desync-split-pos=$pos --dpi-desync-split-seqovl=1 $e && {
					[ "$SCANLEVEL" = quick ] && return
					need_wssize=0
				}
			done
			[ "$sec" != 0 ] && pktws_curl_test_update $1 $3 --dpi-desync=multisplit --dpi-desync-split-pos=2 --dpi-desync-split-seqovl=336 --dpi-desync-split-seqovl-pattern="$ZAPRET_BASE/files/fake/tls_clienthello_iana_org.bin" $e && {
				[ "$SCANLEVEL" = quick ] && return
				need_wssize=0
			}
		}
		[ "$need_disorder" = 1 ] && {
			if [ "$sec" = 0 ]; then
				for pos in 'method+1 method+2' 'midsld-1 midsld' 'method+1 method+2,midsld'; do
					f="$(extract_arg 1 $pos)"
					f2="$(extract_arg 2 $pos)"
					pktws_curl_test_update $1 $3 --dpi-desync=multidisorder --dpi-desync-split-pos=$f2 --dpi-desync-split-seqovl=$f $e && {
						[ "$SCANLEVEL" = quick ] && return
						need_wssize=0
					}
				done
			else
				for pos in '1 2' 'sniext sniext+1' 'sniext+3 sniext+4' 'midsld-1 midsld' '1 2,midsld'; do
					f=$(extract_arg 1 $pos)
					f2=$(extract_arg 2 $pos)
					pktws_curl_test_update $1 $3 --dpi-desync=multidisorder --dpi-desync-split-pos=$f2 --dpi-desync-split-seqovl=$f $e && {
						[ "$SCANLEVEL" = quick ] && return
						need_wssize=0
					}
				done
			fi
		}

		need_fakedsplit=1
		need_fakeddisorder=1
		need_fake=1
		for desync in fake ${need_split:+fakedsplit fake,multisplit fake,fakedsplit} ${need_disorder:+fakeddisorder fake,multidisorder fake,fakeddisorder}; do
			[ "$need_fake" = 0 ] && test_has_fake "$desync" && continue
			[ "$need_fakedsplit" = 0 ] && contains "$desync" fakedsplit && continue
			[ "$need_fakeddisorder" = 0 ] && contains "$desync" fakeddisorder && continue
			ok=0
			for orig in '' 1 2 3; do
				for delta in 1 2 3 4 5; do
					pktws_curl_test_update_vary $1 $2 $3 $desync ${orig:+--orig-autottl=+$orig} --dpi-desync-ttl=1 --dpi-desync-autottl=-$delta $e && ok=1
				done
				[ "$ok" = 1 -a "$SCANLEVEL" != force ] && break
			done
			[ "$ok" = 1 ] &&
			{
				echo "WARNING ! although autottl worked it requires testing on multiple domains to find out reliable delta"
				echo "WARNING ! if a reliable delta cannot be found it's a good idea not to use autottl"
				[ "$SCANLEVEL" = quick ] && return
				need_wssize=0
				[ "$SCANLEVEL" = force ] || {
					[ "$desync" = fake ] && need_fake=0
					[ "$desync" = fakedsplit ] && need_fakedsplit=0
					[ "$desync" = fakeddisorder ] && need_fakeddisorder=0
				}
			}			
		done

		s="http_iana_org.bin"
		[ "$sec" = 0 ] || s="tls_clienthello_iana_org.bin"
		for desync in syndata ${need_split:+syndata,multisplit} ${need_disorder:+syndata,multidisorder} ; do
			pktws_curl_test_update_vary $1 $2 $3 $desync $e && [ "$SCANLEVEL" = quick ] && return
			pktws_curl_test_update_vary $1 $2 $3 $desync --dpi-desync-fake-syndata="$ZAPRET_BASE/files/fake/$s" $e && [ "$SCANLEVEL" = quick ] && return
		done

		# do not do wssize test for http and TLS 1.3. it's useless
		[ "$sec" = 1 ] || break
		[ "$SCANLEVEL" = force -o "$need_wssize" = 1 ] || break
	done
}
pktws_check_domain_http_bypass()
{
	# $1 - test function
	# $2 - encrypted test : 0 = plain, 1 - encrypted with server reply risk, 2 - encrypted without server reply risk
	# $3 - domain

	local strategy
	pktws_check_domain_http_bypass_ "$@"
	strategy_append_extra_pktws
	report_strategy $1 $3 $PKTWSD
}

pktws_check_domain_http3_bypass_()
{
	# $1 - test function
	# $2 - domain

	local f desync frag tests rep fake

	for fake in '' "--dpi-desync-fake-quic=$ZAPRET_BASE/files/fake/quic_initial_www_google_com.bin"; do
		for rep in '' 2 5 10 20; do
			pktws_curl_test_update $1 $2 --dpi-desync=fake ${fake:+$fake }${rep:+--dpi-desync-repeats=$rep} && [ "$SCANLEVEL" != force ] && {
				[ "$SCANLEVEL" = quick ] && return
				break
			}
		done
	done

	[ "$IPV" = 6 ] && {
		f="hopbyhop destopt"
		[ -n "$IP6_DEFRAG_DISABLE" ] && f="$f ipfrag1"
		for desync in $f; do
			pktws_curl_test_update $1 $2 --dpi-desync=$desync && [ "$SCANLEVEL" = quick ] && return
		done
	}

	# OpenBSD has checksum issues with fragmented packets
	[ "$UNAME" != "OpenBSD" ] && [ "$IPV" = 4 -o -n "$IP6_DEFRAG_DISABLE" ] && {
		for frag in 8 16 24 32 40 64; do
			tests="ipfrag2"
			[ "$IPV" = 6 ] && tests="$tests hopbyhop,ipfrag2 destopt,ipfrag2"
			for desync in $tests; do
				pktws_curl_test_update $1 $2 --dpi-desync=$desync --dpi-desync-ipfrag-pos-udp=$frag && [ "$SCANLEVEL" = quick ] && return
			done
		done
	}
	
}
pktws_check_domain_http3_bypass()
{
	# $1 - test function
	# $2 - domain

	local strategy
	pktws_check_domain_http3_bypass_ "$@"
	strategy_append_extra_pktws
	report_strategy $1 $2 $PKTWSD
}
warn_mss()
{
	[ -n "$1" ] && echo 'WARNING ! although mss worked it may not work on all sites and will likely cause significant slowdown. it may only be required for TLS1.2, not TLS1.3'
	return 0
}
fix_seg()
{
	# $1 - split-pos
	[ -n "$FIX_SEG" ] && contains "$1" , && echo "$FIX_SEG"
}

tpws_check_domain_http_bypass_()
{
	# $1 - test function
	# $2 - encrypted test : 0 = plain, 1 - encrypted with server reply risk, 2 - encrypted without server reply risk
	# $3 - domain

	local s mss s2 s3 oobdis pos sec="$2"
	local splits_tls='2 1 sniext+1 sniext+4 host+1 midsld 1,midsld 1,sniext+1,host+1,midsld,endhost-1'
	local splits_http='method+2 midsld method+2,midsld'

	# simulteneous oob and disorder works properly only in linux. other systems retransmit oob byte without URG tcp flag and poison tcp stream.
	[ "$UNAME" = Linux ] && oobdis='--oob --disorder'
	if [ "$sec" = 0 ]; then
		for s in '--hostcase' '--hostspell=hoSt' '--hostdot' '--hosttab' '--hostnospace' '--domcase' ; do
			tpws_curl_test_update $1 $3 $s && [ "$SCANLEVEL" = quick ] && return
		done
		for s in 1024 2048 4096 8192 16384 ; do
			tpws_curl_test_update $1 $3 --hostpad=$s && [ "$SCANLEVEL" != force ] && {
				[ "$SCANLEVEL" = quick ] && return
				break
			}
		done
		for s2 in '' '--hostcase' '--oob' '--disorder' ${oobdis:+"$oobdis"}; do
			for s in $splits_http ; do
				tpws_curl_test_update $1 $3 --split-pos=$s $(fix_seg $s) $s2 && [ "$SCANLEVEL" != force ] && {
					[ "$SCANLEVEL" = quick ] && return
					break
				}
			done
		done
		for s in  '--methodspace' '--unixeol' '--methodeol'; do
			tpws_curl_test_update $1 $3 $s && [ "$SCANLEVEL" = quick ] && return
		done
	else
		local need_mss=1
		for mss in '' 88; do
			s3=${mss:+--mss=$mss}
			for s2 in '' '--oob' '--disorder' ${oobdis:+"$oobdis"}; do
				for pos in $splits_tls; do
					tpws_curl_test_update $1 $3 --split-pos=$pos $(fix_seg $pos) $s2 $s3 && warn_mss $s3 && [ "$SCANLEVEL" != force ] && {
						[ "$SCANLEVEL" = quick ] && return
						need_mss=0
						break
					}
				done
			done
			for s in '' '--oob' '--disorder' ${oobdis:+"$oobdis"}; do
				for s2 in '--tlsrec=midsld' '--tlsrec=sniext+1 --split-pos=midsld' '--tlsrec=sniext+4 --split-pos=midsld' "--tlsrec=sniext+1 --split-pos=1,midsld $FIX_SEG" "--tlsrec=sniext+4 --split-pos=1,midsld $FIX_SEG" ; do
					tpws_curl_test_update $1 $3 $s2 $s $s3 && warn_mss $s3 && [ "$SCANLEVEL" != force ] && {
						[ "$SCANLEVEL" = quick ] && return
						need_mss=0
						break
					}
				done
			done
			# only linux supports mss
			[ "$UNAME" = Linux -a "$sec" = 1 ] || break
			[ "$SCANLEVEL" = force -o "$need_mss" = 1 ] || break
		done
	fi
}
tpws_check_domain_http_bypass()
{
	# $1 - test function
	# $2 - encrypted test : 0 = plain, 1 - encrypted with server reply risk, 2 - encrypted without server reply risk
	# $3 - domain

	local strategy
	tpws_check_domain_http_bypass_ "$@"
	strategy_append_extra_tpws
	report_strategy $1 $3 tpws
}

check_dpi_ip_block()
{
	# $1 - test function
	# $2 - domain

	local blocked_dom=$2
	local blocked_ip blocked_ips unblocked_ip

	echo 
	echo "- IP block tests (requires manual interpretation)"

	echo "> testing $UNBLOCKED_DOM on it's original ip"
	if curl_test $1 $UNBLOCKED_DOM; then
		unblocked_ip=$(mdig_resolve $IPV $UNBLOCKED_DOM)
		[ -n "$unblocked_ip" ] || {
			echo $UNBLOCKED_DOM does not resolve. tests not possible.
			return 1
		}

		echo "> testing $blocked_dom on $unblocked_ip ($UNBLOCKED_DOM)"
		curl_test $1 $blocked_dom $unblocked_ip detail

		blocked_ips=$(mdig_resolve_all $IPV $blocked_dom)
		for blocked_ip in $blocked_ips; do
			echo "> testing $UNBLOCKED_DOM on $blocked_ip ($blocked_dom)"
			curl_test $1 $UNBLOCKED_DOM $blocked_ip detail
		done
	else
		echo $UNBLOCKED_DOM is not available. skipping this test.
	fi
}

curl_has_reason_to_continue()
{
	# $1 - curl return code
	for c in 1 2 3 4 6 27 ; do
		[ $1 = $c ] && return 1
	done
	return 0
}

check_domain_prolog()
{
	# $1 - test function
	# $2 - port
	# $3 - domain

	local code

	echo
	echo \* $1 ipv$IPV $3

	echo "- checking without DPI bypass"
	curl_test $1 $3 && {
		report_append "ipv${IPV} $3 $1 : working without bypass"
		[ "$SCANLEVEL" = force ] || return 1
	}
	code=$?
	curl_has_reason_to_continue $code || {
		report_append "ipv${IPV} $3 $1 : test aborted, no reason to continue. curl code $(curl_translate_code $code)"
		return 1
	}
	return 0
}
check_domain_http_tcp()
{
	# $1 - test function
	# $2 - port
	# $3 - encrypted test : 0 = plain, 1 - encrypted with server reply risk, 2 - encrypted without server reply risk
	# $4 - domain

	# in case was interrupted before
	pktws_ipt_unprepare_tcp $2
	ws_kill

	check_domain_prolog $1 $2 $4 || return

	[ "$SKIP_IPBLOCK" = 1 ] || check_dpi_ip_block $1 $4

	[ "$SKIP_TPWS" = 1 ] || {
		echo
		tpws_check_domain_http_bypass $1 $3 $4
	}

	[ "$SKIP_PKTWS" = 1 ] || {
		echo
	        echo preparing $PKTWSD redirection
		pktws_ipt_prepare_tcp $2 "$(mdig_resolve_all $IPV $4)"

		pktws_check_domain_http_bypass $1 $3 $4

		echo clearing $PKTWSD redirection
		pktws_ipt_unprepare_tcp $2
	}
}
check_domain_http_udp()
{
	# $1 - test function
	# $2 - port
	# $3 - domain

	# in case was interrupted before
	pktws_ipt_unprepare_udp $2
	ws_kill

	check_domain_prolog $1 $2 $3 || return

	[ "$SKIP_PKTWS" = 1 ] || {
		echo
	        echo preparing $PKTWSD redirection
		pktws_ipt_prepare_udp $2 "$(mdig_resolve_all $IPV $3)"

		pktws_check_domain_http3_bypass $1 $3

		echo clearing $PKTWSD redirection
		pktws_ipt_unprepare_udp $2
	}
}


check_domain_http()
{
	# $1 - domain
	check_domain_http_tcp curl_test_http $HTTP_PORT 0 $1
}
check_domain_https_tls12()
{
	# $1 - domain
	check_domain_http_tcp curl_test_https_tls12 $HTTPS_PORT 1 $1
}
check_domain_https_tls13()
{
	# $1 - domain
	check_domain_http_tcp curl_test_https_tls13 $HTTPS_PORT 2 $1
}
check_domain_http3()
{
	# $1 - domain
	check_domain_http_udp curl_test_http3 $QUIC_PORT $1
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
	HTTP3=
	curl_supports_http3 && HTTP3=1
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
	
	curl_supports_connect_to || {
		echo "installed curl does not support --connect-to option. pls install at least curl 7.49"
		echo "current curl version:"
		$CURL --version
		exitp 1
	}

	local dom
	[ -n "$DOMAINS" ] || {
		DOMAINS="$DOMAINS_DEFAULT"
		[ "$BATCH" = 1 ] || {
			echo "specify domain(s) to test. multiple domains are space separated."
			printf "domain(s) (default: $DOMAINS) : "
			read dom
			[ -n "$dom" ] && DOMAINS="$dom"
		}
	}

	local IPVS_def=4
	[ -n "$IPVS" ] || {
		# yandex public dns
		pingtest 6 2a02:6b8::feed:0ff && IPVS_def=46
		[ "$BATCH" = 1 ] || {
			printf "ip protocol version(s) - 4, 6 or 46 for both (default: $IPVS_def) : "
			read IPVS
		}
		[ -n "$IPVS" ] || IPVS=$IPVS_def
		[ "$IPVS" = 4 -o "$IPVS" = 6 -o "$IPVS" = 46 ] || {
			echo 'invalid ip version(s). should be 4, 6 or 46.'
			exitp 1
		}
	}
	[ "$IPVS" = 46 ] && IPVS="4 6"

	configure_curl_opt

	[ -n "$ENABLE_HTTP" ] || {
		ENABLE_HTTP=1
		[ "$BATCH" = 1 ] || {
			echo
			ask_yes_no_var ENABLE_HTTP "check http"
		}
	}

	[ -n "$ENABLE_HTTPS_TLS12" ] || {
		ENABLE_HTTPS_TLS12=1
		[ "$BATCH" = 1 ] || {
			echo
			ask_yes_no_var ENABLE_HTTPS_TLS12 "check https tls 1.2"
		}
	}

	[ -n "$ENABLE_HTTPS_TLS13" ] || {
		ENABLE_HTTPS_TLS13=0
		if [ -n "$TLS13" ]; then
			[ "$BATCH" = 1 ] || {
				echo
				echo "TLS 1.3 uses encrypted ServerHello. DPI cannot check domain name in server response."
				echo "This can allow more bypass strategies to work."
				echo "What works for TLS 1.2 will also work for TLS 1.3 but not vice versa."
				echo "Most sites nowadays support TLS 1.3 but not all. If you can't find a strategy for TLS 1.2 use this test."
				echo "TLS 1.3 only strategy is better than nothing."
				ask_yes_no_var ENABLE_HTTPS_TLS13 "check https tls 1.3"
			}
		else
			echo
			echo "installed curl version does not support TLS 1.3 . tests disabled."
		fi
	}

	[ -n "$ENABLE_HTTP3" ] || {
		ENABLE_HTTP3=0
		if [ -n "$HTTP3" ]; then
			ENABLE_HTTP3=1
			[ "$BATCH" = 1 ] || {
				echo
				echo "make sure target domain(s) support QUIC or result will be negative in any case"
				ask_yes_no_var ENABLE_HTTP3 "check http3 QUIC"
			}
		else
			echo
			echo "installed curl version does not support http3 QUIC. tests disabled."
		fi
	}

	[ -n "$REPEATS" ] || {
		[ "$BATCH" = 1 ] || {
			echo
			echo "sometimes ISPs use multiple DPIs or load balancing. bypass strategies may work unstable."
			printf "how many times to repeat each test (default: 1) : "
			read REPEATS
		}
		REPEATS=$((0+${REPEATS:-1}))
		[ "$REPEATS" = 0 ] && {
			echo invalid repeat count
			exitp 1
		}
	}
	[ -z "$PARALLEL" -a $REPEATS -gt 1 ] && {
		PARALLEL=0
		[ "$BATCH" = 1 ] || {
			echo
			echo "parallel scan can greatly increase speed but may also trigger DDoS protection and cause false result"
			ask_yes_no_var PARALLEL "enable parallel scan"
		}
	}
	PARALLEL=${PARALLEL:-0}

	[ -n "$SCANLEVEL" ] || {
		SCANLEVEL=standard
		[ "$BATCH" = 1 ] || {
			echo
			echo quick    - scan as fast as possible to reveal any working strategy
			echo standard - do investigation what works on your DPI
			echo force    - scan maximum despite of result
			ask_list SCANLEVEL "quick standard force" "$SCANLEVEL"
			# disable tpws checks by default in quick mode
			[ "$SCANLEVEL" = quick -a -z "$SKIP_TPWS" -a "$UNAME" != Darwin ] && SKIP_TPWS=1
		}
	}

	echo

	configure_defrag
}



ping_with_fix()
{
	local ret
	$PING $2 $1 >/dev/null 2>/dev/null
	ret=$?
	# can be because of unsupported -4 option
	if [ "$ret" = 2 -o "$ret" = 64 ]; then
		ping $2 $1 >/dev/null
	else
		return $ret
	fi
}

pingtest()
{
	# $1 - ip version : 4 or 6
	# $2 - domain or ip

	# ping command can vary a lot. some implementations have -4/-6 options. others don.t
	# WARNING ! macos ping6 command does not have timeout option. ping6 will fail

	local PING=ping ret
	if [ "$1" = 6 ]; then
		if exists ping6; then
			PING=ping6
		else
			PING="ping -6"
		fi
	else
		if [ "$UNAME" = Darwin -o "$UNAME" = FreeBSD -o "$UNAME" = OpenBSD ]; then
			# ping by default pings ipv4, ping6 only pings ipv6
			# in FreeBSD -4/-6 options are supported, in others not
			PING=ping
		else
			# this can be linux or cygwin
			# in linux it's not possible for sure to figure out if it supports -4/-6. only try and check for result code=2 (invalid option)
			PING="ping -4"
		fi
	fi
	case "$UNAME" in
		Darwin)
			$PING -c 1 -t 1 $2 >/dev/null 2>/dev/null
			# WARNING ! macos ping6 command does not have timeout option. ping6 will fail. but without timeout is not an option.
			;;
		OpenBSD)
			$PING -c 1 -w 1 $2 >/dev/null
			;;
		CYGWIN)
			if starts_with "$(which ping)" /cygdrive; then
				# cygwin does not have own ping by default. use windows PING.
				$PING -n 1 -w 1000 $2 >/dev/null
			else
				ping_with_fix $2 '-c 1 -w 1'
			fi
			;;
		*)
			ping_with_fix $2 '-c 1 -W 1'
			;;
	esac
}
dnstest()
{
	# $1 - dns server. empty for system resolver
	"$LOOKUP" iana.org $1 >/dev/null 2>/dev/null
}
find_working_public_dns()
{
	local dns
	for dns in $DNSCHECK_DNS; do
		pingtest 4 $dns && dnstest $dns && {
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
			if is_linked_to_busybox nslookup; then
				nslookup $1 $2 2>/dev/null | sed -e '1,3d' -nre 's/^.*:[^0-9]*(([0-9]{1,3}\.){3}[0-9]{1,3}).*$/\1/p'
			else
				nslookup $1 $2 2>/dev/null | sed -e '1,3d' -nre 's/^[^0-9]*(([0-9]{1,3}\.){3}[0-9]{1,3}).*$/\1/p'
			fi
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

	# windows version of mdig outputs 0D0A line ending. remove 0D.
	echo $1 | "$MDIG" --family=4 | tr -d '\r' >"$DNSCHECK_DIG1"
	lookup4 $1 $2 >"$DNSCHECK_DIG2"
	# check whether system resolver returns anything other than public DNS
	grep -qvFf "$DNSCHECK_DIG2" "$DNSCHECK_DIG1"
}
check_dns_cleanup()
{
	rm -f "$DNSCHECK_DIG1" "$DNSCHECK_DIG2" "$DNSCHECK_DIGS" 2>/dev/null
}
check_dns_()
{
	local C1 C2 dom

	DNS_IS_SPOOFED=0

	[ "$SKIP_DNSCHECK" = 1 ] && return 0

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
				DNS_IS_SPOOFED=1
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

	echo "checking resolved IP uniqueness for : $DNSCHECK_DOM"
	echo "censor's DNS can return equal result for multiple blocked domains."
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
		DNS_IS_SPOOFED=1
		return 1
	}
	echo all resolved IPs are unique
	echo -- DNS looks good
	echo -- NOTE this check is Russia targeted. In your country other domains may be blocked.
	check_dns_cleanup
	return 0
}

check_dns()
{
	local r
	check_dns_
	r=$?
	[ "$DNS_IS_SPOOFED" = 1 ] && SECURE_DNS=${SECURE_DNS:-1}
	[ "$SECURE_DNS" = 1 ] && {
		doh_find_working || {
			echo could not find working DoH server. exiting.
			exitp 7
		}
	}
	return $r
}

unprepare_all()
{
	# make sure we are not in a middle state that impacts connectivity
	ws_kill
	wait
	[ -n "$IPV" ] && {
		pktws_ipt_unprepare_tcp $HTTP_PORT
		pktws_ipt_unprepare_tcp $HTTPS_PORT
		pktws_ipt_unprepare_udp $QUIC_PORT
	}
	cleanup
	rm -f "${HDRTEMP}"* "${PARALLEL_OUT}"*
}
sigint()
{
	echo
	echo terminating...
	unprepare_all
	exitp 1
}
sigint_cleanup()
{
	cleanup
	exit 1
}
sigsilent()
{
	# must not write anything here to stdout
	unprepare_all
	exit 1
}


fsleep_setup
fix_sbin_path
check_system
check_already
# no divert sockets in MacOS
[ "$UNAME" = "Darwin" ] && SKIP_PKTWS=1
[ "$UNAME" != CYGWIN  -a "$SKIP_PKTWS" != 1 ] && require_root
check_prerequisites
trap sigint_cleanup INT
check_dns
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
			[ "$SKIP_IPBLOCK" = 1 ] || check_domain_port_block $dom $HTTP_PORT
			check_domain_http $dom
		}
		[ "$ENABLE_HTTPS_TLS12" = 1 -o "$ENABLE_HTTPS_TLS13" = 1 ] && [ "$SKIP_IPBLOCK" != 1 ] && check_domain_port_block $dom $HTTPS_PORT
		[ "$ENABLE_HTTPS_TLS12" = 1 ] && check_domain_https_tls12 $dom
		[ "$ENABLE_HTTPS_TLS13" = 1 ] && check_domain_https_tls13 $dom
		[ "$ENABLE_HTTP3" = 1 ] && check_domain_http3 $dom
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
