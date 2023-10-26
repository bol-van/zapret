apply_unspecified_desync_modes()
{
	NFQWS_OPT_DESYNC_HTTP="${NFQWS_OPT_DESYNC_HTTP:-$NFQWS_OPT_DESYNC}"
	NFQWS_OPT_DESYNC_HTTPS="${NFQWS_OPT_DESYNC_HTTPS:-$NFQWS_OPT_DESYNC}"
	NFQWS_OPT_DESYNC_HTTP6="${NFQWS_OPT_DESYNC_HTTP6:-$NFQWS_OPT_DESYNC_HTTP}"
	NFQWS_OPT_DESYNC_HTTPS6="${NFQWS_OPT_DESYNC_HTTPS6:-$NFQWS_OPT_DESYNC_HTTPS}"
	NFQWS_OPT_DESYNC_QUIC6="${NFQWS_OPT_DESYNC_QUIC6:-$NFQWS_OPT_DESYNC_QUIC}"
}

get_nfqws_qnums()
{
	# $1 - var name for ipv4 http
	# $2 - var name for ipv4 https
	# $3 - var name for ipv6 http
	# $4 - var name for ipv6 https
	local _qn _qns _qn6 _qns6

	[ "$DISABLE_IPV4" = "1" ] || {
		_qn=$QNUM
		_qns=$_qn
		[ "$NFQWS_OPT_DESYNC_HTTP" = "$NFQWS_OPT_DESYNC_HTTPS" ] || _qns=$(($QNUM+1))
	}
	[ "$DISABLE_IPV6" = "1" ] || {
		_qn6=$(($QNUM+2))
		_qns6=$(($QNUM+3))
		[ "$DISABLE_IPV4" = "1" ] || {
			if [ "$NFQWS_OPT_DESYNC_HTTP6" = "$NFQWS_OPT_DESYNC_HTTP" ]; then
				_qn6=$_qn;
			elif [ "$NFQWS_OPT_DESYNC_HTTP6" = "$NFQWS_OPT_DESYNC_HTTPS" ]; then
				_qn6=$_qns;
			fi
			if [ "$NFQWS_OPT_DESYNC_HTTPS6" = "$NFQWS_OPT_DESYNC_HTTP" ]; then
				_qns6=$_qn;
			elif [ "$NFQWS_OPT_DESYNC_HTTPS6" = "$NFQWS_OPT_DESYNC_HTTPS" ]; then
				_qns6=$_qns;
			fi
		}
		[ "$NFQWS_OPT_DESYNC_HTTPS6" = "$NFQWS_OPT_DESYNC_HTTP6" ] && _qns6=$_qn6;
	}
	if [ "$MODE_HTTP" = 1 ]; then
		eval $1=$_qn
		eval $3=$_qn6
	else
		eval $1=
		eval $3=
	fi
	if [ "$MODE_HTTPS" = 1 ]; then
		eval $2=$_qns
		eval $4=$_qns6
	else
		eval $2=
		eval $4=
	fi
}

get_nfqws_qnums_quic()
{
	# $1 - var name for ipv4 quic
	# $2 - var name for ipv6 quic
	local _qn _qn6

	[ "$DISABLE_IPV4" = "1" ] || {
		_qn=$(($QNUM+10))
	}
	[ "$DISABLE_IPV6" = "1" ] || {
		_qn6=$(($QNUM+11))
		[ "$DISABLE_IPV4" = "1" ] || {
			if [ "$NFQWS_OPT_DESYNC_QUIC" = "$NFQWS_OPT_DESYNC_QUIC6" ]; then
				_qn6=$_qn;
			fi
		}
	}
	if [ "$MODE_QUIC" = 1 ]; then
		eval $1=$_qn
		eval $2=$_qn6
	else
		eval $1=
		eval $2=
	fi
}
