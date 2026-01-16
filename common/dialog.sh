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
	printf "$2 (default : $DEFAULT) (Y/N) ? "
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
ask_list()
{
	# $1 - mode var
	# $2 - space separated value list
	# $3 - (optional) default value
	local M_DEFAULT
	eval M_DEFAULT="\$$1"
	local M_DEFAULT_VAR="$M_DEFAULT"
	local M="" m

	[ -n "$3" ] && { find_str_in_list "$M_DEFAULT" "$2" || M_DEFAULT="$3" ;}

	n=1
	for m in $2; do
		echo $n : $m
		n=$(($n+1))
	done
	printf "your choice (default : $M_DEFAULT) : "
	read m
	[ -n "$m" ] && M=$(echo $2 | cut -d ' ' -f$m 2>/dev/null)
	[ -z "$M" ] && M="$M_DEFAULT"
	echo selected : $M
	eval $1="\"$M\""

	[ "$M" != "$M_DEFAULT_VAR" ]
}
