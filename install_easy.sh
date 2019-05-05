#!/bin/sh

# automated script for easy installing zapret on systemd based system
# all required tools must be already present or system must use apt as package manager
# if its not apt or yum based system then manually install ipset, curl

exists()
{
	which $1 >/dev/null 2>/dev/null
}
whichq()
{
	which $1 2>/dev/null
}

[ $(id -u) -ne "0" ] && {
	echo root is required
	exists sudo && exec sudo $0
	exists su && exec su -c $0
	echo su or sudo not found
	exit 2
}

SCRIPT=$(readlink -f $0)
EXEDIR=$(dirname $SCRIPT)
ZAPRET_BASE=/opt/zapret
INIT_SCRIPT_SRC=$EXEDIR/init.d/debian/zapret
INIT_SCRIPT=/etc/init.d/zapret
GET_IPLIST=$EXEDIR/ipset/get_antizapret.sh
GET_IPLIST_PREFIX=$EXEDIR/ipset/get_
SYSTEMD_SYSV_GENERATOR=/lib/systemd/system-generators/systemd-sysv-generator

exitp()
{
	echo
	echo press enter to continue
	read A
	exit $1
}


echo \* checking system ...

SYSTEMCTL=$(whichq systemctl)
[ -x "$SYSTEMCTL" ] || {
	echo not systemd based system
	exitp 5
}
[ -x "$SYSTEMD_SYSV_GENERATOR" ] || {
	echo systemd is present but it does not support sysvinit compatibility
	echo $SYSTEMD_SYSV_GENERATOR is required
	exitp 5
}


echo \* checking location ...

[ "$EXEDIR" != "$ZAPRET_BASE" ] && {
	echo easy install is supported only from default location : $ZAPRET_BASE
	echo currenlty its run from $EXEDIR
	echo -n "do you want the installer to copy it for you (Y/N) ? "
	read A
	if [ "$A" = "Y" ] || [ "$A" = "y" ]; then
		if [ -d "$ZAPRET_BASE" ]; then
			echo installer found existing $ZAPRET_BASE
			echo -n "do you want to delete all files there and copy this version (Y/N) ? "
			read A
			if [ "$A" = "Y" ] || [ "$A" = "y" ]; then
				rm -r "$ZAPRET_BASE"
			else
				echo refused to overwrite $ZAPRET_BASE. exiting
				exitp 3
			fi
		fi
		cp -R $EXEDIR $ZAPRET_BASE
		echo relaunching itself from $ZAPRET_BASE
		exec $ZAPRET_BASE/$(basename $0)
	else
		echo copying aborted. exiting
		exitp 3
	fi
}
echo running from $EXEDIR


echo \* checking prerequisites ...

if exists ipset && exists curl ; then
	echo everything is present
else
	echo \* installing prerequisites ...

	APTGET=$(whichq apt-get)
	YUM=$(whichq yum)
	PACMAN=$(whichq pacman)
	if [ -x "$APTGET" ] ; then
		"$APTGET" update
		"$APTGET" install -y --no-install-recommends ipset curl dnsutils || {
			echo could not install prerequisites
			exitp 6
		}
	elif [ -x "$YUM" ] ; then
		"$YUM" -y install curl ipset daemonize || {
			echo could not install prerequisites
			exitp 6
		}
	elif [ -x "$PACMAN" ] ; then
		"$PACMAN" -Syy
		"$PACMAN" --noconfirm -S ipset curl || {
			echo could not install prerequisites
			exitp 6
		}
	else
		echo supported package manager not found
		echo you must manually install : ipset curl
		exitp 5
	fi
fi

echo \* installing binaries ...

"$EXEDIR/install_bin.sh"


echo \* installing init script ...

"$SYSTEMCTL" stop zapret 2>/dev/null

script_mode=Y
[ -f "$INIT_SCRIPT" ] &&
{
	cmp -s $INIT_SCRIPT $INIT_SCRIPT_SRC ||
	{
		echo $INIT_SCRIPT already exists and differs from $INIT_SCRIPT_SRC
		echo Y = overwrite with new version 
		echo N = exit
		echo L = leave current version and continue
		read script_mode
		case "${script_mode}" in
			Y|y|L|l)
				;;
			*)
				echo aborted
				exitp 3
				;;
		esac
	}
}

if [ "$script_mode" = "Y" ] || [ "$script_mode" = "y" ]; then
	echo -n "copying : "
	cp -vf $INIT_SCRIPT_SRC $INIT_SCRIPT
fi


echo \* registering init script ...

"$SYSTEMCTL" enable zapret || {
	echo could not register $INIT_SCRIPT with systemd
	exitp 20
}


echo \* downloading blocked ip list ...

"$GET_IPLIST" || {
	echo could not download ip list
	exitp 25
}


echo \* adding crontab entry ...

CRONTMP=/tmp/cron.tmp
crontab -l >$CRONTMP
if grep -q "$GET_IPLIST_PREFIX" $CRONTMP; then
	echo some entries already exist in crontab. check if this is corrent :
	grep "$GET_IPLIST_PREFIX" $CRONTMP
else
	echo "0 12 * * */2 $GET_IPLIST" >>$CRONTMP
	crontab $CRONTMP
fi

rm -f $CRONTMP


echo \* starting zapret service ...

systemctl start zapret || {
	echo could not start zapret service
	exitp 30
}

exitp 0
