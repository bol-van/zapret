#!/bin/sh

DIR_PATCH=/etc/crontabs/patches
ZAPRET_RW=/data/zapret

if [ ! -d $DIR_PATCH ]; then
	mkdir -p $DIR_PATCH
	chown root $DIR_PATCH
	chmod 0755 $DIR_PATCH
fi


	cp $ZAPRET_RW/zapret_patch.sh $DIR_PATCH/
	chmod +x $DIR_PATCH/zapret_patch.sh	
	FILE_FOR_EDIT=/etc/crontabs/root
	grep -v "/zapret_patch.sh" $FILE_FOR_EDIT > $FILE_FOR_EDIT.new
	echo "*/1 * * * * /etc/crontabs/patches/zapret_patch.sh >/dev/null 2>&1" >> $FILE_FOR_EDIT.new
	mv $FILE_FOR_EDIT.new $FILE_FOR_EDIT
	/etc/init.d/cron restart