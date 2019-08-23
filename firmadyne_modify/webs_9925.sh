#!/bin/sh
echo [$0] $1 ... > /dev/console
TROOT="/etc/templates"
hostname=`rgdb -g /sys/hostname`

case "$hostname" in
DAP-1525)
	WEB=`rgdb -g /sys/web/status`
	;;
DAP-1522)
	WEB=`rgdb -g /sys/web/status`
	;;
*)
	WEB=`rgdb -g /sys/web/enable`
	;;	
esac

case "$1" in
password)
	rgdb -A $TROOT/httpd/httpasswd.php > /var/etc/httpasswd
	;;
reload)
	killall -SIGUSR2 httpd
	;;
start|restart)
	if [ "$WEB" = "1" ]; then
	[ -f /var/run/webs_stop.sh ] && sh /var/run/webs_stop.sh > /dev/console
	rgdb -A $TROOT/httpd/webs_run.php -V generate_start=1 > /var/run/webs_start.sh
	rgdb -A $TROOT/httpd/webs_run.php -V generate_start=0 > /var/run/webs_stop.sh
	cp http-loop.sh /var/run/http-loop.sh
	sh /var/run/webs_start.sh > /dev/console 2> /dev/null
	fi	
	;;
stop)
	if [ "$WEB" = "1" ]; then
	if [ -f /var/run/webs_stop.sh ]; then
		sh /var/run/webs_stop.sh > /dev/console
		rm -f /var/run/webs_stop.sh
	fi
	fi		
	;;
*)
	echo "usage: $0 {start|stop|restart|password|reload}"
	;;
esac
