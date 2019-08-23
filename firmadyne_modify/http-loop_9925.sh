#!/bin/sh
rgdb -A /etc/templates/httpd/httpd.php > /var/etc/httpd.cfg
rgdb -A /etc/templates/httpd/httpasswd.php > /var/etc/httpasswd
httpd -s wapac02_dkbs_dap2695 -f /var/etc/httpd.cfg
sleep 2
