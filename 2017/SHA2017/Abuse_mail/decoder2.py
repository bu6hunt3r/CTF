import base64
data = open('getfile_usb.txt').read()

files = data.replace('\n', '').split('getfile:')[1:]

output = [0] * len(files)
print output

for file in files:
	file = file.split(':')
	print "\033[1;31m{}\033[0m".format(int(file[0]))
	output[int(file[0])] = file[1]

f = open('usb.pcap', 'w')
f.write(base64.urlsafe_b64decode(''.join(output)))
f.close()

