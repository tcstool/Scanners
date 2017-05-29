#!/usr/bin/python

import urllib2
import ipcalc
import sys

def authScan(ipFile):
    try:
        with open(ipFile) as f:
            ipList = f.readlines()

    except Exception,e:
	print e
        print 'Couldn\'t open ' + ipFile
        sys.exit()

    for target in ipList:
       if target.find('/') == -1: #Single IP or DNS name, no IP calculator to break out targets
            httpHandler(target.rstrip() )

       else: #Subnet specified, break out IPs
            for address in ipcalc.Network(target.rstrip()):
            	httpHandler(address)

def httpHandler(scanTarget):
	try:
 		request = urllib2.Request('http://' + str(scanTarget))
        	request.add_header('User-Agent','Mozilla/5.0 (Windows NT 6.1)') #Add a fake user agent in case the app/LB wants it
        	request.add_header('Connection','close') #More fake stuff
        	response = urllib2.urlopen(request, timeout=3)

       	except urllib2.HTTPError,e:
           if 'WWW-authenticate' in e.hdrs:
               	print 'Found basic authentication on ' + str(scanTarget) + '!'
               	fo = open('./basic_auth_sites.txt', 'a')
               	fo.write(str(scanTarget) + '\n')
               	fo.close()
               	return

           else: #handle other HTTP error codes (500 etc.)
		print 'Got ' + str(e.code) + ' from ' + str(scanTarget)
                fo = open('./other_http_logs.csv','a')
                fo.write(str(scanTarget) + ',' + str(e.code) + '\n')
		fo.close()
		return

        except Exception: #something else went wrong at the network level
           print 'No HTTP response from ' + str(scanTarget)
           return

       #Application probably gave a normal response (e.g. HTTP 200 or something).  Record just to see if anything interesting is out there.
	print 'Got ' + str(response.code) + ' from ' + str(scanTarget)
        fo = open('./other_http_logs.csv', 'a') 
        fo.write(str(scanTarget) + ',' + str(response.code) + '\n')
        fo.close()

        return

def main(targetFile):
    authScan(targetFile)

if __name__ == '__main__':
	if len(sys.argv) != 2:
		print 'Usage:  http_basic_final.py <path to text file with IPs/DNS names/subnets to scan>'
	
	else:
		main(sys.argv[1])
