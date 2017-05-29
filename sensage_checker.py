#!/usr/bin/python

import pexpect
import sys

def main():
        if len(sys.argv) != 2:
                print 'Usage:  sensage_check.py <path to server list>'
                sys.exit()

        else:
                senScan(sys.argv[1])

def senScan(listFile):
        with open(listFile) as f:
                serverList = f.readlines()

        for senHost in serverList:
                senPort = '9999'
                senCommand = 'config\n'

                try:
                        child = pexpect.spawn('nc ' + senHost + ' ' + senPort)
                        child.expect('SenSage Windows Event-Log Retriever v74963.', timeout=10)
                        child.sendline('config\r\n')
                        child.expect('awt.toolkit=sun.awt.windows.WToolkit')

                        if len(child.buffer) > 1000:
                                print 'Anonymous access found on ' + senHost
                                print 'Current Buffer: ' + child.buffer #Make sure the script hasn't crapped out
                                fo = open('sensage_anonymous_access.log','a')
                                fo.write(senHost)
                                fo.close()
                except:
                        print 'Error connecting to ' + senHost
                        pass



if __name__ == '__main__':
    main()







