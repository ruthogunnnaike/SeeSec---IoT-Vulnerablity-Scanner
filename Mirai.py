
#Copyright 2016 Ruth Ogunnaike

"""
sshscanner, this code runs 462 combinations of common weak/default usernames  and passwords against port 22 in order
to have a login access into the host. It includes method to change user's password

Procedures
runScan(IP_Address),this method initiates and run the default/weak vulnerability scanner password. The parameter
ip_address is passed as a string value.

getStatus(), this function returns the login status of the scan. The return values are Success Scan Error and Failed
. Success and Scan Error should flag the host vulnerable and the Failed status flags the host as not-vulnerable.

isPasswordChanged(IP_Address), this is a Boolean function that fix the weak/default vulnerability by changing the password
 of the host.  A new password is generated using combinations of alphanumeric characters of length eight.
"""


from __future__ import print_function

from __future__ import absolute_import
from pexpect import pxssh
import pexpect
import os
import socket
import time
import string
import random
import subprocess
import sys, getpass

COMMAND_PROMPT = '[$#] '
TERMINAL_PROMPT = r'Terminal type\?'
TERMINAL_TYPE = 'vt100'
SSH_NEWKEY = r'Are you sure you want to continue connecting \(yes/no\)\?'


try:
    import urllib.request as urllib2
except ImportError:
    import urllib2

url = 'https://localhost:8834'

class sshscanner(object):
    def built_url(self, resource):
        return '{0}{1}'.format(url, resource)

def setStatus(value):
    global status
    status = value

def getStatus():
    return status

def launchMiraiScan(ip):
    global status
    cmd = 'perl iotScanner.pl %s' % ip
    starttime = time.time()
    # mChild = pexpect.spawn(cmd)
    pipe = subprocess.Popen(['perl', './iotScanner.pl', ip], stdout = subprocess.PIPE)
    result = pipe.stdout.read()
    print('the result is', result)
    expect = ('device ' + ip + ': failed to establish TCP connection')
    if expect.find(result) != 1 :
        print('Run time:', round((time.time() - starttime), 3))
        setStatus('Non-vulnerable')
    else:
        print('Run time:', round((time.time() - starttime), 3))
        setStatus('Vulnerable')

def runScan(ip):
    launchMiraiScan(ip);

#
# if __name__ == '__main__':
#     ip = '10.156.15.118'
#     runScan(ip)
#     status = getStatus()
#     print ('This is the status:', status)

#
#
#     # mChild.expect(pexpect.EOF, timeout=None)
#     # mChild.expect('Enter password:')
#     # child.sendline('password')
#     # child.expect(pexpect.EOF, timeout=None)
#     # cmd_show_data = child.before
#     # cmd_output = cmd_show_data.split('\r\n')
#
# def login(host, user, password):
#     global child
#     child = pexpect.spawn('ssh -l %s %s'%(user, host))
#     fout = file ("LOG.TXT","wb")
#     child.logfile_read = fout #use child.logfile to also log writes (passwords!)
#
#     i = child.expect([pexpect.TIMEOUT, SSH_NEWKEY, '[Pp]assword: '])
#     if i == 0: # Timeout
#         print('ERROR!')
#         print('SSH could not login. Here is what SSH said:')
#         print(child.before, child.after)
#         sys.exit (1)
#     if i == 1: # SSH does not have the public key. Just accept it.
#         child.sendline ('yes')
#         child.expect ('[Pp]assword: ')
#     child.sendline(password)
#     # Now we are either at the command prompt or
#     # the login process is asking for our terminal type.
#     i = child.expect (['Permission denied', TERMINAL_PROMPT, COMMAND_PROMPT])
#     if i == 0:
#         print('Permission denied on host:', host)
#         sys.exit (1)
#     if i == 1:
#         child.sendline (TERMINAL_TYPE)
#         child.expect (COMMAND_PROMPT)
#     return child
#
#
#

#
# #
# # # def generatePassword():
# # #     chars = string.ascii_lowercase  + string.digits
# # #     size = 8
# # #     password= ''.join(random.choice(chars) for _ in range (size))
# # #
# # #     return password
# # #
# # # # (current) UNIX password:
# # def change_password(child):
# #     newpassword = generatePassword()
# #     print (newpassword)
# #     child.sendline('passwd')
# #     #The first expected command is to enter the current password
# #     i = child.expect(['Changing', 'current','Changing password for mininet. ',   '[Oo]ld [Pp]assword', '.current.*password', '[Nn]ew [Pp]assword'])
# #     if i != -1:
# #         print (oldpassword)
# #     else:
# #         print ("Wrong expected command")
# #
# #     #Expected command is to enter the current password
# #     i = child.expect(['(current)', 'Enter current', '[E/e]nter', '[#\$] '], timeout=60)
# #     if i != -1:
# #         child.sendline(oldpassword)
# #     if i == 3:
# #         print("This is the next command: ", child.after)
# #
# #     #Expected command is to enter the new password
# #     i = child.expect(['Enter current', '[E/e]nter', '[#\$] ', 'Retype'])
# #     if i != -1:
# #         child.sendline(newpassword)
# #
# #     #Expected command is to retype the new password
# #     i = child.expect(['New password', 'Retype', 'Re-enter'], timeout=120)
# #     if i != -1:
# #         child.sendline(newpassword)
# #
# #     #Expected command is to password update failed or successful
# #     i = child.expect(['password', 'updated', 'success'], timeout=120)
# #     if i != -1:
# #             print("Success")
# #     else:
# # #         print ("Error occured")
# # #
# # # def isPasswordChanged(host):
# # #     changeTime = time.time()
# # #     loginchild= login(host, username, oldpassword)
# # #     if loginchild ==None:
# # #         print ("Cannot login to host:", host)
# # #         print("Resolution Time: ", round((time.time() - changeTime), 3))
# # #         return False
# # #     else:
# # #         print("Changing Password for host:", host)
# # #         change_password(loginchild)
# # #         child.expect(COMMAND_PROMPT)
# # #         print("Resolution Time: ", round((time.time() - changeTime), 3))
# # #         return True
#
# def login(host, user, password):
#     global child
#     child = pexpect.spawn('ssh -l %s %s'%(user, host))
#     fout = file ("LOG.TXT","wb")
#     child.logfile_read = fout #use child.logfile to also log writes (passwords!)
#
#     i = child.expect([pexpect.TIMEOUT, SSH_NEWKEY, '[Pp]assword: '])
#     if i == 0: # Timeout
#         print('ERROR!')
#         print('SSH could not login. Here is what SSH said:')
#         print(child.before, child.after)
#         sys.exit (1)
#     if i == 1: # SSH does not have the public key. Just accept it.
#         child.sendline ('yes')
#         child.expect ('[Pp]assword: ')
#     child.sendline(password)
#     # Now we are either at the command prompt or
#     # the login process is asking for our terminal type.
#     i = child.expect (['Permission denied', TERMINAL_PROMPT, COMMAND_PROMPT])
#     if i == 0:
#         print('Permission denied on host:', host)
#         sys.exit (1)
#     if i == 1:
#         child.sendline (TERMINAL_TYPE)
#         child.expect (COMMAND_PROMPT)
#     return child
#
# #
