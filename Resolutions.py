
from __future__ import print_function

from __future__ import absolute_import
from subprocess import Popen, PIPE, call
import sys
# from scanserver \
import DBModel
import  os
import platform
from pexpect import pxssh
import pexpect
import socket
import time

def test(device_id, mac_address):
    messages = ('Scan results for device: {0}, with MAC address: {1}'.format(device_id, mac_address))
    new_window_command = "x-terminal-emulator -e ".split()
    report = DBModel.get_scan_report(device_id)
    handle = Popen(new_window_command + [sys.executable, report] + [device_id] + [mac_address]
                   , stdin=PIPE, stderr=PIPE,  close_fds=False)

    output = handle.communicate()
    print(output)
    handle.wait()
    print(handle.pid)


def test4(device_id, mac_address):
    global status
    cmd = 'sudo -i ' + device_id + ' ' + mac_address
    m_child = pexpect.spawn('/bin/bash', ['-c', cmd], timeout=600)

    m_child.wait()
    print (m_child.command)
    print(m_child.stdout)

    # i = m_child.expect(['failed to establish TCP connection', TERMINAL_PROMPT, COMMAND_PROMPT])
    #
    # if i == 0:
    #     print('Run time:', round((time.time() - start_time), 3))
    #     set_status('Non-vulnerable')
    # elif i == 1 or i == 2:
    #     set_status('Vulnerable')
    # else:
    #     set_status('Non-vulnerable')
    #

def test3(device_id, mac_address):
    sys.stderr.write('test.py: starting \n')
    sys.stderr.flush()


def new_console(device_id, mac_address):
    messages = ('Scan results for device: {0}, with MAC address: {1}'.format(device_id, mac_address))
    report = DBModel.get_scan_report(device_id)
    new_window_command = "x-terminal-emulator -e".split() #https://accounts.google.com/SignOutOptions?hl=en&continue=https://mail.google.com/mail&service=mail
    # echo = [sys.executable, "-c", report]
    #         "import sys; print(sys.argv[1]); raw_input('Press Enter..')"]  # ;
    processes = Popen(new_window_command + [sys.executable, 'report.py'] + [str(device_id)])
    processes.communicate()
    processes.wait()



def create_new_console(device_id, mac_address):
    messages = ('Scan results for device: {0}, with MAC address: {1}'.format(device_id, mac_address))
    report = DBModel.get_scan_report(device_id)
    new_window_command = "x-terminal-emulator -e".split() #https://accounts.google.com/SignOutOptions?hl=en&continue=https://mail.google.com/mail&service=mail
    echo = ["import sys; raw_input('Press Enter..')", messages]  #[sys.executable, "-c", report]
    processes = Popen(new_window_command + echo)
    processes.wait()

    # processes = [Popen(new_window_command + echo + [messages])]
    #
    # # wait for the windows to be closed
    # for proc in processes:
    #     proc.communicate()
    #     proc.wait()

def get_scan_report(device_id):
    DBModel.get_scan_report(device_id)



def non_vuln_prompt(device_id):
    while True:
        consent = raw_input('\n Do you want to view vulnerability scan report? Enter Y(Yes) or N(No)').lower()
        if consent in ('y', 'yes', 'n', 'no'):
            if consent in ('y', 'yes'):
                get_scan_report(device_id)
            elif consent in ('n', 'no'):
                confirm = raw_input('\n Are you sure you do not want to view Vulnerability Scan Report. Enter Y(Yes)'
                                    ' to exit, and N(No) to view report').lower()
                if confirm in ('y', 'Yes', 'n', 'no'):
                    if confirm in ('y', 'yes'):
                        print('\n Please proceed with the use of your device')
                    elif confirm in ('n', 'no'):
                        get_scan_report(device_id)

            break
        else:
            print('Enter a valid input')


def vuln_prompt(vulnerability_name, resolution_name, device_id):
    response = ''
    while True:
        consent = raw_input('Do you want SeeSec to resolve vulnerability: {0}, by {1} on your device? Enter Y(Yes) '
                            'or N(No)'.format(vulnerability_name, resolution_name)).lower()
        if consent in ('y', 'yes', 'n', 'no'):
            if consent in ('y', 'yes'):
                print(resolution_name + '. Please wait....')
                response = 'yes'
            elif consent in ('n', 'no'):
                confirm = raw_input('Are you sure you do not want to resolve vulnerability: {0}'.
                                    format(vulnerability_name)).lower()
                if confirm in ('y', 'yes', 'n', 'no'):
                    if confirm in ('n', 'no'):
                        print(resolution_name + '. Please wait....')
                        response = 'yes'
                    elif confirm in ('yes', 'y'):
                        print('\n You have opted out on resolving vulnerability: {0}. Please be aware your'
                              ' device is vulnerable and you are at risk of a cyber attack.'.format(vulnerability_name))
                        response = 'no'
                    else:
                        print('Onto the next......')
                        response = 'no'
            else:
                print('Discarding resolution on vulnerability: {0}'.format(vulnerability_name))
            break
        else:
            print('Enter a valid input')
    return response


def resolve_ssh_scanner(vulnerability_name, resolution_name):
    user_consent = vuln_prompt(vulnerability_name, resolution_name)
    if user_consent == 1:
        print('Run the resolution function')
    else:
        print('Do nothing')

def test2(device_id, mac_address):
    messages = ('Scan results for device: {0}, with MAC address: {1}'.format(device_id, mac_address))
    new_window_command = "x-terminal-emulator -c".split()
    report = DBModel.get_scan_report(device_id)
    handle = Popen(new_window_command + [sys.executable, 'print({0})'.format(report)])
    # new_process = call(['python', 'test.py'])
    handle.wait()
    handle.communicate()[0]
    print(handle.pid)


def console(device_id, mac_address):
    messages = ('Scan results for device: {0}, with MAC address: {1}'.format(device_id, mac_address))
    report = DBModel.get_scan_report(device_id)
    new_window_command = "x-terminal-emulator -e".split() #https://accounts.google.com/SignOutOptions?hl=en&continue=https://mail.google.com/mail&service=mail
    echo = ['print({0})'.format(report)]  # ;
    processes = Popen(new_window_command + [sys.executable] + echo, shell=True )
    # processes.wait()
    # processes.communicate()

def r(device_id, mac_address):
    messages = ('Scan results for device: {0}, with MAC address: {1}'.format(device_id, mac_address))
    new_window_command = "x-terminal-emulator -e ".split()
    report = DBModel.get_scan_report(device_id)
    handle = Popen(new_window_command + ['-c', 'python', 'report.py'] + [str(device_id)] + [mac_address]
                   , stdin=PIPE, stderr=PIPE)

    output = handle.communicate()
    print(output)
    handle.wait()
    print(handle.pid)

if __name__ == '__main__':
    # new_console(32, 'mac address')
    # console(32, 'mac address')
    r(32, 'mac')
    # create_new_console(32, '45:23:34:12:ac:j7')
    # num = validate_user_input('Bad lock detection', 'Changing the default password')
    print('Finished running')
    # resolve_ssh_scanner()

