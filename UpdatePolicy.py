# Copyright 2016 Ruth Ogunnaike
"""
#This code reads and update various csv files. It analyses the result from the NessusScanner class.
"""

# import pox.openflow.libopenflow_01 as of
# import os
# from csv import DictReader
# from pox.core import core
# from pox.lib.revent import *
# from pox.lib.util import dpidToStr
# from pox.lib.addresses import IPAddr,EthAddr,parse_cidr

import os
from csv import DictReader
import csv
from collections import namedtuple



# class UpdatePolicy(object):
#     def __init__(self):
#         self.listenTo(core.openflow)
#         log.debug("Updating policy file Firewall")

def clearPolicies(filename):
    """ Clear the data in file (MAC address) """
    f = open(filename, "w+")
    f.close()

def exist(filename, mac_add):
    count=0
    headers = ["macadd"]
    f = open(filename)
    reader = csv.DictReader(f, headers)

    for row in reader:
        for val in row.itervalues():
            print val
            if val in (None, ""):
                count = count + 0
            if val == mac_add:
                count = count + 1

    return count

def policyId(filename):
    count=0
    headers = ["macadd"]
    f = open(filename)
    reader = csv.DictReader(f, headers)

    for row in reader:
        if row in (None, ""):
            count = count + 0
        else:
            count = count + 1

    return count

def addlist(filename, mac_add):
    """ Add data to file (MAC address) """
    count = exist(filename, mac_add)
    if count == 0:
        with open(filename, 'a') as list:
            updatelist = csv.writer(list, delimiter=',')
            updatelist.writerow([str(mac_add).strip()])

def updatepolicy(whitelist, blacklist, firewallpolicy):
    headers = ["mac_0", "mac_1"]

    #open whitelisted mac_address for read
    w = open(whitelist)
    whitereader = csv.DictReader(w, headers)

    # open blacklisted mac_address for read
    b = open(blacklist)
    blackreader = csv.DictReader(b, headers)

    #open firewall policies for write
    f = open(firewallpolicy, 'a')
    firewall= csv.writer(f, delimiter =',')

    clearPolicies(firewallpolicy)
    count= policyId(firewallpolicy)
    firewall.writerow(["id", "mac_0", "mac_1"])


    for row in blackreader:
        for bval in row.itervalues():
            if bval in (None, ""):
                print (bval)
            else:
                for row in whitereader:
                    for val in row.itervalues():

                        if val in (None, ""):
                            print( val)
                        else:
                            count = count + 1
                            firewall.writerow([count, str(bval).strip(), str(val).strip()])


Policy = namedtuple('Policy', ('dl_src', 'dl_dst'))
def read_policies( file):
    with open(file, 'r') as f:
        reader = DictReader(f, delimiter=",")
        policies = {}
        for row in reader:
            policies[row['id']] = Policy((row['mac_0']), (row['mac_1']))
    return policies

def launch():
    '''Start the Policy update '''
    core.registerNew(updatepolicy)
