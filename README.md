# SeeSec---IoT-Vulnerablity-Scanner
SeeSec - IoT Vulnerablity Scanner
Utilizes an SDN to prevent IoT devices with known vulnerabilities from using the network. The system also attempts to automatically fix vulnerabilities when possible.

Note: IoT seeker (the codes that scans for default credentials in IoT devices – Mirai malware) is also integrated with this system. Ref - https://github.com/rapid7/IoTSeeker.

Other integrated scanners include Nessus vulnerability scanner and a custom scanner that login via ssh using 462 combinations of default/weak credentials.

Here are the Steps:

    Install Mininet VM image. Version 2.2.0 or higher
    The required installation will depend on which integrated vulnerability scan you want to run. You can run the desired integrated scanners by disabling the lines of codes that launches undesired integrated scanners.

a.	Install the Nessus scanning tool on your virtual machine and download a mininet virtual image **if you would like to run the Nessus scanner

b.	Install perl packages by cpan AnyEvent::HTTP Data::Dumper JSON **if you would like to run the Mirai scanner 

    In the home directory of the mininet VM, add the following python script and folders in the specified directory below. Existing components in the POX server should be overwritten

a. Scanresults - /home/mininet/pox

b.	Firewallpolices, scanserver - /home/mininet/pox/pox

c.	Dhpd.py - /home/mininet/pox/proto

d.	Dhcpmininet.py - /home/mininet/pox/topology

e.	Firewall.py - /home/mininet/pox/pox/misc

f.	Host_tracker - /home/mininet/pox/pox/host_tracker 

g. Devices.cfg, iotScanner.pl - /home/mininet/pox

    To run the test, log into the mininet virtual machine via SSH using putty or any other suitable program. Open 3 terminals. First terminal for mininet network simulation, the second to start POX controller and the third to track the access control list 3.

    To start the network simulation, enter the following commands;

a. sudo python ./pox/pox/topology/dhcpmininet.py- to start a network of hosts with no assigned IP_Address, sudo mn –topo single,6 - -mac - -switch ovsk - -controller remote -to start a network with static or pre-assigned IP_Adress

b. ./pox/pox.py misc.firewall openflow.discovery host_tracker.host_tracker forwarding.l2_learning proto.dhcpd -to start the POX SDN controller. This will start the POX controller and connect to the OF-switch. 5.

c. Send dhcp request for each hosts on the mininet terminal. Run sudo dhclient h1-eth1 (h1, h2, h3)

d. To view the access control list, enter the following command on the third terminal. cd pox/pox/firewallpolicies cat whitelist.csv cat blacklist.csv cat firewallpolicies.csv

e. To test the communication flow, ping hosts via the controller within the network. h1 ping –c1 h2 h2 ping –c1 h3 etc.
