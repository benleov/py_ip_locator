#!/usr/bin/env python

#
#  Author: Benjamin Leov
#
# MAC to IP translation program.
#
# Works by using fping to ping every ip on a given subnet,
# then checking the arp cache for existance of that mac address.

# This program requres the gtk.glade python bindings for glade,
# and either the command "fping", known to work with Version 2.4b2_,
# OR root access (as raw sockets require it) to perform the ICMP request
# manually. Using raw sockets is much slower than fping at this stage,
# so be careful when specifying large subnets.

import traceback
import sys

try:
    import gtk
    import gtk.glade
except ImportError:
    print "Sorry, you don't have the GTK Glade module installed, and this"
    print "script relies on it.  Please install or reconfigure Glade"
    print "and try again."
    
import commands

import socket         # required to get local IP address
import fcntl 
import struct

import threading
import time           # for pausing
from threading import Thread

import string         # general string functions

import ping           # class required to do ping

curr_message = 1      # counter for messages being put onto the status bar

# function to get the local ip address.
def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

# Main aplication close button action
def on_btnClose_clicked(self):
   print "Close application"
   gtk.main_quit()

# On buttonAbout clicked action
def on_btnAbout_clicked(button):
   aboutDialog = gtk.glade.XML('../gui/about.glade') # load glade xml file
   about = aboutDialog.get_widget("diaAbout") 
   about.run()        # run() is blocking; clicking "close" unblocks and
   about.destroy()    # continues on to destroy

# wraps the on_btnStart_clicked function in a thread, so the gui will
# still keep updating in its own thread, while we are busy searching via fping
# or raw sockets
def start_search_thread(button):
   threading.Thread(target=on_btnStart_clicked).start()
   
# 
def on_btnStart_clicked():
   
   print "validating input"
   btnMac = main_window.get_widget("txtMac")
   btnNet = main_window.get_widget("txtSubnet")
   staStatus = main_window.get_widget("staStatus")

   print_message ( staStatus, "Starting..." )

   mac = btnMac.get_text().strip()
   sub = btnNet.get_text().strip()

   if mac == "" or sub == "":
      print "Invalid mac or subnet mask"
      print_message ( staStatus, "Invalid input" )
      return
  
   print_message ( staStatus, "Flushing ARP cache" )
   print "Flushing ARP cache"  
   
   output = commands.getstatusoutput("ip neigh flush all > /dev/null")

   print_message ( staStatus, "Broadcasting ping" )

   print "broadcast ping on subnet: " + sub
   
   # check if fping command has been installed

   output = commands.getstatusoutput("which fping")

   if int(output[0]) != 0:    # its not installed
      print "fping not installed. attepting manual ping"
      print_message ( staStatus, "fping not installed. attepting manual ping" )
      
      # attempt manual ping
      manual_ping ( sub )

   else:  # use fping
       output = commands.getstatusoutput("fping -c 1 -g -q " + sub +" 2> /dev/null")
       print "ping output : " + output[1]
       
   print_message ( staStatus, "Locating IP address" )
   output = commands.getstatusoutput("arp -n | grep \"" + mac + "\"")

   arpLine = output[1].split(" ");

   ip = arpLine[0].strip()

   if ip == "":
      print_message ( staStatus, "MAC address not found on subnet" )
   else:
      print_message ( staStatus, "Found: " + ip )
      
# quit button
def gtk_main_quit(window, event):
   gtk.main_quit()

# ------------- load the interface -------------

main_window = gtk.glade.XML('../gui/util.glade')

# connect handlers
main_window.signal_autoconnect(
   {
   "on_btnClose_clicked" : on_btnClose_clicked,
   "on_btnStart_clicked" : start_search_thread,
   "on_btnAbout_clicked" : on_btnAbout_clicked
   })

# pushs @param message onto status bar
def print_message ( status_widget, message ):
    
   global curr_message
   
   if curr_message is None:
      curr_message = 0        # str(curr_message) + ": "
      
   gtk.gdk.threads_enter()
   status_widget.push(curr_message,  message)
   curr_message+=1
   
   gtk.gdk.threads_leave()
   
   time.sleep(1)     # sleep for one second, so message is displayed properly
   
# attempt to get local ip address; only trying eth0, and eth1
lblLocalIP = main_window.get_widget("lblLocalIP")
try:
   ip = get_ip_address("eth0")
   lblLocalIP.set_text(ip)
except:
   try:
      ip = get_ip_address("eth1")
   except:
      ip = "None" 

lblLocalIP.set_text(ip)
 
gtk.gdk.threads_init()

# start the event loop
gtk.gdk.threads_enter()
gtk.main()
gtk.gdk.threads_leave()

# turns an integer to a binary string
def get_binary_value ( integer ):
 
    copy = integer
    bStr = ""

    while copy > 0:
            bStr = str(copy % 2) + bStr
            copy = copy >> 1
            
    return bStr

# converts binary ip address to octect . notation, i.e 10.0.0.2
def get_full_ip_address ( ip ):

    # print("%.%.%.%" % ip >> 24 & 0xFF, ip >> 16 & 0xFF, ip >> 8 & 0xFF, ip & 0xFF)
    
    octect_mask = 255 # first otect (from the right)
    one = ip & octect_mask

    octect_mask = octect_mask << 8 # shift left for next otect
    two = ip & octect_mask    # and together 
    two = two >> 8                 # shift back to get decimal
    
    octect_mask = octect_mask << 8 # and so on
    three = ip & octect_mask
    three = three >> 16
    
    octect_mask = octect_mask << 8
    four = ip & octect_mask
    four = four >> 24

    return str(four) + "." + str(three) + "." + str(two) + "." + str(one)

# manually pings @param network, using raw sockets. Expects @parm network
# to be in the format 192.168.0.1/24
def manual_ping ( network ):

    print "manual ping: " + network

    if network is None:
        print "Invalid network (no network passed)"
        return

    net = string.split(network,"/")

    if len(net) != 2:
        print "invalid network; required format is network/mask (i.e 10.0.0.2/24)"
        return 
   
    ip = net[0]
   # ip = ip[0:len(ip) ] splice example
    mask = net[1]

    print "manual ping, pinging network " + ip + " mask " + mask

    octects = string.split(ip,".")
    
    if len(octects) != 4:
        print "invalid network. must contain four .'s "
        return
    
    print "octects: " + str(octects)
    #         8         16        24        32
    # ip   00000000, 00000000, 00000000, 00000000
    #        10, 0 0 0
    # mask 00000000, 00000000, 00000000, 00000000
    
    # left shift each octect to appropriate position
    full_ip = (int(octects[0]) << 24) + (int(octects[1]) << 16) + (int(octects[2]) << 8) + int(octects[3])
    str_full_ip = get_binary_value ( full_ip )

    print "full ip:           " + str_full_ip.rjust(32,"0")  # pad out to 32 bits
    
    i = 0
    full_mask = 0

    for i in range (0,int(mask)):  # create full subnet mask by shifting bits left by mask number
        full_mask = (full_mask << 1) + 1

    full_mask = full_mask << (32 - int (mask))

    print "full mask:         " + get_binary_value ( full_mask )

    sub_net = int(full_ip) & int(full_mask)  # and subnet mask and full ip to get subnet
    
    str_sub_net = get_binary_value ( sub_net );

    print "calculated ip: " + get_full_ip_address(full_ip)
    print "calculated subnet: " + str(sub_net)
    print "calculated subnet: " + get_full_ip_address(sub_net)
    
    i = 0
    max_subnet = 0

    for i in range (0, 32 - int(mask)):  # create full subnet mask by shifting bits left by mask number
        max_subnet = (max_subnet << 1) + 1
           
    print "max subnet       : " + str(max_subnet)
    
    i = 0
    active_ip_cnt = 0      # used to declare index
    active_ips = []        # declare empty list
    
    for i in range (1, max_subnet): 
        curr_ip = sub_net + i
        curr_full_ip = get_full_ip_address ( curr_ip )
        print "pinging: " + curr_full_ip
 
        try:
            p = ping.Pinger(None,curr_full_ip,1)  # hostname, ip address, attempts
            p.ping()
            summary = p.get_summary()
            print "---Ping statistics---"
            print "%d packets transmitted, %d packets received, %d%% packet loss" % \
            (summary[3], summary[4], int(summary[5] * 100.))
            print "round-trip (ms)   min/avg/max = %d/%d/%d" % \
            (summary[0], summary[1], summary[2])
        
            if summary[6] is not None:
                print "macAddr: " + summary[6]
        
                if summary[4] > 0:  # got a packet back
                    active_ips.append(curr_ip)
    
        except:
           print "you must be root to perform this operation" , sys.exc_info()[0]
           return None
        
    return active_ips
