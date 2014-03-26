MAC to IP translation GUI
====================================

Works by using fping to ping every ip on a given subnet, then checking the arp cache for existance of that mac address.


Requirements
--------------------------------

This program requres the gtk.glade python bindings for glade, and either the command "fping" (known to work with Version 2.4b2_), OR root access (as raw sockets require it) to perform the ICMP request manually. Using raw sockets is much slower than fping at this stage, so be careful when specifying large subnets.


Usage
--------------------------------

``` python
python locator/__init__.py
```
