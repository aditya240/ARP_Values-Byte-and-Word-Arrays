# ARP_Values-Byte-and-Word-Arrays_using_C

Here we are trying to decode the ARP Packet Details (as shown below). The details are in the form of various byte and word arrays. We also have a header file (arp_header.h) which contains the various user-defined data structures which were used to implement the required functionality

Compile using : gcc decoder.c -o decoder

Example ouptut :-

ARP PACKET DETAILS 
     htype:     0x0001 
     ptype:     0x0800 
     hlen:      6  
     plen:      4 
     op:        1 
     spa:       192.168.1.51 
     sha:       01:02:03:04:05:06 
     tpa:       192.168.1.1 
     tha:       aa:bb:cc:dd:ee:ff 
