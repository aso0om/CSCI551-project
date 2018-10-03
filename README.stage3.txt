In stage 3, it took me a considarable amount of time to relay the ICMP packet to the internet. At first
I faced issues with configuring the adapters of the hyporvisor which is in my case (VMware player), after
that I had problems with sendmsg() and I used sendto() which worked just fine.

a)Reused Code: I used the UDP communication code from here: (Marked in the code) https://www.cs.rutgers.edu/~pxk/417/notes/sockets/udp.html - (1)
https://austinmarton.wordpress.com/2011/09/14/sending-raw-ethernet-packets-from-a-specific-interface-in-c-on-linux/ - (2)
http://www.binarytides.com/packet-sniffer-code-c-linux/ - (3)
https://stackoverflow.com/questions/13620607/creating-ip-network-packets - (4)
and countless stackoverflow and small forum topics that are to many to mintion, plus I take small hints.

b)Complete: Yes, works as intended. :)

c)Addressing on the way out of your router: so that the real source would not be known, and that's usually
the job of the proxy.

d)Addressing on the way in to the VM: because, if all the routers were on the same network, it would be
easy to monitor and correlate the traffic.

e)Addressing from the VM to the host: The host is doin network address transilation to the 
outgoing traffic.

