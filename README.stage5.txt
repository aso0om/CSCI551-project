stage5 was among the hardest parts of the project which include alot of coding and many things could go easily wrong because when there
is an error in one the routers it probagates to other routers which sometimes lead to long time of debuggining

a)Reused Code: I used the UDP communication code from here: (Marked in the code) https://www.cs.rutgers.edu/~pxk/417/notes/sockets/udp.html - (1)
https://austinmarton.wordpress.com/2011/09/14/sending-raw-ethernet-packets-from-a-specific-interface-in-c-on-linux/ - (2)
http://www.binarytides.com/packet-sniffer-code-c-linux/ - (3)
https://stackoverflow.com/questions/13620607/creating-ip-network-packets - (4)
and countless stackoverflow and small forum topics that are to many to mintion, plus I take small hints.

b)Complete: Yes, works as intended. :)

c)Because, the idea of onion routing is that the hops in the circuit do not know the source (except the first hop) or else the anonimity 
of the user is compromised.

