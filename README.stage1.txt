In stage 1, I made a simple UDP communication between a proxy and a router the exercise was easy and helpful. 
I learned how to make a UDP socket. Particularly, the creation of the socket address and the binding. What I also learned is how the fork() command works in c and how we can distinguish the parent from the child by checking the return value of the fork() command.
Being familiar with C the reading/writing to files was seemingly easy.

a)Reused Code: I used the UDP communication code from here: (Marked in the code) https://www.cs.rutgers.edu/~pxk/417/notes/sockets/udp.html - (1)
https://austinmarton.wordpress.com/2011/09/14/sending-raw-ethernet-packets-from-a-specific-interface-in-c-on-linux/ - (2)
http://www.binarytides.com/packet-sniffer-code-c-linux/ - (3)
https://stackoverflow.com/questions/13620607/creating-ip-network-packets - (4)
and alot of small commands from stackoverflow.

b)Complete: Yes. Everything works as intended.

c)Portable: Yes. I think the program would work in different architicture if the other device is using 
the same compiler and equipped with all the required libraries. Because, the compiler will handle the differences
and for the communication between the proxy and the router. We are using UDP wish is a standard protocol
and core members of the Internet protocol suite. defined in rfc768 (https://www.ietf.org/rfc/rfc768.txt)
similarly for the ICMP communication which is also defined in rfc792 (https://tools.ietf.org/html/rfc792).
