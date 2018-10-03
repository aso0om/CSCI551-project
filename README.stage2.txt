In stage 2, I was able to effectively use select() to monitor both tun_fd and  srv_fd,also extract the ICMP packet data and send
the data to the router and back with a replay. I faced a problem with the udp sockets when I'm forking new
routers, which is since I'm forking in a for loop the first child block the forking from the rest of the childs
because it is waiting for an input from the proxy server using recvfrom() function. also the managment of the different file descriptors
sometimes it gets confusing.   

Reused Code: I used the UDP communication code from here: (Marked in the code) https://www.cs.rutgers.edu/~pxk/417/notes/sockets/udp.html - (1)
https://austinmarton.wordpress.com/2011/09/14/sending-raw-ethernet-packets-from-a-specific-interface-in-c-on-linux/ - (2)
http://www.binarytides.com/packet-sniffer-code-c-linux/ - (3)
https://stackoverflow.com/questions/13620607/creating-ip-network-packets - (4)

Complete: No. I wasn’t able to write the Echo replay packet back to the tunnel, I tried writing the data 
directly using write() with same descriptor .. didn’t work. I also tried creating RAW socket and then
send the data using sendto() still didn’t work, tried to bind a socket with a an interface both (lo and tun1) and then craft a 
a new ICMP packet still the resposnse doesn't reach I tried also couple of other methods. I’m pretty sure
I’m missing something small but I spent hours and I couldn’t find it.

c)Portable: Yes. I think the program would work in different architicture if the other device is using 
the same compiler and equipped with all the required libraries. Because, the compiler will handle the differences
and for the communication between the proxy and the router. We are using UDP wish is a standard protocol
and core members of the Internet protocol suite. defined in rfc768 (https://www.ietf.org/rfc/rfc768.txt)
similarly for the ICMP communication which is also defined in rfc792 (https://tools.ietf.org/html/rfc792).
