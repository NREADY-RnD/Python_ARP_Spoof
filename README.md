# Introduction

Manipulation of DNS traffic is a very dangerous attack. Knowing how it works, and how to write code to perform this spoofing is very important in understanding how to protect from it. For our assignment we have implemented a very simple ARP and DNS spoofer in python that will send spoofed DNS responses to a victim, redirecting all of their web requests to an ip address you specify. 

# Design

Our application has these main components: 

1. Start → Get user input of ip addresses needed for spoofing

2. We need to enable IP forwarding, and add an iptables rule as to not send back the legit DNS responses to our victim.

3. Initialize → here is where we craft our ARP packets then start our threads

4. ARP Thread → This thread sends out the spoofed arp packets to the router and victim

5. DNS Thread → Here we sniff for incoming DNS requests, and send back spoofed responses redirecting the victim to our spoofing webservice

# Design - Diagram

![image alt text](/readme_images/image_0.png)

# Testing 

The following requirements were given for a successful DNS spoof implementation:

* Your application will simply sense an HTML DNS Query and respond with a crafted Response answer, which will direct the target system to a your own web site.

* You will test this POC on a LAN on your own systems only. This means that you are not to carry out any DNS spoofing activity on unsuspecting client systems.

* You are required to handle any arbitrary domain name string and craft a spoofed Response. 

Based on the requirements above, we came up with the test cases below to test the application against. Our results and discussion of each test case are presented in the following sections.

 

<table>
  <tr>
    <td>#</td>
    <td>Scenario</td>
    <td>Tools Used</td>
    <td>Expected Behavior</td>
    <td>Actual Behavior</td>
    <td>Status</td>
  </tr>
  <tr>
    <td>1</td>
    <td>Sense HTML DNS Queries </td>
    <td>Wireshark,
Scapy,
Python</td>
    <td>Victim’s DNS Queries appear on attacker’s machine</td>
    <td>Victim’s DNS Queries appear on attacker’s machine</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>2</td>
    <td>Send back spoof DNS responses</td>
    <td>Python, Scapy, Wireshark</td>
    <td>DNS Responses appear on both attacker and target machines as DNS responses</td>
    <td>DNS Responses appear on both attacker and target machines as DNS responses</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>3</td>
    <td>Victim is redirected to our web service</td>
    <td>Node.js
Chrome</td>
    <td>User is redirected to our "You have been spoofed site" when they try to navigate to any A record URL</td>
    <td>User is redirected to our “You have been spoofed site” when they try to navigate to any A record URL</td>
    <td>Pass




</td>
  </tr>
  <tr>
    <td>4</td>
    <td>Handle any arbitrary domain name string and craft a spoofed Response. 
</td>
    <td>Python,
Scapy,
Wireshark</td>
    <td>We send spoofed packets on any DNS request from the victim</td>
    <td>We send spoofed packets on any DNS request from the victim</td>
    <td>Pass</td>
  </tr>
</table>


An example of how we started our application: 

![image alt text](/readme_images/image_1.png)

# Test 1 Sense HTML DNS Queries

**DNS Queries as they appear on the attackers machine.**

![image alt text](/readme_images/image_2.png)

![image alt text](/readme_images/image_3.png)

**DNS Queries as they appear on our spoofer application.**![image alt text](/readme_images/image_4.png)

# Test 2 Send back spoof DNS responses

**Here is a response that our spoofer has sent, as seen by the attacker’s machine.**

![image alt text](/readme_images/image_5.png)![image alt text](/readme_images/image_6.png)

**An answer as seen by the victim machine: **

As you can see the spoofed response is for milliways.bcit.ca but the address is shown as 192.168.2.50

![image alt text](/readme_images/image_7.png)

**Nslookups as seen by the victim machine: **

Here we demonstrate how all nslookups turn up as our spoofed address of 192.168.2.50 where our web server is running.

![image alt text](/readme_images/image_8.png)

# Test 3 Victim is redirected to our web service

When victim navigates to any web page, they will be redirected to our "you have been spoofed webpage" 

![image alt text](/readme_images/image_9.png)![image alt text](/readme_images/image_10.png)

As you can see even mobile devices can be affected by this spoof: 

![image alt text](/readme_images/image_11.png)

# Test 4 Handle any arbitrary domain name string and craft a spoofed Response

Any arbitrary request will be redirected: 

![image alt text](/readme_images/image_12.png)

# Conclusion

After doing this assignment we have realised how easy it is to perform these type of man in the middle attacks on unsuspecting networks. It really demonstrates the necessity to protect ourselves and our information when we are navigating the web on any network. 

By writing this application we better understand the ARP and DNS protocols and will be much more effective as security admins out in the field. 

