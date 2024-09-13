https://www.youtube.com/watch?v=5PKAa6TI82U
https://www.youtube.com/watch?v=4DvbsZU-psg
https://www.youtube.com/watch?v=SObjAYjOzAg

https://medium.com/@haircutfish/tryhackme-wireshark-traffic-analysis-task-1-introduction-task-2-nmap-scans-829476811898
https://medium.com/@haircutfish/tryhackme-wireshark-traffic-analysis-task-3-arp-poisoning-man-in-the-middle-and-task-4-4b15305d539a
https://medium.com/@haircutfish/tryhackme-wireshark-traffic-analysis-task-5-tunneling-traffic-dns-and-icmp-task-6-cleartext-a207e006fbd1
https://medium.com/@haircutfish/tryhackme-wireshark-traffic-analysis-task-7-cleartext-protocol-analysis-http-task-8-encrypted-1d3d929f6b9
https://medium.com/@haircutfish/tryhackme-wireshark-traffic-analysis-task-9-bonus-hunt-cleartext-credentials-5379bb1c28e6

Learn the basics of traffic analysis with Wireshark and how to find anomalies on your network!

# Task 1 Introduction

In this room, we will cover the techniques and key points of traffic analysis with Wireshark and detect suspicious activities. Note that this is the third and last room of the Wireshark room trio, and it is suggested to visit the first two rooms stated below to practice and refresh your Wireshark skills before starting this one.

- [**Wireshark: The Basics**](https://tryhackme.com/room/wiresharkthebasics)
- [**Wireshark: Packet Operations**](https://tryhackme.com/room/wiresharkpacketoperations)

In the first two rooms, we have covered how to use Wireshark and do packet-level searches. Now, it is time to investigate and correlate the packet-level information to see the big picture in the network traffic, like detecting anomalies and malicious activities. For a security analyst, it is vital to stop and understand pieces of information spread in packets by applying the analyst’s knowledge and tool functionality. This room will cover investigating packet-level details by synthesising the analyst knowledge and Wireshark functionality for detecting anomalies and odd situations for a given case.

**Note:** A VM is attached to this room. You don’t need SSH or RDP; the room provides a “Split View” feature. **DO NOT** directly interact with any domains and IP addresses in this room. The domains and IP addresses are included only for reference reasons.

# Task 2 Nmap Scans

## Nmap Scans

Nmap is an industry-standard tool for mapping networks, identifying live hosts and discovering the services. As it is one of the most used network scanner tools, a security analyst should identify the network patterns created with it. This section will cover identifying the most common Nmap scan types.

- TCP connect scans
- SYN scans
- UDP scans

It is essential to know how Nmap scans work to spot scan activity on the network. However, it is impossible to understand the scan details without using the correct filters. Below are the base filters to probe Nmap scan behaviour on the network.

**TCP flags in a nutshell.**

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/2dc3c9c19481f5a5c6b7327d29ddbb35_MD5.jpg)

## TCP Connect Scans

**TCP Connect Scan in a nutshell:**

- Relies on the three-way handshake (needs to finish the handshake process).
- Usually conducted with `nmap -sT` command.
- Used by non-privileged users (only option for a non-root user).
- Usually has a windows size larger than 1024 bytes as the request expects some data due to the nature of the protocol.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/e12c8f7cf22ea600185719c23ec8a312_MD5.jpg)

The images below show the three-way handshake process of the open and close TCP ports. Images and pcap samples are split to make the investigation easier and understand each case’s details.

**Open TCP port (Connect):**

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/0d01f650f47881462f0120ca6ed0c434_MD5.jpg)

**Closed TCP port (Connect):**

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/1f5fa7195f79d6fccbdf300ce92fc1b0_MD5.jpg)

The above images provide the patterns in isolated traffic. However, it is not always easy to spot the given patterns in big capture files. Therefore analysts need to use a generic filter to view the initial anomaly patterns, and then it will be easier to focus on a specific traffic point. The given filter shows the TCP Connect scan patterns in a capture file.

`tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024`

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/b7f3c35196d09ba2acafec9cb1d15c92_MD5.jpg)

## SYN Scans

**TCP SYN Scan in a nutshell:**

- Doesn’t rely on the three-way handshake (no need to finish the handshake process).
- Usually conducted with `nmap -sS` command.
- Used by privileged users.
- Usually have a size less than or equal to 1024 bytes as the request is not finished and it doesn’t expect to receive data.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/82eb45ebbb07e1e8436b62f6b010db9a_MD5.jpg)

**Open TCP port (SYN):**

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/4e7abd60c5ae2957751e6ea47ab4ebd6_MD5.jpg)

**Closed TCP port (SYN):**

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/2ccff0504534632202a880c633bdf6e1_MD5.jpg)

The given filter shows the TCP SYN scan patterns in a capture file.

`tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024`

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/b9c4badae22af1a8890dda437a2c9a6b_MD5.jpg)

## UDP Scans

**UDP Scan in a nutshell:**

- Doesn’t require a handshake process
- No prompt for open ports
- ICMP error message for close ports
- Usually conducted with `nmap -sU` command.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/7e62a82aee6a6f98d9beccd614e6df63_MD5.jpg)

**Closed (port no 69) and open (port no 68) UDP ports:**

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/b549040b86ebf8a66c038b81102f9479_MD5.jpg)

The above image shows that the closed port returns an ICMP error packet. No further information is provided about the error at first glance, so how can an analyst decide where this error message belongs? The ICMP error message uses the original request as encapsulated data to show the source/reason of the packet. Once you expand the ICMP section in the packet details pane, you will see the encapsulated data and the original request, as shown in the below image.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/6ac789627c9bd65557254344356a0023_MD5.jpg)

The given filter shows the UDP scan patterns in a capture file.

`icmp.type==3 and icmp.code==3`

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/551b3fc70fa1038403a056645d63ee17_MD5.jpg)

Detecting suspicious activities in chunked files is easy and a great way to learn how to focus on the details. **Now use the exercise files to put your skills into practice against a single capture file and answer the questions below!**

### Answer the questions below

Use the “Desktop/exercise-pcaps/nmap/Exercise.pcapng” file.

Inside the _exercise-pcaps_ folder, double-click on the _nmap_ folder.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/1c4162a3ce9afd9333a6b4f7ab3f01ac_MD5.jpg)

Inside the nmap folder you will see the _Exercise.pcap_ file. Right-click on it, then choose _Open With Wireshark_ from the drop-down menu.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/f701e95d5e349ab6c89955f2419be611_MD5.jpg)

You are now ready to answer the following questions.

**What is the total number of the “TCP Connect” scans?**

The command needed to find the answer is given above. But I am going to explain what exactly the command is looking for. In short this command looks for the TCP Connect Scan that results in a Closed Port. The `tcp.flags.syn == 1` looks for the _SYN_ flag being set on a TCP packet. Then the `tcp.flags.ack == 0` is looking for any packet that doesn’t have the _ACK_ flag set. Finally it is also looking for any packet that has a size greater than 1024 bytes. After we put together the command, it will be `tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024` . Type this into the mint green filter bar, then press enter to use this filter on the pcapng.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/71292a4786da6ac21d82925e92552b3f_MD5.jpg)

Look at the bottom right of the Wireshark window. You are looking for the word _Displayed:_. The numbers to the right of _Displayed_, is the answer. Type the answer in the THM answer field, and then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/884f2fe10e3a517831a0c16f6f4a0a7e_MD5.jpg)

Answer: 1000

**Which scan type is used to scan the TCP port 80?**

Since we want to know that we are looking at port 80 via TCP. Click on the mint green filter bar, and use the filter `tcp.port == 80`. This will filter out and display only packets that travel over TCP to port 80. Press enter to use apply this filter.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/20cb968f1391f85fa4293c815d1b90bd_MD5.jpg)

You will be left with 7 results. Looking at the first 4 results we can see that they are all part of the same stream by the connecting bracket. So next we want to move down to the _Info section_, to figure out what type of scan this could be.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/d6403e123981d5e5b408ecc3e32d7573_MD5.jpg)

Taking a look at the different flags that were used, we see _SYN, SYN ACK, ACK, RST ACK_. It looks like the process of a _Three-way Handshake_. Knowing this, along with what we read above, we can figure out what type of scan this is. Once you figure it out, type the answer in the THM answer field, and then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/4d70a80009165855a5862f5c3b9115d1_MD5.jpg)

Answer: tcp connect

**How many “UDP close port” messages are there?**

The command needed to find the answer is given above. But I am going to explain what exactly the command is looking for. With the filter we are looking at both the _ICMP type_ and _code_, both of which is _3_. We know this by the information given to us by THM above in the table. So the filter is `icmp.type == 3 and icmp.code == 3`. Once you have typed the filter into the mint green filter bar, press enter to use it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/e112dea1f949c9bc62df2892a6471281_MD5.jpg)

Look at the bottom right of the Wireshark window. You are looking for the word _Displayed:_. The numbers to the right of _Displayed_, is the answer. Type the answer in the THM answer field, and then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/9ca5f66e06e1318c6431613136400690_MD5.jpg)

Answer: 1083

**Which UDP port in the 55–70 port range is open?**

The question is looking to find out which UDP port is open amongst the port range. To be honest, I had to do some searching to figure out the correct syntax for the filter. Huge shout out to Chris Greer, and his [YouTube Short](https://www.youtube.com/shorts/R4L5ONvznmQ) that shows how to properly create this filter. Since we are looking for a UDP protocol port, we start the filter with `udp.port`. Then we are looking at the ports `in` a port range, we add the `in` operator. Now it’s time for the port range, to achieve this we need to use the curly brackets (`{ }`). We then put the port range in between the curly bracket with a double period between the numbers, `55..70`. Let’s put it all together, `udp.port in {55..70}`. Type the filter into the mint green filter bar, then press enter to use.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/3e666e1be11a26a7dc74f57a18e9cc12_MD5.jpg)

As we can see from the search results, the first UDP attempts met a closed port. But upon the third try, an open port was found. Once you see the open port. Type the answer in the THM answer field, and then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/b8e3ef3be69fe44b5e7156e15e90c159_MD5.jpg)

Answer: 68

# Task 3 ARP Poisoning & Man In The Middle!

## **ARP Poisoning/Spoofing (A.K.A. Man In The Middle Attack)

**ARP** protocol, or **A**ddress **R**esolution **P**rotocol (**ARP**), is the technology responsible for allowing devices to identify themselves on a network. Address Resolution Protocol Poisoning (also known as ARP Spoofing or Man In The Middle (MITM) attack) is a type of attack that involves network jamming/manipulating by sending malicious ARP packets to the default gateway. The ultimate aim is to manipulate the **“IP to MAC address table”** and sniff the traffic of the target host.

There are a variety of tools available to conduct ARP attacks. However, the mindset of the attack is static, so it is easy to detect such an attack by knowing the ARP protocol workflow and Wireshark skills.

**ARP analysis in a nutshell:**

- Works on the local network
- Enables the communication between MAC addresses
- Not a secure protocol
- Not a routable protocol
- It doesn’t have an authentication function
- Common patterns are request & response, announcement and gratuitous packets.

Before investigating the traffic, let’s review some legitimate and suspicious ARP packets. The legitimate requests are similar to the shown picture: a broadcast request that asks if any of the available hosts use an IP address and a reply from the host that uses the particular IP address.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/6ad18b1f3fed994508d7333d22eec6ba_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/dc100e6e061c640bdf499bd0c9af6b51_MD5.jpg)

A suspicious situation means having two different ARP responses (conflict) for a particular IP address. In that case, Wireshark’s expert info tab warns the analyst. However, it only shows the second occurrence of the duplicate value to highlight the conflict. Therefore, identifying the malicious packet from the legitimate one is the analyst’s challenge. A possible IP spoofing case is shown in the picture below.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/9d37dac80c0c0b52a92559c8e02bcc04_MD5.jpg)

Here, knowing the network architecture and inspecting the traffic for a specific time frame can help detect the anomaly. As an analyst, you should take notes of your findings before going further. This will help you be organised and make it easier to correlate the further findings. Look at the given picture; there is a conflict; the MAC address that ends with “b4” crafted an ARP request with the “192.168.1.25” IP address, then claimed to have the “192.168.1.1” IP address.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/258d3df8e909218498519d14222c0d96_MD5.jpg)

Let’s keep inspecting the traffic to spot any other anomalies. Note that the case is split into multiple capture files to make the investigation easier.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/86d4475dd934877a60979156c586126b_MD5.jpg)

At this point, it is evident that there is an anomaly. A security analyst cannot ignore a flood of ARP requests. This could be malicious activity, scan or network problems. There is a new anomaly; the MAC address that ends with “b4” crafted multiple ARP requests with the “192.168.1.25” IP address. Let’s focus on the source of this anomaly and extend the taken notes.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/e23d39c8602594692d2660a88d4f5c80_MD5.jpg)

Up to this point, it is evident that the MAC address that ends with “b4” owns the “192.168.1.25” IP address and crafted suspicious ARP requests against a range of IP addresses. It also claimed to have the possible gateway address as well. Let’s focus on other protocols and spot the reflection of this anomaly in the following sections of the time frame.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/b3dcd8b9825e043ce1e4fa35a8b97902_MD5.jpg)

There is HTTP traffic, and everything looks normal at the IP level, so there is no linked information with our previous findings. Let’s add the MAC addresses as columns in the packet list pane to reveal the communication behind the IP addresses.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/c3dcfafd7fb59d62f8647c562819813c_MD5.jpg)

One more anomaly! The MAC address that ends with “b4” is the destination of all HTTP packets! It is evident that there is a MITM attack, and the attacker is the host with the MAC address that ends with “b4”. All traffic linked to “192.168.1.12” IP addresses is forwarded to the malicious host. Let’s summarise the findings before concluding the investigation.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/23a35246132c891c17677990ff36008b_MD5.jpg)

Detecting these bits and pieces of information in a big capture file is challenging. However, in real-life cases, you will not have “tailored data” ready for investigation. Therefore you need to have the analyst mindset, knowledge and tool skills to filter and detect the anomalies.

**Note:** In traffic analysis, there are always alternative solutions available. The solution type and the approach depend on the analyst’s knowledge and skill level and the available data sources.

Detecting suspicious activities in chunked files is easy and a great way to learn how to focus on the details. **Now use the exercise files to put your skills into practice against a single capture file and answer the questions below!**

### Answer the questions below

Use the “Desktop/exercise-pcaps/arp/Exercise.pcapng” file.

Inside the _exercise-pcaps_ folder, double-click on the _arp_ folder.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/061e5ca81ddc40c05cb6abbf2513bf6b_MD5.jpg)

Inside the arp folder you will see the _Exercise.pcap_ file. Right-click on it, then choose _Open With Wireshark_ from the drop-down menu.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/3e44ab8804daa92de7f469e347f9113f_MD5.jpg)

**What is the number of ARP requests crafted by the attacker?**

First, we need to figure out what the attacker’s IP or MAC address is. Taking into account from the question, we are looking for ARP requests. So to me it seems like the attacker is scanning the system. With all of this knowledge, we can start to figure out the filter we need to craft to be able to find the answer. Scrolling up to the table that THM provided at the beginning of this task, we can find a filter for possible ARP scanning. That being `arp.dst.hw_mac==00:00:00:00:00:00`. Copy (_ctrl_+_C_) & Paste(_crtl_+_P_) or type the filter into the mint green filter bar in Wireshark, then press enter.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/ff486de3b60b4af53d7ad0c2dce4ebbf_MD5.jpg)

From the results we can see that the Source MAC address seems to be scanning the system. This could be our attacker, so to investgate this possibility, right-click on the Source MAC address. Hover you cursor over the _Apply as Filter_. Another drop-down menu will appear. Move your cursor over to the _…and Selected_ and click on it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/9ce3c94f257d372a84eccfc5e2c8a87f_MD5.jpg)

Looking at the results it seems like we may have our answer. But since the question did say _Requests_, then we want to confirm this. We can easily do this by adding onto our filter.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/2bb426e372f198ad4bf960a844e150f8_MD5.jpg)

Following the syntax already established by the search parameters, along what THM shared at the start of this task. We can add the following to the end of our filter: `&& (arp.opcode==1)`. Adding this to the end of the filter will show only _Arp Request from the suspected Malcious actor_. Once you have typed it into the mint green search bar, press enter to search.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/fb270aa8277a7b4e843e3dce87b37bd4_MD5.jpg)

The answer will be located in the bottom right of the Wireshark window. The number next to _Displayed_ is the answer to the question. Once you have found it, type it into the THM answer field. The click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/638010fc36b80aa11c40f12671d381eb_MD5.jpg)

Answer: 284

**What is the number of HTTP packets received by the attacker?**

Since we know what the MAC address is for the attacker, we can use that to search for the HTTP packets. To do this you will need to follow a couple of steps. The first being in the Detail section of Wireshark. You want to click on the _drop-down carot for Layer 2_. You will then see _Destination_ and _Source_, click on the _drop-down carot for Source_. We can now see the attacker’s MAC address, time to apply it as a filter. To do this, right-click on _Address: VMware_e2:18:b4 (00:0c:29:e2:18:b4)_. A drop-down menu will appear, move your cursor over top of _Apply as Filter_. The final drop-down menu will appear, move your cursor over to _Selected_ and click on it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/d0d485a3692995c60615c63479a00da6_MD5.jpg)

The filter will appear in the mint green Filter bar. Now before we press enter and use it, we need to add to the filter. Since the question is asking for HTTP we can add to the end of the filter `&& http`. This will search for any HTTP packets from our attackers MAC address. Now press enter to use the filter.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/991a568f1a350a93c7b05a5b0ca8bcd6_MD5.jpg)

You should now have all the HTTP packets attributed to the attackers MAC address. The answer will be located in the bottom right of the Wireshark window. The number next to _Displayed_ is the answer to the question. Once you have found it, type it into the THM answer field. The click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/6aa2867386921a135ec2f091002d982e_MD5.jpg)

Answer: 90

**What is the number of sniffed username&password entries?**

Heading back to Wireshark, we can stick with the filter we currently have to start investigating. Looking at the _Info_ section of the packet area, we can see an interesting frame. Inside this frame we see _POST_ and _/userinfo.php_

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/3d40af1702f1f7b6f55e16e7ef235e32_MD5.jpg)

Inspecting the _Details_ section, we can see that we are correct. We see the _username_ and _password._ Time to filter down so that we only see these types of packets.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/939e1b23e4252867d6bb830a4affcf8a_MD5.jpg)

To do this we first need to dig down a bit. Do this by clicking on the drop-down carot on _Hypertext Transfer Protocol._ Again click on the drop-down carot next to _POST /userinfo.php._ You should now see _Request URI: /userinfo.php_. Right-click on _Request URI: /userinfo.php_, from the drop-down menu hover your cursor over _Apply as Filter._ When the new drop-down menu appears, move your cursor over to _…and Selected._ Then click on it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/d19588868ff9074853b8290c0f8b0480_MD5.jpg)

As we can see we have 8 results left. Two of which seem to be a bit larger than the others. Let’s check them out to see they contain _usernames_ and _passwords_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/d2dd4f5df6b778eb67b027224f55deb8_MD5.jpg)

Taking a look we can see a _username_, but no _password_. So it seems safe to believe that the two packets that are larger, do not contain _passwords_ (feel free to take a look since there is only one other packet).

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/32eb28681a0a2ab956bc21e7d4d9c7b4_MD5.jpg)

So it looks like we need to count the other packets we have left. Once you have done this, type the number into the THM answer field, and click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/11ca56fa1f8f0c12640945a91f944648_MD5.jpg)

Answer: 6

**What is the password of the “Client986”?**

Time to do some inspecting. We need to click on each of the packets. Then check out the detail section of each. At the bottom of the Detail section is _HTML Form URL Encoded: application/x-www-for-urlencoded._ Under this drop down is _uname_ and _pass_. You need to look at each till you find the _uname Client986_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/7a3a9048f77ed7b3584afe0c7f4a64fe_MD5.jpg)

Once you find it, type the answer into the THM answer field. Then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/2e835c548e80a282ab29e880f3c57ba5_MD5.jpg)

Answer: clientnothere!

**What is the comment provided by the “Client354”?**

To be honest this took me a while to figure out as I was over looking and narrowed my scope to much. I took a step back and removed the filter that showed only _HTTP URI of /userinfo.php_. To do this delete that filter from the filter field, but don’t press enter to resubmit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/8a8143b1c2822bd7089819d03803362e_MD5.jpg)

Now right-click on _HTML Form URL Encoded: application/x-www-for-urlencoded_. On the drop-down menu, hover your cursor over _Apply as Filter_. Then an new drop-down will appear, click on _…and Selected_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/1b354e4882d7405cf4ac8877274b42f9_MD5.jpg)

Looks like we have two new packets, _newuser.php_ and _comment.php_. Since we want to see what comment was made by _client354_. It is safe to say we want to check the packet containing _comment.php_, so click on it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/15e4a539364f49a8edbc87f9fb01bb89_MD5.jpg)

This was the right call, because as we can see we have _client354_ and _comment_. So if we look at _comment_ we can find the answer. Once you see it, type it into the THM answer field. Then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/00a900fc53805a50440225c8dff744e6_MD5.jpg)

Answer: Nice Work!

# Task 4 Identifying Hosts: DHCP, NetBIOS and Kerberos

## Identifying Hosts

When investigating a compromise or malware infection activity, a security analyst should know how to identify the hosts on the network apart from IP to MAC address match. One of the best methods is identifying the hosts and users on the network to decide the investigation’s starting point and list the hosts and users associated with the malicious traffic/activity.

Usually, enterprise networks use a predefined pattern to name users and hosts. While this makes knowing and following the inventory easier, it has good and bad sides. The good side is that it will be easy to identify a user or host by looking at the name. The bad side is that it will be easy to clone that pattern and live in the enterprise network for adversaries. There are multiple solutions to avoid these kinds of activities, but for a security analyst, it is still essential to have host and user identification skills.

Protocols that can be used in Host and User identification:

- Dynamic Host Configuration Protocol (DHCP) traffic
- NetBIOS (NBNS) traffic
- Kerberos traffic

## DHCP Analysis

**DHCP** protocol, or **D**ynamic **H**ost **C**onfiguration **P**rotocol **(DHCP),** is the technology responsible for managing automatic IP address and required communication parameters assignment.

**DHCP investigation in a nutshell:**

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/4a87e150f3a8ae8691353ccd3ce428e8_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/ed2a8cc90177f9728be5ec1aef8cdb98_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/e87a7848a276355dc957e2bf7cfcbdd4_MD5.jpg)

## NetBIOS (NBNS) Analysis

**NetBIOS** or **Net**work **B**asic **I**nput/**O**utput **S**ystem is the technology responsible for allowing applications on different hosts to communicate with each other.

**NBNS investigation in a nutshell:**

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/c484b2b7ae5121f5f2521022b4114abe_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/0a85021cd5b700b741bad2015ded8a6f_MD5.jpg)

## Kerberos Analysis

**Kerberos** is the default authentication service for Microsoft Windows domains. It is responsible for authenticating service requests between two or more computers over the untrusted network. The ultimate aim is to prove identity securely.

**Kerberos investigation in a nutshell:**

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/b4c7ec1c5715a2cc49339ed0c4a46194_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/c540ae7260afe3e203bb0227146ba1ef_MD5.jpg)

Detecting suspicious activities in chunked files is easy and a great way to learn how to focus on the details. **Now use the exercise files to put your skills into practice against a single capture file and answer the questions below!**

### Answer the questions below

Use the “Desktop/exercise-pcaps/dhcp-netbios-kerberos/dhcp-netbios.pcap” file.

Going back to the folder where the pcapng file is located. Click on the _Back_ button in the upper left of the arp folder’s window.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/75c5e32322f0112709faa59a6e38628b_MD5.jpg)

Now being in the exercise-pcaps folder, double-click on _dchp-netbios-kerberos_ folder to open it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/0920cd30d1b52431a75ab46c36fe4d3a_MD5.jpg)

Now being inside the dhcp-netbios-pcaps folder, right-click on the _dchp-netbios.pcap_ file. From the drop-down menu, click on _Open With Wireshark_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/f3dc2a2139b31ab3b3c7572b95ec1238_MD5.jpg)

**What is the MAC address of the host “Galaxy A30”?**

A way we can find this is using DHCP (Dynamic Host Configuration Protocol). Since DHCP will will assign an IP address to everything attached to the network. From the reading above, we know that the option for a DHCP request is 3. Along with that we are looking for a device the Galaxy in the Hostname. So let’s build our filter with our knowledge, we can start with `dhcp.option.dhcp == 3` which will look for DHCP request. Then `and`, followed by `dhcp.option.hostname contains "Galaxy"`. Which will look for any host names that have Galaxy in the name. All together the filter looks like this: `dhcp.option.dhcp == 3 and dhcp.option.hostname contains “Galaxy”` . After you typed it into the mint green filter bar, press enter to filter for you query.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/6d8667f3f3da20e1125510e346278b7b_MD5.jpg)

Looks like we are left with two results. Taking a look at the Source IP, we can see the first one is coming from inside the system. While the second one looks to be outside the system getting an interior IP address. Let’s take a look at this one, click on the result. In the Packet Detail section let’s inspect the details by clicking the carot to drop the DHCP section.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/0a962f85fb13b48e7ed6b12cefc79080_MD5.jpg)

Looks like we have a lot of info, so scroll down till you see the different _Options_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/4d3b982e50f279eae2202f304703c81e_MD5.jpg)

Once you reach the _Options_ section. You should see one labeled _Option: (12) Host Name._ Click on the carot to drop down the details of this section. Taking a look at it we can see that is the _Galaxy A30_ we are looking for. Time to scroll up just a bit to see the _MAC_ _Address_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/841f20a5ebf79e6b59330e746a570b88_MD5.jpg)

Once you see the _Client MAC address:_ you have found the answer. You can type it into the answer field. Or you can _right-click_ on the _Client MAC address_. Then from the drop-down menu, hover you mouse over _Copy_. A new drop-down will appear, move your mouse over to _Value_ and _click_ on it. Now you can paste the answer into the THM answer field, and click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/a72b600ac77963edc960ca6d48695d47_MD5.jpg)

Answer: 9a:81:41:cb:96:6c

**How many NetBIOS registration requests does the “LIVALJM” workstation have?**

After reading the section above, the start of this should be pretty start forward. We are looking for a the NetBIOS name. So to start crafting this filter we will use `nbns.name contains "LIVALJM"`. Since THM gave us the name we added it into the section after contains. Once this is typed into the mint green filter bar, press enter to filter for your query.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/b34548b1824cbd79019c09dbdb8386c9_MD5.jpg)

We are now left with the results that match the netBIOS name. But we can see that there is more than just Registration requests. So if you want to you could use some counting to find the answer. But I want to filter these so that only the Registration requests are the only thing that appears. To do this we can click on the carot of the _NetBIOS Name Service_ to reveal the details to help us filter this down further.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/5daa1086f94dd3ee673bdd739aaa089b_MD5.jpg)

The first thing that catches my eye is that in the section is _Registration_. Since we are looking for _registration requests_, it seems like a great way to narrow this down. Click the carot to drop-down the _Flags_ section, to show more details. Inside this section we can see that _O_pcode: _Registration_ is _5_. I think we have enough to expand our filter.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/d7f42bae672664100b48e6345792e0a6_MD5.jpg)

Going back to the mint green filter bar. Start by typing `and` to include our next bit in the filter. The next part we are looking for any packets that have the _Ocode_ of _5_ under the flags section. To do this we use the following `nbns.flgs.opcode == 5`. Once we have this typed into your filter field, press enter to filter.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/092ea1110d2e34b72c691e6eca9548be_MD5.jpg)

Looking at the top section, all we see is _Registration Request_ now. Look at the bottom right of the Wireshark window. You are looking for the word _Displayed:_. The numbers to the right of _Displayed_, is the answer. Type the answer in the THM answer field, and then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/f611e787f90c90f6a8c1a5df47cab27e_MD5.jpg)

Answer: 16

**Which host requested the IP address “172.16.13.85”?**

Since the question is asking which host requested, it is safe to assume we could be jumping back to DHCP type filters. With this knowledge, taking a look up at some of the examples given to us by THM. One stands out, and that being the _Option 50: Requested IP Address_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/ecd3fcb45931c12cf4496a73bc429d05_MD5.jpg)

Let’s build the filter. On the mint green filter bar, we want to create the filter similar to the other DHCP filter from before. Start with `dchp.option`, as you type this you will see in the drop down suggestion menu will be `requested_ip_address`. Either finish typing or click on the suggestion to added it onto the filter bar. Now it’s time to add the IP address we are looking for. We can do this with `== 172.16.13.85`. So the final filter should be built on the filter bar. Only thing left to do is using it, so press enter to filter for our query.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/6266b1b5501ff917d3264d98216b3ea9_MD5.jpg)

As we can see there is only one result left. To find the name of the host we have to look in the _Dynamic Host Configuration Protocol_ section. Click the carot to drop down more details. Then it’s time to scroll down till you see _Option: (12) Host Name_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/05e2c4daa4186689920825bc6d4bea9d_MD5.jpg)

Once you find _Option: (12) Host Name_, click the carot to drop-down more details about the _Host Name_. You will see a row with _Host Name_ as the label. The answer can be found to the right of this Label. Once you see it, type the answer into the THM answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/720a4ccb68e572767e3c06d3f29aa50e_MD5.jpg)

Answer: Galaxy-A12

Use the “Desktop/exercise-pcaps/dhcp-netbios-kerberos/kerberos.pcap” file.

Going back to the dhcp-netbios-kerberos folder, right-click on the _kerberos.pcap_ file. From the drop-down menu, click on _Open With Wireshark_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/3ff28011637ed4bdd8b48ae464a55004_MD5.jpg)

**What is the IP address of the user “u5”? (Enter the address in defanged format.)**

After reading through the Kerberos section above, we learn if we want to search for a username we use the filter `kerberos.CNameString contains "keyword"`. So to look the the user we are looking for we would change `keyword` to `u5` . So the filter will look like `kerberos.CNameString contains “u5”`. Once this is typed into the mint green filter field, press enter to filter.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/76e00b59483a831f18060bc0f036317a_MD5.jpg)

As we can see from the results we have a couple of options. We can see the initial request come in for authentication. What I want to do is narrow down the small field to only show the request. To do this we want to add to the filter `and` to show that we want to include the next filter statement. That filter being `kerberos.as_req_element`, which is looking for the request being made to the Kerberos server. So the filter should now look like `kerberos.CNameString contains “u5” and kerberos.as_req_element`. After you type it into the mint green filter press enter to use it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/25b0f333af6c8700c379b2d4c2a4a9b3_MD5.jpg)

As we can see, we now only have 2 results. The question is asking for what the IP addres of said user is. But they want it defanged for the answer. So let’s copy the Source IP address. To do this first click on the _Internet Protocol Version_ carot in the details section. Looking at the Details that have now dropped down you will see _Source_, right click on it. From the drop-down menu, hover you cursor over _Copy_. A new drop-down will appear, on this one you will see _Value_. Click on it to copy the IP Address.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/843cb30938d340e66f6cc2ecc7fe96f2_MD5.jpg)

Time to Defang this IP, in a new browser head over to [cyberchef.org](https://cyberchef.org). Once there you will see on the left side of the screen is a search bar under _Operations_. Type _defang_, into this search bar. You will see _Defang IP Addresses_. Click and drag this into the center _Recipe_ column.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/0f3f39fa0884d9958aa612d87c0a6ff2_MD5.jpg)

On the right side of the screen you will see the _Input_ box. Paste (ctrl+v) the IP Address into this section. Then in the _Output_ section will be the _Defanged IP Address_. Copy (ctrl+c) and Paste (ctrl+v) the newly defanged IP into the THM answer field, then click submit

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/1e913b0736b9b4c6fd0ab34ac8075573_MD5.jpg)

Answer: `10[.]1[.]12[.]2`

**What is the hostname of the available host in the Kerberos packets?**

This one took me a bit to figure out. But as I tell myself re-read and go back. After re-reading, THM gives a great filter above. Look at the section regarding _CNameString_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/cf811c67c5cef7d7efb1157d7db35a74_MD5.jpg)

We don’t need the full filter, instead we only need `kerberos.CNameString contains "$"`. Once we have this typed into the mint green Filter Bar. Press enter to filter for any CNameString that would have the Hostname in it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/0671e7e7974f72c239f2a4cc7aff19aa_MD5.jpg)

You should be left with only one result. Time to get that Hostname, let’s start by following the path down by clicking the carots of _Kerberos > tgs-rep > cname > cname-string: 1 item_. Once you reach the final section, you will see _CNameString:_. The answer can be found to the right of this. Type the answer you find in the THM answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/9886b30491127c452269c15510df9499_MD5.jpg)

Answer: xp1$

# Task 5 Tunneling Traffic: DNS and ICMP

## Tunnelling Traffic: ICMP and DNS

Traffic tunnelling is (also known as **“port forwarding”**) transferring the data/resources in a secure method to network segments and zones. It can be used for “internet to private networks” and “private networks to internet” flow/direction. There is an encapsulation process to hide the data, so the transferred data appear natural for the case, but it contains private data packets and transfers them to the final destination securely.

Tunnelling provides anonymity and traffic security. Therefore it is highly used by enterprise networks. However, as it gives a significant level of data encryption, attackers use tunnelling to bypass security perimeters using the standard and trusted protocols used in everyday traffic like ICMP and DNS. Therefore, for a security analyst, it is crucial to have the ability to spot ICMP and DNS anomalies.

## ICMP Analysis

Internet Control Message Protocol (ICMP) is designed for diagnosing and reporting network communication issues. It is highly used in error reporting and testing. As it is a trusted network layer protocol, sometimes it is used for denial of service (DoS) attacks; also, adversaries use it in data exfiltration and C2 tunnelling activities.

**ICMP analysis in a nutshell:**

Usually, ICMP tunnelling attacks are anomalies appearing/starting after a malware execution or vulnerability exploitation. As the ICMP packets can transfer an additional data payload, adversaries use this section to exfiltrate data and establish a C2 connection. It could be a TCP, HTTP or SSH data. As the ICMP protocols provide a great opportunity to carry extra data, it also has disadvantages. Most enterprise networks block custom packets or require administrator privileges to create custom ICMP packets.

A large volume of ICMP traffic or anomalous packet sizes are indicators of ICMP tunnelling. Still, the adversaries could create custom packets that match the regular ICMP packet size (64 bytes), so it is still cumbersome to detect these tunnelling activities. However, a security analyst should know the normal and the abnormal to spot the possible anomaly and escalate it for further analysis.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/b5c1ea71f2f68d4091ca14f7eed873a5_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/2df836629da59db672df6cd45960916a_MD5.jpg)

## DNS Analysis

Domain Name System (DNS) is designed to translate/convert IP domain addresses to IP addresses. It is also known as a phonebook of the internet. As it is the essential part of web services, it is commonly used and trusted, and therefore often ignored. Due to that, adversaries use it in data exfiltration and C2 activities.

**DNS analysis in a nutshell:**

Similar to ICMP tunnels, DNS attacks are anomalies appearing/starting after a malware execution or vulnerability exploitation. Adversary creates (or already has) a domain address and configures it as a C2 channel. The malware or the commands executed after exploitation sends DNS queries to the C2 server. However, these queries are longer than default DNS queries and crafted for subdomain addresses. Unfortunately, these subdomain addresses are not actual addresses; they are encoded commands as shown below:

**“encoded-commands.maliciousdomain.com”**

When this query is routed to the C2 server, the server sends the actual malicious commands to the host. As the DNS queries are a natural part of the networking activity, these packets have the chance of not being detected by network perimeters. A security analyst should know how to investigate the DNS packet lengths and target addresses to spot these anomalies.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/c608545fa856079d236bfcdfd18b94b4_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/274b1c9bd880ec39ac9bf7c93d3a450c_MD5.jpg)

Detecting suspicious activities in chunked files is easy and a great way to learn how to focus on the details. **Now use the exercise files to put your skills into practice against a single capture file and answer the questions below!**

### Answer the questions below

Use the “Desktop/exercise-pcaps/dns-icmp/icmp-tunnel.pcap” file.

Inside the _exercise-pcaps_ folder, double-click on the _dns-icmp_ folder.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/5298ea34ef46f87295c3ea6e3a5f9110_MD5.jpg)

Inside the dns-icmp folder you will see the _Exercise.pcap_ file. Right-click on it, then choose _Open With Wireshark_ from the drop-down menu.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/24cfdc1ab6a5040499925c947c7e4b7f_MD5.jpg)

**Investigate the anomalous packets. Which protocol is used in ICMP tunneling?**

Reading through the ICMP section, a regular size of a ICMP packet is 64 bytes. So to investigate this issue, we should start by looking for packets that are sized greater than 64 bytes. To do so, THM gave us a great filter to use, `data.len > 64 and icmp`. This will filter for any packets that have a data length of greater than 64 bytes. Once it’s in the mint green filter bar, press enter to use it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/b32f08eca22817d7d00bc5e5cff5deb1_MD5.jpg)

Now it’s time to play investigate. In the Hexadecimal section in the bottom right of Wireshark, we can see what it translates to in ASCII. Make sure you have click on the first packet. Then, using the down arrow, you can cycle down through the packets. As you do, keep watching the ASCII output for any signs of the type of protocol that the attacker used to connect to the system.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/8760ed5ca8e61f8f8e272eba0baa8f40_MD5.jpg)

You will reach a point where the protocol the attacker used will be obvious. Keep in mind how an attacker or even you may easily connect to a server if you have the right credentials. Once you find it, type the answer in the THM answer field, and click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/2c74e38addcccbe485cc580c45498c4e_MD5.jpg)

Answer: ssh

Use the “Desktop/exercise-pcaps/dns-icmp/dns.pcap” file.

Going back to the dns-icmp folder, right-click on the _dns.pcap_ file. From the drop-down menu, click on _Open With Wireshark_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/e801105a40a94bf79b29523ad81df969_MD5.jpg)

**Investigate the anomalous packets. What is the suspicious main domain address that receives anomalous DNS queries? (Enter the address in defanged format.)**

To be able to detect anomalous traffic, we want to look for anything out of the ordinary. A dead give away that data is being exfiltrated is in DNS queries or responses. You may see a domain with a large string of Alpha Numerical Characters followed by a domain name or even the top level domain. THM explains it pretty good above, along with giving a great filter to start with.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/30be398b78b5cfc77de0d7e05217e879_MD5.jpg)

Since we know what the filter we want to start with is, let’s break it down. The first part of the filter is `dns.qry.name.len > 15`, this will filter for any DNS query that has a character length of greater than 15. Then we want to use the `and` operator to make the filter match both filter queries. Lastly, using the `!mdns` to remove any Local Link device queries from the results. Once you have the filter typed out in the mint green filter bar, press enter to use it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/3770f72694452be89c54a434c3802592_MD5.jpg)

WOW we still have 91.5%. Lets take a quick peak at the info section to see if we can find any suspicious activity. We can see the first MX record instance looks interesting, as it looks like a long encoded string. Looks like the attacker is trying to exfil the data via quering the MX record. Click on the Packet so we can investigate it further.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/5937ba430141a008ccbd53b60002a3ac_MD5.jpg)

Taking a look in the Details section on the bottom right of Wireshark. We can see the Full Encoded string for this packet, and at the end you see what looks like a domain name. The domain looks quite suspicious. Let’s submit it using the format *********[.]***. After you have typed the answer into the THM answer field, click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/547c8118281cbed1b7289cd4af810b3b_MD5.jpg)

Answer: `dataexfil[.]com`

# Task 6 Cleartext Protocol Analysis: FTP

## Cleartext Protocol Analysis

Investigating cleartext protocol traces sounds easy, but when the time comes to investigate a big network trace for incident analysis and response, the game changes. Proper analysis is more than following the stream and reading the cleartext data. For a security analyst, it is important to create statistics and key results from the investigation process. As mentioned earlier at the beginning of the Wireshark room series, the analyst should have the required network knowledge and tool skills to accomplish this. Let’s simulate a cleartext protocol investigation with Wireshark!

## FTP Analysis

File Transfer Protocol (FTP) is designed to transfer files with ease, so it focuses on simplicity rather than security. As a result of this, using this protocol in unsecured environments could create security issues like:

- MITM attacks
- Credential stealing and unauthorised access
- Phishing
- Malware planting
- Data exfiltration

**FTP analysis in a nutshell:**

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/d146bbef90f983290bba2a2c1a9bd550_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/541382dbe6b60c8f889d842a86e2c422_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/08a4de6ade3622c6967a903d764c485b_MD5.jpg)

Detecting suspicious activities in chunked files is easy and a great way to learn how to focus on the details. **Now use the exercise files to put your skills into practice against a single capture file and answer the questions below!**

### Answer the questions below

Before you start!

Here is a resource I found that helped to identify the different commands used on an FTP server. Use it to better understand what is going on and what the attacker may be doing

[https://en.wikipedia.org/wiki/List_of_FTP_commands](https://en.wikipedia.org/wiki/List_of_FTP_commands)

Use the “Desktop/exercise-pcaps/ftp/ftp.pcap” file.

Going back to the folder where the pcapng file is located. Click on the _Back_ button in the upper left of the dns-icmp folder’s window.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/eca8b4bc29b34794c4bc389ad81c337e_MD5.jpg)

Now being in the exercise-pcaps folder, double-click on _ftp_ folder to open it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/e8d39e8f12eb101ba8e22587289340a7_MD5.jpg)

Now being inside the ftp folder, right-click on the _ftp.pcap_ file. From the drop-down menu, click on _Open With Wireshark_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/f0cbc450e81a1cdbf309696679151c31_MD5.jpg)

**How many incorrect login attempts are there?**

Taking a look up in the text THM give us some good filters to attempt. We want to look at the `ftp.response.code`. Since the question is looking for incorrect login attempts, 430 and 530 look like a great place to start.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/7309a143fcb9d5f591f5f03e1630cc40_MD5.jpg)

Heading into Wireshark, lets create of filter in the mint green filter bar. As stated we want to start with `ftp.response.code` then we want to add `== 430` to indicate that we are looking for response code of 430. Next we want the `or` operator so it can either be response code 430 or 530. Then repeat the process, but this time with `ftp.response.code == 530`. Now that you have that all typed into the filter bar. Hit enter to filter for it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/74308ba82014637244e51ae00d5c4293_MD5.jpg)

Once the filtering is done you can find the answer in the bottom right of Wireshark. To the right of the word _Displayed_. Once you find it, type the answer into the THM answer field and click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/1c638ef6b551f3f43421a52c95053f4b_MD5.jpg)

Answer: 737

**What is the size of the file accessed by the “ftp” account?**

The question gives us some information, the account we need to look for first is the `ftp` account. To find the acount we want to start out with the filter that THM shared above. That filter being `ftp.request.arg ==`. We just need to add `"ftp"` to the end. What this filter does is we are looking for when the user uses the username _ftp_. So we can start investigating. Now once you have the filter typed in, press enter to use it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/7777885c0f39e558b5e6926e2447d05b_MD5.jpg)

We are left with two results. One using _ftp_ for the USER request and the other for the PASS. Since we want to find the size of the file the account accessed, we can find it by following the stream. To do this you will right-click on the first Packet. From the drop down, move your mouse to _Follow_. From the new drop down click on _TCP Stream_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/5efe2667d1d6017362d8e36bf512ebf7_MD5.jpg)

The _TCP Stream_ window will pop up. Reading down through we can see that the user ended up checking SIZE of the file _resume.doc._ Since we can see the size of the file, it sounds like it fits the description of the question. Let’s type the answer over in the THM answer field, and click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/8544b96618b4ba73faf71edf75b5c208_MD5.jpg)

Answer: 39424

**The adversary uploaded a document to the FTP server. What is the filename?**

This question feeds directly off the previous question. After checking the size. The attacker proceeds to use RETR which is used to download a copy of a file onto the server. We can see to the right of this command what the name of the file is. Once you have found it, type the answer into the THM answer field and click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/2157f2d92fd1171a560fcdc7351381a4_MD5.jpg)

Answer: resume.doc

**The adversary tried to assign special flags to change the executing permissions of the uploaded file. What is the command used by the adversary?**

We can see what command the Attacker used by scrolling down and following the entire stream.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/aa8d9a3e1e58c619b086b61d9322464b_MD5.jpg)

Once you reach the bottom, you can see where the attacker was trying to run a linux command to change the files permissions. Once you see it, type the answer in the THM answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/7ebc5f4dd2124c4db9354f94d9facd28_MD5.jpg)

Answer: chmod 777

# Task 7 Cleartext Protocol Analysis: HTTP

## HTTP Analysis

Hypertext Transfer Protocol (HTTP) is a cleartext-based, request-response and client-server protocol. It is the standard type of network activity to request/serve web pages, and by default, it is not blocked by any network perimeter. As a result of being unencrypted and the backbone of web traffic, HTTP is one of the must-to-know protocols in traffic analysis. Following attacks could be detected with the help of HTTP analysis:

- Phishing pages
- Web attacks
- Data exfiltration
- Command and control traffic (C2)

**HTTP analysis in a nutshell:**

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/374c61924b04e91673c88a7ff54beb7d_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/de4adb26a63e26f35c3e6658ac64d876_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/9e096581346b03a3802528d34d6b49db_MD5.jpg)

## User Agent Analysis

As the adversaries use sophisticated technics to accomplish attacks, they try to leave traces similar to natural traffic through the known and trusted protocols. For a security analyst, it is important to spot the anomaly signs on the bits and pieces of the packets. The “user-agent” field is one of the great resources for spotting anomalies in HTTP traffic. In some cases, adversaries successfully modify the user-agent data, which could look super natural. A security analyst cannot rely only on the user-agent field to spot an anomaly. Never whitelist a user agent, even if it looks natural. User agent-based anomaly/threat detection/hunting is an additional data source to check and is useful when there is an obvious anomaly. If you are unsure about a value, you can conduct a web search to validate your findings with the default and normal user-agent info ([**example site**](https://developers.whatismybrowser.com/useragents/explore/)).

**User Agent analysis in a nutshell:**

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/2b7b521e3665940f7885d5e4abfe7794_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/bf34de678acac86124657106a0b76b77_MD5.jpg)

## Log4j Analysis

A proper investigation starts with prior research on threats and anomalies going to be hunted. Let’s review the knowns on the “Log4j” attack before launching Wireshark.

**Log4j vulnerability analysis in a nutshell:**

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/988c1761835fa3b9ca802ebaa35915ef_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/04209ed41a4f20295c2207d0925b207f_MD5.jpg)

Detecting suspicious activities in chunked files is easy and a great way to learn how to focus on the details. **Now use the exercise files to put your skills into practice against a single capture file and answer the questions below!**

### Answer the questions below

Use the “Desktop/exercise-pcaps/http/user-agent.cap” file.

Inside the _exercise-pcaps_ folder, double-click on the _http_ folder.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/e74188a71ad44dbd3af1c8ab1f44bf52_MD5.jpg)

Inside the http folder you will see the _user-agent.cap_ file. Right-click on it, then choose _Open With Wireshark_ from the drop-down menu.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/83b41235be08d7974cf77cdc64f05248_MD5.jpg)

**Investigate the user agents. What is the number of anomalous “user-agent” types?**

To make this task a bit easier, we need to do a little prep. Inside of Wireshark, right-click on the _Column names_ that are underneath the filter bar. Once you have right-clicked on this row, a drop-down menu will appear. Click on _Column Preferences…._

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/d455152639e6065035e81fa98768676b_MD5.jpg)

The _Wireshark Preferences_ window will pop up onto your screen. From here, there is a `+` icon under the different column’s that can be displayed. Click the `+` icon.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/1994ff74b8bff28b696f216b880c852b_MD5.jpg)

A new row will appear in the chart. You will need to interact with both the _Title_ and _Fields_ cells of the new row. To do this, you will only need to double-click on the cell. So for the _Title_ cell, you can name it _User Agent_. Then for the _Fields_ cell, you will put in the filter needed to show the User Agent. That filter is `http.user_agent`. Once you have done this, the _Type_ cell will change from _Number_ to _Custom_. This is normal and good.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/177ed3d78c81abd57d55b883acec6500_MD5.jpg)

Click on the _OK_ button, in the bottom right of the window.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/f40845d2c14474d20b787fa3f07cf946_MD5.jpg)

The _Wireshark Preferences_ window will disappear. You should see the main Wireshark window. But, looking to the right, you will see the new Column we just added to the _Packet List_ section. Click on the new _User Agent_ column to organize the _Packet List_ by _User Agent_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/7079afe67d152afc9c4582760e5d29e5_MD5.jpg)

Looking through the different User Agents, I was still coming to a wall. So I took a look at the Hint, it shares about looking into the _Windows NT 6.4_. So I did a little Googling, and found this [Article](https://b1thunt3r.se/2015/02/windows-nt-10-what-happened-to-nt-6-4) , that explains that there is no such Windows User Agent Version. It goes from Windows NT 6.3 to Windows NT 10. So we have found our Anomolous Packets. Time to count them. Once you have counted the number of Packets that contain this User Agent. Type this number into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/ce06af75847d7506601339d11b383173_MD5.jpg)

Answer: 6

**What is the packet number with a subtle spelling difference in the user agent field?**

Hover your cursor over the divide bar to the right of the_User Agent_ column we created. Once the cursor changes to arrows pointing both ways, _Click and Hold_ then slide the column to the left to expand it. If needed, repeat this same step on the right side to expand the column some more.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/d2a0bad03a604a85f661c2ff529b4c49_MD5.jpg)

Now that the column is expanded, it’s time to start parsing through the information.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/8b811abf579aafc8d3d3592ee234a0b0_MD5.jpg)

Once you find the spelling error, look at the first column on the left. This is the _Packet Number_. Take this number and type it into the TryHackMe answer field. Then click _Submit_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/f3e0c51afb8890d75e9cd9b080d1bdda_MD5.jpg)

Answer: 52

Use the “Desktop/exercise-pcaps/http/http.pcapng” file.

Going back to the http folder, right-click on the _http.pcapng_ file. From the drop-down menu, click on _Open With Wireshark_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/e8bfaf8c1a6c6f96af015ecaacf7e2d1_MD5.jpg)

**Locate the “Log4j” attack starting phase. What is the packet number?**

Looking over the section above in regards to Log4j, it gives us some areas to start with. Since we are looking for the starting phase packet number, the table tells us that the attack starts with a _POST request_. Along with some known cleartext patterns. Let’s build a filter, head back to Wireshark.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/b78e744a35db2a79ad910772f405c066_MD5.jpg)

In the mint green filter bar let’s create our filter. We will start by encapsilating the first pramater in `()`. Our first parameter is filtering only _POST request_, to do this use `(http.request.method == “POST”)` . We then want to add `and` to let Wireshark know that the filter needs to match both parameters to get a result. Next we again are using `()` to encapsilate the parameters and function. The parameter this time is looking for the clear text patterns in the IP field. Here is how this should look `((ip contains “jndi”) or ( ip contains “Exploit”))`. We use the double `()`, with the `or` function to say that this parameter can match either one of these filters. If it does along with it being a _POST Request_, then a result will be given. The full filter will look like this: `(http.request.method == “POST”) and ((ip contains “jndi”) or ( ip contains “Exploit”))`. Once you have this typed into the filter bar, press enter to run.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/6bb55eb553cf81fa6f176a03c9c46201_MD5.jpg)

You will be left with one result. Look at the Packet number in the first column of the Packet List Section. Type this number into the TryHackMe answer field, then click _Submit_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/d031ffae2c75100751242cd2199a2e5d_MD5.jpg)

Answer: 444

**Locate the “Log4j” attack starting phase and decode the base64 command. What is the IP address contacted by the adversary? (Enter the address in defanged format and exclude “{}”.)**

Going back to Wireshark, we can see in the hex output of the packet the _Base64_ string. We need to copy this string so we can decode it. The easiest way is to click the _drop-down carot_ for _HyperText Transfer Protocol_ found in the Packet Detail Section.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/b1377b17a5a5d5cf900e78eb8ba41a98_MD5.jpg)

Once we have done that, we can see the _User-Agent_ Field. The _Base64_ value can be found in the field. Start by _right-clicking_ the _User-Agent_ field. In the drop-down menu, hover your cursor over _Copy._ A new drop down will appear. Move your cursor over to _Value_, then click on it. The User-Agent is now copied!

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/da65cd24fdd97ce4a925e67888f61acc_MD5.jpg)

Now head over to [CyberChef](https://gchq.github.io/CyberChef/), time to work some magic. In the _Input_ field, paste the _User-Agent String._ Under _Operations_ drag and drop _From Base64_ into the _Recipe_ field.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/0817aa7928b2f4baa25ab1032161875e_MD5.jpg)

As we can see we have some extra info that we don’t need. Remove all the characters starting at the `$` and ending at `Base64/`. Then finally the `}`, at the end of the _User-Agent String_. You should be left with the _Base64 String_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/7aaea495910f162046654023488e6a70_MD5.jpg)

You should now be able to see the IP address in the _Output_ field, with the rest of the command from the _Base64 String_. But we need it to be defanged for the answer. To do this we need to search _defang IP_ in the search field under _Operations_. After typing _defang IP_, you should see it at the top of the list/under the search field. Drag and drop it over into the _Recipe_ field.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/654ad6a393e1c8679273dfd65d46efee_MD5.jpg)

You will now see the defanged IP in the _Output_ field. Higlight the defanged IP, then copy (ctrl+c) and paste(ctrl+v) into the TryHackMe answer field. Then click _Submit_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/3ca4cb01e13b8668e90128914a504f2c_MD5.jpg)

Answer: `62[.]210[.]130[.]250`

# Task 8 Encrypted Protocol Analysis: Decrypting HTTPS

## Decrypting HTTPS Traffic

When investigating web traffic, analysts often run across encrypted traffic. This is caused by using the Hypertext Transfer Protocol Secure (HTTPS) protocol for enhanced security against spoofing, sniffing and intercepting attacks. HTTPS uses TLS protocol to encrypt communications, so it is impossible to decrypt the traffic and view the transferred data without having the encryption/decryption key pairs. As this protocol provides a good level of security for transmitting sensitive data, attackers and malicious websites also use HTTPS. Therefore, a security analyst should know how to use key files to decrypt encrypted traffic and investigate the traffic activity.

The packets will appear in different colours as the HTTP traffic is encrypted. Also, protocol and info details (actual URL address and data returned from the server) will not be fully visible. The first image below shows the HTTP packets encrypted with the TLS protocol. The second and third images demonstrate filtering HTTP packets without using a key log file.

**Additional information for HTTPS :**

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/8f54ed8022afae41cba36ca98e8bbd97_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/5b85f329446e70373c618d50b6e3ab76_MD5.jpg)

Similar to the TCP three-way handshake process, the TLS protocol has its handshake process. The first two steps contain “Client Hello” and “Server Hello” messages. The given filters show the initial hello packets in a capture file. These filters are helpful to spot which IP addresses are involved in the TLS handshake.

- Client Hello: `(http.request or tls.handshake.type == 1) and !(ssdp)`
- Server Hello:`(http.request or tls.handshake.type == 2) and !(ssdp)`

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/361e0affe7f0325085c8983d1470fca8_MD5.jpg)

An encryption key log file is a text file that contains unique key pairs to decrypt the encrypted traffic session. These key pairs are automatically created (per session) when a connection is established with an SSL/TLS-enabled webpage. As these processes are all accomplished in the browser, you need to configure your system and use a suitable browser (Chrome and Firefox support this) to save these values as a key log file. To do this, you will need to set up an environment variable and create the SSLKEYLOGFILE, and the browser will dump the keys to this file as you browse the web. SSL/TLS key pairs are created per session at the connection time, so it is important to dump the keys during the traffic capture. Otherwise, it is not possible to create/generate a suitable key log file to decrypt captured traffic. You can use the “right-click” menu or **“Edit → Preferences → Protocols → TLS”** menu to add/remove key log files.

**Adding key log files with the “right-click” menu:**

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/e10641bf6322f73840618fd5c62a0282_MD5.jpg)

**Adding key log files with the “Edit → Preferences → Protocols → TLS” menu:**

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/cec7eff9832418d169ce5ed65c91fb5c_MD5.jpg)

**Viewing the traffic with/without the key log files:**

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/b023cf534fd592811014facafa569ca2_MD5.jpg)

The above image shows that the traffic details are visible after using the key log file. Note that the packet details and bytes pane provides the data in different formats for investigation. Decompressed header info and HTTP2 packet details are available after decrypting the traffic. Depending on the packet details, you can also have the following data formats:

- Frame
- Decrypted TLS
- Decompressed Header
- Reassembled TCP
- Reassembled SSL

Detecting suspicious activities in chunked files is easy and a great way to learn how to focus on the details. **Now use the exercise files to put your skills into practice against a single capture file and answer the questions below!**

### Answer the questions below

Use the “Desktop/exercise-pcaps/https/Exercise.pcap” file.

Going back to the folder where the pcapng file is located. Click on the _Back_ button in the upper left of the dns-icmp folder’s window.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/631d57388f39fe1e36e879e7411643d4_MD5.jpg)

Now being in the exercise-pcaps folder, double-click on _https_ folder to open it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/2f75948d38ee188458a08371a8824a95_MD5.jpg)

Now being inside the ftp folder, right-click on the _Exercise.pcapng_ file. From the drop-down menu, click on _Open With Wireshark_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/b53233676e93c37c5b178f4a21526c92_MD5.jpg)

**What is the frame number of the “Client Hello” message sent to “accounts.google.com”?**

Reading through the materials above. TryHackMe gave us a great start with a filter that will get us only the _Client Hello_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/fdaf353686458978030fa0921891a3ad_MD5.jpg)

Copy and Paste or type the filter for _Client Hello_ into the mint green filter bar. Once entered in the filter bar press enter to run the filter.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/3059be0b54cdbd478eaf18e828b27fd3_MD5.jpg)

Now we are only left with the _Client Hello_ packets. We need to find the one that was sent to _accounts.google.com_. If we look at the hex dump of the packet. We can see the word _google_ in it. Click on _google_ in the hexdump to expand upon it in the _Packet Detail_ section.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/8a8882099c6f67393cde2d35654e9fd2_MD5.jpg)

In the _Packet Detail_ section you will see _Server Name: clientservices.googleapis.com_ highlighted. This isn’t the server we are looking for, but it will help us to locate the _accounts.google.com_. We first need to right-click on _Server Name: clientservices.googleapis.com_. This will bring up a drop-down menu. Move your cursor over the _Apply as Filter_. A new drop-down will appear, move your cursor over to _Selected_ and click on it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/f99ac04506e894aa00081506e0c15fc3_MD5.jpg)

Looking at the mint green filter bar, we can see the new filter we ran. But as I said before, _clientservices.googleapis.com_ is not the _Name Server_ we are looking for. So let’s change that! Remove _clientservices.googleapis.com_ and replace it with _accounts.google.com_. Once you have it replaced, press enter to run the new/updated filter.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/d7bbc499c6222f383415aea91cbb3f9a_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/ceea6dd1d2fcd67cb9f2c70bd07cf394_MD5.jpg)

You will be left with one packet left. Look at the _Packet Number_ from the first column. Once you see it type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/eb957740718fc46d2ab9190ae5ccbd73_MD5.jpg)

Answer: 16

**Decrypt the traffic with the “KeysLogFile.txt” file. What is the number of HTTP2 packets?**

First let’s decrypt the traffic. To do so click _Edit_ in the top left of Wireshark. From the drop-down menu, move your cursor to the bottom where it say _Preferences_ and click on it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/ce93afef1f87bd007cdd94ff0cd3071f_MD5.jpg)

The Wireshark Preference window will pop-up in the middle of the screen. Find _Protocols_, click the down carot that is on the left.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/28c1253b6382f8f86f536aef9519de43_MD5.jpg)

Now either scroll down till you see _TLS_ or type _TLS_ quickly to be taken to it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/323a301bda5a2e9ff5c963fa016fad6c_MD5.jpg)

Look for _(Pre)-Master-Secret log filename_, you will see a field under with a _Browse…_ button to the right. Click on this _Browse…_ button.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/4c93b94512d6bfdaa677741512000f83_MD5.jpg)

A File Explorer Window will pop-up. If you remember, when we opened the PCAP file, there was another file in the folder. This file is _KeysLogFile.txt_, and the file we are looking for. So we need to navigate to this file. To do so follow the path of _Desktop > exercist-pcaps > https_. Once in the folderwe see the _KeysLogFile.txt._

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/5f1cd912742f13d4a61fc0e5ec445579_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/7b97a7de20ec46ff1aa419cae1d71515_MD5.jpg)

To select the file, either _double-click_ on _KeysLogFile.txt_. Or click on _KeysLogFile.txt_ then click on the _Open_ button in the bottom right of the File Explorer Window.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/f72c193bb2d7c49d718f7bf60fc11184_MD5.jpg)

You will be brought back to the Wireshark Preferences window. We can now see that the file along with the absolute path is in the _(Pre)-Master-Secret Log Filename_ field. Next you can click the _Ok_ button in the bottom right of the Wireshark Prefernces window.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/bf42e050d75f7555f1ca2042ff99ed00_MD5.jpg)

Since the question is looking for the number of packets that are _http2 protocol_. Then we need to filter for _http2_, which is quiet simple as the filter is _http2_. Type this into the mint green filter bar, then press enter to run.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/90d2a50d233a66356ff64b648d4c9145_MD5.jpg)

Looking to the bottom right of the Wireshark window you will see the word _Displayed_. The number to the right of this is the number and _http2_ packets and thus the answer to this question. Once you found it type the answer into the TryHackMe answer field, and click the _Submit_ button.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/9d788e544e1014eb919cf5db44ec8979_MD5.jpg)

Answer: 115

**Go to Frame 322. What is the authority header of the HTTP2 packet? (Enter the address in defanged format.)**

Keeping the filter from the previous question, let’s elaborate on it. Since we want to see _Frame 322_, we can add to our filter the following. Start with _and_ as we want the filter to match both _http2_ along with our frame number. Then we will add _frame.number == 322_, which is looking for _Frame 322_. Once we have our filter build, press enter to run it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/44914c36797a54514b05c25a5ca974fe_MD5.jpg)

Looking in the _Packet Details_ section, look for _HyperText Transfer Protocol_. Once you find it click the _carot_ to the left of it to drop-down more information. You will see a new line, and thats it. But we can drop-down some more. So click the _carot_ to the left of _Stream:_ to discover more information. Now we can scroll down till we see the _Header: :authority:_ field.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/f468fc37bc30e838c833f60fd9048598_MD5.jpg)

Once we see the _Header: :authority:_ field, we can see the domain name. But the question is asking for the domain to be defanged. So we need to grab the domain. To do this _right-click_ on _Header: :authority:_ field. A drop-down menu will appear, hover your cursor over _Copy_. A new drop-down will appear. Move your cursor over to _Description_, then click on it. You now have what you need, time to head over to [CyberChef](https://gchq.github.io/CyberChef/).

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/7cf9f2dfb0f036c5be3724bfb888a0c8_MD5.jpg)

Once at CyberChef, type _defang_ in the input field under _Operations_. The top result will be _Defang URL_. Drag and drop _Defang URL_ into the _Recipe_ area.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/47ec84fddabadef0e347e08da88e9488_MD5.jpg)

Now paste in the _Description/Domain_ we copied from WireShark. CyberChef should automatically defang the URL which you will see in the _Output_ field. Now Copy and Paste the defanged URL into the TryHackMe answer field, then click the _Submit_ button.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/ea833834c0e5fb085cfd8b9284c9fb00_MD5.jpg)

Answer: `safebrowsing[.]googleapis[.]com`

**Investigate the decrypted packets and find the flag! What is the flag?**

Time to use our investigation skills we have learned so far. Since we are looking at _http_ traffic, the first place I like to look is _Export Objects_. _Export Objects_ is where you can export/save files that were captured in the PCAP file. To do this first click on _File_ in the top right of the Wireshark window. On the drop-down menu, move your cursor to hover over _Export Objects_. A new drop-down will appear. On this drop-down you will see _HTTP…_, click on _HTTP…_

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/63a767ee334454c66757335fc4111769_MD5.jpg)

We can see two files that were captured from the HTTP Protocol. The first one has an interesting _Filename_, let’s check it out. To do this click on the first row with the interesting _Filename_. Then click the _Save_ button in the bottom right of the Wireshark Export HTTP object list.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/798d9bea3a1b07cb14905847acf0ae65_MD5.jpg)

The Wireshark Save Object As… window will popup. On the left side of this window we can see _Desktop_, click on _Desktop_. Now click the _Save_ button in the bottom right of the window.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/f76c969254aa87ba65b0702e014cbf45_MD5.jpg)

The file is now saved to the Desktop, so let’s head there. First _X_ out of the Wireshark Export HTTP object list window. Then _Minimize_ the Wireshark window.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/849b16392a34695d42e1a95207ceb207_MD5.jpg)

We can now see the new file on the desktop. Let’s open it by double-clicking on the new file on the desktop.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/c4a88e07883f906dfe53ae7dfecb1267_MD5.jpg)

Once the file opens, we are greeted with some sweet ASCII art and what looks like the flag!! Highlight and copy the flag, then paste the answer in the TryHackMe answer field, and click the _Submit_ button.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/8fa7d24f6598d9842467b0850ef9bf4c_MD5.jpg)

Answer: `FLAG{THM-PACKETMASTER}`

# Task 9 Bonus: Hunt Cleartext Credentials!

## Bonus: Hunt Cleartext Credentials!

Up to here, we discussed how to inspect the packets for specific conditions and spot anomalies. As mentioned in the first room, Wireshark is not an IDS, but it provides suggestions for some cases under the expert info. However, sometimes anomalies replicate the legitimate traffic, so the detection becomes harder. For example, in a cleartext credential hunting case, it is not easy to spot the multiple credential inputs and decide if there is a brute-force attack or if it is a standard user who mistyped their credentials.

As everything is presented at the packet level, it is hard to spot the multiple username/password entries at first glance. The detection time will decrease when an analyst can view the credential entries as a list. Wireshark has such a feature to help analysts who want to hunt cleartext credential entries.

Some Wireshark dissectors (FTP, HTTP, IMAP, pop and SMTP) are programmed to extract cleartext passwords from the capture file. You can view detected credentials using the **“Tools → Credentials”** menu. This feature works only after specific versions of Wireshark (v3.1 and later). Since the feature works only with particular protocols, it is suggested to have manual checks and not entirely rely on this feature to decide if there is a cleartext credential in the traffic.

Once you use the feature, it will open a new window and provide detected credentials. It will show the packet number, protocol, username and additional information. This window is clickable; clicking on the packet number will select the packet containing the password, and clicking on the username will select the packet containing the username info. The additional part prompts the packet number that contains the username.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/b18dc70946d442737634d1246129c0a8_MD5.jpg)

### Answer the questions below

Use the “Desktop/exercise-pcaps/bonus/Bonus-exercise.pcap” file.

Inside the _exercise-pcaps_ folder, double-click on the _bonus_ folder.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/d584c3a5d7539de0f816a15c70e53701_MD5.jpg)

Inside the bonus folder you will see the _Bonus-exercise.pcap_ file. Right-click on it, then choose _Open With Wireshark_ from the drop-down menu.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/c8001ec70cad1d527df3dc2b206c42f0_MD5.jpg)

**What is the packet number of the credentials using “HTTP Basic Auth”?**

Click on the _Tools_ drop-down menu at the top of the Wireshark window. From the drop-down, click on _Credentials_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/244e1893054b4ae3065b014c1f7374c8_MD5.jpg)

The Wireshark Credentials window will pop up. Looking through the Protocols, we can see one _HTTP_ Packet. Looking at the _Packet Number_ to the left we have our answer. Type the _Packet Number_ into the TryHackMe answer field, then click _Submit_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/d42cdc4f635865d42dff35d9af5e67c4_MD5.jpg)

Answer: 237

**What is the packet number where “empty password” was submitted?**

Time to do some investigating! In the Wireshark Credentials Window, click on the _Packet Number_. You will see that the _Packet Details_ change to the _Packet Number_ you clicked on. Looking at the _Request arg:_ will show you the password that was used. Now click down through the _Packet Numbers_ till you don’t see _Request arg:_, this means that no password was submitted. Once you find this Packet, you have found the _Packet Number_ that is the answer. Type this answer into the TryHackMe answer field, then click the _Submit_ button.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/684159e69e5278805bca93fcc4f858d0_MD5.jpg)

Answer: 170

# Task 10 Bonus: Actionable Results!

## Bonus: Actionable Results!

You have investigated the traffic, detected anomalies and created notes for further investigation. What is next? Not every case investigation is carried out by a crowd team. As a security analyst, there will be some cases you need to spot the anomaly, identify the source and take action. Wireshark is not all about packet details; it can help you to create firewall rules ready to implement with a couple of clicks. You can create firewall rules by using the **“Tools → Firewall ACL Rules”** menu. Once you use this feature, it will open a new window and provide a combination of rules (IP, port and MAC address-based) for different purposes. Note that these rules are generated for implementation on an outside firewall interface.

Currently, Wireshark can create rules for:

- Netfilter (iptables)
- Cisco IOS (standard/extended)
- IP Filter (ipfilter)
- IPFirewall (ipfw)
- Packet filter (pf)
- Windows Firewall (netsh new/old format)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/618b6331498db884012520c5a13c8026_MD5.jpg)

### Answer the questions below

Use the “Desktop/exercise-pcaps/bonus/Bonus-exercise.pcap” file.

You will use the same _Bonus-exercise.pcap_ file you opened in the previous Task.

**Select packet number 99. Create a rule for “IPFirewall (ipfw)”. What is the rule for “denying source IPv4 address”?**

Let’s start by filtering for only Packet 99. Using the _frame.number_ filter we used before, adding _== 99_. So that the filter is _frame.number == 99_, then press enter to run the filter.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/f7415ac7144dbf8ad8539462d9f042b6_MD5.jpg)

Click on the _Tools_ drop-down menu at the top of the Wireshark window. From the drop-down, click on _Firewall ACL Rules_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/28232ba820e075a60c0285a90ff49cf9_MD5.jpg)

The Wireshark Firewall ACL Rules window will pop up. At the bottom of the window we can see _Create Rules For_ with a drop-down menu to the right. Click the down carot to expand this menu.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/07a28cc4e78a34b3fe21f68d7f2ebc41_MD5.jpg)

The drop-down will expand. Look for _IPFirewall (ipfw)_, once you find it, click on it. This will select it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/01c81b0f3c969291cfa841d1f61fc46c_MD5.jpg)

The _IPFirewall (ipfw)_ rules will be loaded in the window now. As we can see, the rule for _denying IPv4 source address_ is at the top of the list. Highlight the rule and copy (ctrl + c), then paste it in the TryHackMe answer field. Then click _Submit_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/8ab861c84e54e5864b75be62f9e2fef4_MD5.jpg)

Answer: add deny ip from 10.121.70.151 to any in

**Select packet number 231. Create “IPFirewall” rules. What is the rule for “allowing destination MAC address”?**

Close out the Wireshark Firewall ACL Rules window using the _Close_ button in the bottom right of the window.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/a949e97ad5af52e38ffea12254323008_MD5.jpg)

Now change the _Frame Number_ from _99_ to _231_. So that the filter will look like _frame.number == 231_, then press enter to run it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/d466a9b2adb1f274091a8d0d9b9a8457_MD5.jpg)

Click on the _Tools_ drop-down menu at the top of the Wireshark window. From the drop-down, click on _Firewall ACL Rules_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/28232ba820e075a60c0285a90ff49cf9_MD5.jpg)

The Wireshark Firewall ACL Rules window will pop up. At the bottom of the window we can see _Create Rules For_ with a drop-down menu to the right. Click the down carot to expand this menu.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/07a28cc4e78a34b3fe21f68d7f2ebc41_MD5.jpg)

The drop-down will expand. Look for _IPFirewall (ipfw)_, once you find it, click on it. This will select it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/01c81b0f3c969291cfa841d1f61fc46c_MD5.jpg)

One final thing we need to do is _uncheck_ the _deny_ box in the bottom right of the window. This will change the rules to be _allow_ instead of _deny_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/b3257009db822a3bad1ee6bfe3027f51_MD5.jpg)

Now scroll down till you see _MAC destination address._ Once you spot it, highlight and copy (ctrl + c) the rule. Then paste (ctrl + v) the answer into the TryHackMe answer field, then click _Submit_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/11%20Wireshark%20-%20Traffic%20Analysis/43017c31eeadd65fa69363573bdc00ca_MD5.jpg)

Answer: add allow MAC 00:d0:59:aa:af:80 any in

# Task 11 Conclusion

**Congratulations!** You just finished the “Wireshark: The Traffic Analysis” room.

In this room, we covered how to use the Wireshark to detect anomalies and investigate events of interest at the packet level. Now, we invite you to complete the Wireshark challenge room: [**Carnage**](https://tryhackme.com/room/c2carnage), **Warzone 1** and **Warzone 2**.

Wireshark is a good tool for starting a network security investigation. However, it is not enough to stop the threats. A security analyst should have IDS/IPS knowledge and extended tool skills to detect and prevent anomalies and threats. As the attacks are getting more sophisticated consistently, the use of multiple tools and detection strategies becomes a requirement. The following rooms will help you step forward in network traffic analysis and anomaly/threat detection.

- [**NetworkMiner**](https://tryhackme.com/room/networkminer)
- [**Snort**](https://tryhackme.com/room/snort)
- [**Snort Challenge — The Basics**](https://tryhackme.com/room/snortchallenges1)
- [**Snort Challenge — Live Attacks**](https://tryhackme.com/room/snortchallenges2)
- [**Zeek**](https://tryhackme.com/room/zeekbro)
- [**Zeek Exercises**](https://tryhackme.com/room/zeekbroexercises)
- [**Brim**](https://tryhackme.com/room/brim)

