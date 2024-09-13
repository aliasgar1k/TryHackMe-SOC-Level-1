https://www.youtube.com/watch?v=vVNH-e2BFJg
https://www.youtube.com/watch?v=U9oG9IlvywA

https://medium.com/@haircutfish/tryhackme-networkminer-task-1-through-task-4-527779fb49b7
https://medium.com/@haircutfish/tryhackme-networkminer-task-5-tool-overview-2-task-6-version-differences-2de1f0cc4270
https://medium.com/@haircutfish/tryhackme-networkminer-task-7-exercises-task-8-conclusion-cd44742d65e1

Learn how to use NetworkMiner to analyse recorded traffic files and practice network forensics activities.

# Task 1 Room Introduction

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/a388a954f241e5591cbc7eedfebe215f_MD5.jpg)

NetworkMiner is an open-source traffic sniffer, pcap handler and protocol analyser. Developed and still maintained by Netresec.

[The official description](https://www.netresec.com/?page=NetworkMiner);

_“NetworkMiner is an open source Network Forensic Analysis Tool (NFAT) for Windows (but also works in Linux / Mac OS X / FreeBSD). NetworkMiner can be used as a passive network sniffer/packet capturing tool to detect operating systems, sessions, hostnames, open ports etc. without putting any traffic on the network. NetworkMiner can also parse PCAP files for off-line analysis and to regenerate/reassemble transmitted files and certificates from PCAP files._

_NetworkMiner makes it easy to perform advanced Network Traffic Analysis (NTA) by providing extracted artefacts in an intuitive user interface. The way data is presented not only makes the analysis simpler, it also saves valuable time for the analyst or forensic investigator._

_NetworkMiner has, since the first release in 2007, become a popular tool among incident response teams as well as law enforcement. NetworkMiner is today used by companies and organizations all over the world._”

For this room, you will be expected to have basic Linux familiarity and Network fundamentals (ports, protocols and traffic data). We suggest completing the “[**Network Fundamentals**](https://tryhackme.com/module/network-fundamentals)” path before starting working in this room.

The room aims to provide a general network forensics overview and work with NetworkMiner to investigate captured traffic.

**Note:** VMs attached to this challenge. You don’t need SSH or RDP; the room provides a **“Split View”** feature.

**Note:** There are two different NetworkMiner versions are available in the attached VM. Use the required version according to the tasks.

**Note:** Exercise files are located in the folder on the desktop.

Open the tool folder and double click on the **.exe** file.

# Task 2 Introduction to Network Forensics

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/6f6cec8c5d752de5be16a6167a5f8a1f_MD5.jpg)

## Introduction to Network Forensics

Network Forensics is a specific subdomain of the Forensics domain, and it focuses on network traffic investigation. Network Forensics discipline covers the work done to access information transmitted by listening and investigating live and recorded traffic, gathering evidence/artefacts and understanding potential problems.

Briefly, it is the action of recording packets of network traffic and creating investigatable sources and establishing a root–cause analysis of an event. The ultimate goal is to provide sufficient information to detect malicious activities, security breaches, policy/regulation compliance, system health and user behaviour.

The investigation process identifies communicated hosts in terms of time, frequency, protocol, application and data.

The investigation tries to answer the **5W**;

- Who (Source IP and port)
- What (Data/payload)
- Where (Destination IP and port)
- When (Time and data)
- Why (How/What happened)

**Note that** the network evidence capture and investigation process should be systematic. Having enough data and the right timeline capture for a successful network forensics investigation is crucial.

## Network Forensics Use Cases

The most common network forensics use cases are explained below;

- **Network discovery:** Discovering the network to overview connected devices, rogue hosts and network load.
- **Packets reassembling:** Reassembling the packets to investigate the traffic flow. This use case is helpful in unencrypted traffic flows.
- **Data leakage detection:** Reviewing packet transfer rates for each host and destination address helps detect possible data leakage.
- **Anomaly and malicious activity detection:** Reviewing overall network load by focusing on used ports, source and destination addresses, and data helps detect possible malicious activities along with vulnerabilities. This use case covers the correlation of indicators and hypotheses as well.
- **Policy/Regulation compliance control:** Reviewing overall network behaviour helps detect policy/regulation compliance.

## Advantages of Network Forensics

General advantages of network forensics are explained below;

- **Availability of network-based evidence in the wild:** Capturing network traffic is collecting evidence, so it is easier than other types of evidence collections such as logs and IOCs.
- **Ease of data/evidence collection without creating noise:** Capturing and working with network traffic is easier than investigating unfiltered events by EDRs, EPPs and log systems. Usually, sniffing doesn’t create much noise, logs and alerts. The other thing is that network traffic is not destructible like logs and alerts generated by security systems.
- **It is hard to destroy the network evidence, as it is the transferred data:** Since the evidence is the traffic itself, it is impossible to do anything without creating network noise. Still, it is possible to hide the artefacts by encrypting, tunnelling and manipulating the packets. So, the second fact is the challenge of this advantage.
- **Availability of log sources:** Logs provide valuable information which helps to correlate the chain of events and support the investigation hypothesis. The majority of the EDRs, EPPs and network devices create logs by default. Having log files is easy if the attacker/threat/malware didn’t erase/destroy them.
- **It is possible to gather evidence for memory and non-residential malicious activities:** The malware/threat might reside in the memory to avoid detection. However, the series of commands and connections live in the network. So it is possible to detect non-residential threats with network forensics tools and tactics.

## Challenges of Network Forensics

General challenges of the network forensics are explained below;

- **Deciding what to do:** One of the most difficult challenges of network forensics is “Deciding what to do”. There are several purposes of carving networks; SOC, IH/IR and Threat Hunting. Observing, trapping, catching, or stopping an anomalous activity is also possible.
- **Sufficient data/evidence collection on the network:** One of the advantages of network forensics is “Ease of collecting evidence”. However, the breadth of this concept poses a challenge. There are multiple points to consider in data/evidence collection.
- **Short data capture:** One of the challenges in data/evidence collection. Capturing all network activity is not applicable and operable. So, it is hard always to have the packet captures that covers pre, during and post-event.
- **The unavailability of full-packet capture on suspicious events:** Continuously capturing, storing and processing full-packets costs time and resources. The inability to have full-packet captures for a long time creates time gaps between captures, resulting in missing a significant part of an event of interest. Sometimes NetFlow captures are used instead of full-packet captures to reduce the weight of having full-packet captures and increase the capture time. Note that full-packet captures provide full packet details and give the opportunity of event reconstruction, while NetFlow provides high-level summary but not data/payload details.
- **Encrypted traffic:** Encrypted data is another challenge of network forensics. In most cases, discovering the contents of the encrypted data is not possible. However, the encrypted data still can provide valuable information for the hypothesis like source and destination address and used services.
- **GDPR and Privacy concerns in traffic recording:** Capturing the traffic is the same as “recording everything on the wire”; therefore, this act should comply with GDPR and business-specific regulations (e.g. HIPAA, PCI DSS and FISMA ).
- **Nonstandard port usage:** One of the popular approaches in network forensics investigations is grabbing the low-hanging fruits in the first investigation step. Looking for commonly used patterns (like known ports and services used in enumeration and exploitation) is known as grabbing the low-hanging fruits. However, sometimes attackers/threats use nonstandard ports and services to avoid detection and bypass security mechanisms. Therefore sometimes, this ends up as a challenge of network forensics.
- **Time zone issues:** Using a common time zone is important for big-scale event investigation. Especially when working with multiple resources over different time zones, usage of different time zones create difficulties in event correlation.
- **Lack of logs:** Network forensics is not limited to investigating the network traffic data. Network devices and event logs are crucial in event correlation and investigation hypotheses. This fact is known by the attackers/threats as well; therefore these logs are often erased by them, in order to make the investigation more difficult.

## Sources of Network Forensics Evidence

Capturing proper network traffic requires knowledge and tools. Usually, there is a single chance of gathering the live traffic as evidence. There are multiple evidence resources to gather network forensics data.

- TAPS
- InLine Devices
- SPAN Ports
- Hubs
- Switches
- Routers
- DHCP Servers
- Name Servers
- Authentication Servers
- Firewalls
- Web Proxies
- Central Log Servers
- Logs (IDS/IPS, Application, OS, Device)

## Primary Purposes of Network Forensics

There are two primary purposes in Network Forensics investigations.

- **Security Operations (SOC):** Daily security monitoring activities on system performance and health, user behaviour, and security issues.
- **Incident Handling/Response and Threat Hunting:** During/Post-incident investigation activities on understanding the reason for the incident, detecting malicious and suspicious activity, and investigating the data flow content.

## Investigated Data Types in Network Forensics

There are three main data types investigated in Network Forensics

- **Live Traffic**
- **Traffic Captures (full packet captures and network flows)**
- **Log Files**

NetworkMiner is capable of processing and handling packet pictures and live traffic. Therefore, we will focus on live and captured traffic in this room. Both of these data sources are valuable for forensics investigations.

Traffic investigation actions fall under network forensics’s “Traffic Analysis” subdomain. However, the main purpose of the NetworkMiner is to investigate the overall flow/condition of the limited amount of traffic, not for a long in-depth live traffic investigation. Therefore we will focus on how to use NetworkMiner for this purpose. In-depth traffic and packet analysis will be covered in the rooms below;

- [Wireshark](https://tryhackme.com/room/wireshark)
- Tcpdump (available soon!)
- Tshark (available soon!)

# Task 3 What is NetworkMiner?

## NetworkMiner in a Nutshell

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/46422b9985ffa693c61932c3be31de59_MD5.jpg)

**We are using NetworkMiner free edition in this room, but a Professional edition has much more features. You can see the differences between free and professional versions** [**here**](https://www.netresec.com/?page=NetworkMiner)**.**

## Operating Modes

There are two main operating modes;

- **Sniffer Mode:** Although it has a sniffing feature, it is not intended to use as a sniffer. The sniffier feature is available only on Windows. However, the rest of the features are available in Windows and Linux OS. Based on experience, the sniffing feature is not as reliable as other features. Therefore we suggest not using this tool as a primary sniffer. Even the official description of the tool mentions that this tool is a “Network Forensics Analysis Tool”, but it can be used as a “sniffer”. In other words, it is a Network Forensic Analysis Tool with but has a sniffer feature, but it is not a dedicated sniffer like Wireshark and tcpdump.
- **Packet Parsing/Processing:** NetworkMiner can parse traffic captures to have a quick overview and information on the investigated capture. This operation mode is mainly suggested to grab the “low hanging fruit” before diving into a deeper investigation.

## Pros and Cons

As mentioned in the previous task, NetworkMiner is mainly used to gain an overview of the network. Before starting to investigate traffic data, let’s look at **the pros and cons of the NetworkMiner.**

**Pros**

- OS fingerprinting
- Easy file extraction
- Credential grabbing
- Clear text keyword parsing
- Overall overview

**Cons**

- Not useful in active sniffing
- Not useful for large pcap investigation
- Limited filtering
- Not built for manual traffic investigation

## Differences Between Wireshark and NetworkMiner

NetworkMiner and Wireshark have similar base features, but they separate in use purpose. Although main functions are identical, some of the features are much stronger for specific use cases.

The best practice is to record the traffic for offline analysis, quickly overview the pcap with NetworkMiner and go deep with Wireshark for further investigation.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/e3ef867652226dd3f2fb39fea6178075_MD5.jpg)

# Task 4 Tool Overview 1

## Getting VM Started

Go back to Task 1, at the top of the task is a green button labled Start Machine. Click the green button to start the VM.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/f1123a6472870726efc6a757b7274cc9_MD5.jpg)

If the screen doesn’t split in half with the VM on the right and Tasks on the left. Then scroll to the top of the page, you will see a Blue button labeled Show Split View, click this button to split the screen.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/bd991173d3fae59072ff7865f31c16ac_MD5.jpg)

Time to open NetworkMiner, double-click on the NetworkMiner_2–7–2 folder.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/9061353fbc44e3dffe2ee1ba2e876ef9_MD5.jpg)

When the directory opens, double-click on NetworkMiner.exe, then give it time to open.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/200c565eeb88dc2061b63af15f91b2cf_MD5.jpg)

NetworkMiner will open, you are now ready to go along with this Task. See you at the Question.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/c3ee0cd8dd95e14a02102ca90a894382_MD5.jpg)

## Landing Page

This is the landing page of the NetworkMiner. Once you open the application, this screen loads up.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/1453c3b9b42ead4e2bc0c7b5b9dcf870_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/2f84069cf40287a035fa9b32628eee99_MD5.jpg)

## File Menu

The file menu helps you load a Pcap file or receive Pcap over IP. You can also drag and drop pcap files as well.

NetworkMiner also can receive Pcaps over IP. This room suggests using NetworkMiner as an initial investigation tool for low hanging fruit grabbing and traffic overview. Therefore, we will skip receiving Pcaps over IP in this room. You can read on receiving Pcap over IP from [here](https://www.netresec.com/?page=Blog&month=2011-09&post=Pcap-over-IP-in-NetworkMiner) and [here](http://www.gavinhollinger.com/2016/10/pcap-over-ip-to-networkminer.html).

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/11c47ce55d9559dcb243d62b2c93f4ae_MD5.jpg)

## Tools Menu

The tools menu helps you clear the dashboard and remove the captured data.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/c3f891db7608eef6b1a54a72b86590dd_MD5.jpg)

## Help Menu

The help menu provides information on updates and the current version.

## Case Panel

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/0e366e39e6ea37d7cb712151aa7fecb3_MD5.jpg)

The case panel shows the list of the investigated pcap files. You can reload/refresh, view metadata details and remove loaded files from this panel.

Viewing metadata of loaded files;

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/e0bc82d0dcd8b90a0b87abe107330794_MD5.jpg)

## Hosts

The “hosts” menu shows the identified hosts in the pcap file. This section provides information on;

- IP address
- MAC address
- OS type
- Open ports
- Sent/Received packets
- Incoming/Outgoing sessions
- Host details

OS fingerprinting uses the Satori GitHub repo and p0f, and the MAC address database uses the mac-ages GitHub repo.

You can sort the identified hosts by using the sort menu. You can change the colour of the hosts as well. Some of the features (OSINT lookup) are available only in premium mode. The right-click menu also helps you to copy the selected value.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/dc36a209b068b0252b78cac7129a7a66_MD5.jpg)

## Sessions

The session menu shows detected sessions in the pcap file. This section provides information on;

- Frame number
- Client and server address
- Source and destination port
- Protocol
- Start time

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/abcbf6a4df835546d501d68eff01d2d9_MD5.jpg)

You can search for keywords inside frames with the help of the filtering bar. It is possible to filter specific columns of the session menu as well. This menu accepts four types of inputs;

- “ExactPhrase”
- “AllWords”
- “AnyWord”
- “RegExe”

## DNS

The DNS menu shows DNS queries with details. This section provides information on;

- Frame number
- Timestamp
- Client and server
- Source and destination port
- IP TTL
- DNS time
- Transaction ID and type
- DNS query and answer
- Alexa Top 1M

Some of the features (Alexa Top 1M) are available only in premium mode. The search bar is available here as well.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/18ae3f964c093ed16c2d3e10ffb3e583_MD5.jpg)

## Credentials

The credentials menu shows extracted credentials and password [hashes](https://tryhackme.com/room/hashingcrypto101) from investigated pcaps. You can use [Hashcat](https://tryhackme.com/room/crackthehashlevel2) ([GitHub](https://github.com/hashcat/hashcat)) and [John the Ripper](https://tryhackme.com/room/johntheripper0) ([GitHub](https://github.com/openwall/john)) to decrypt extracted credentials. NetworkMiner can extract credentials including;

- Kerberos hashes
- NTLM hashes
- RDP cookies
- HTTP cookies
- HTTP requests
- IMAP
- FTP
- SMTP
- MS SQL

The right-click menu is helpful in this part as well. You can easily copy the username and password values.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/bed54633bc2cb7fe2cb87f3dd6bcef53_MD5.jpg)

### Answer the questions below

Use mx-3.pcap

In NetworkMiner, at the top left of the window is the File Tab. Click it, a dropt-down menu will appear, click the Open tab.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/be2dbaee2df8fd5e9b2b9405d8500d7f_MD5.jpg)

A window will pop-up, and you will be in your current directory. On the left side of this window is a quick find bar, click on the Desktop icon.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/0073705bf407d800b76e0717f4cdb716_MD5.jpg)

Double-click on the Exercise Files.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/fe8adb8c0126ff4d2c634c77b6a159d2_MD5.jpg)

Double-click on th emx-3.pcap file, this will open it in NetworkMiner.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/e8860bf0417850dd105c0012d9141318_MD5.jpg)

You are now ready to start finding answers to the questions.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/bea212a82fe0c9b8b563fbed8bbda2f5_MD5.jpg)

**What is the total number of frames?**

On the right side of the NetworkMiner window, you will see the Case Panel. Inside this panel will be the pcap file we just loaded. Right-click on the file, a drop-down menu will appear. On this menu, you will see Show Metadata, click on this tab.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/3206a4ea0638ba579ac1a03fc59c1bb9_MD5.jpg)

The Metadata window will pop-up, you might need to expand the table, as I had too. Go the right edge of the Value column, when your cursor changes to how it is below, you can click and drag the edge of the table out to expand it. After doing this to the Value column, do the same thing to the Name Column.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/e869b0a02a9d6d2f333c7f425b1b22cd_MD5.jpg)

After expanding the table, you will see in the Name column Frames in the fourth row down. Look at the Value of this row, this is the answer to the question. Once you find it, type the answer in the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/3c7c6c6d29a2ca0abfbbc151a7bf7058_MD5.jpg)

Answer: 460

**How many IP addresses use the same MAC address with host 145.253.2.203?**

Head back to NetworkMiner, close out of the Metadata window with the X button in the top right.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/3c3aea0182b457934466f46f0d73720a_MD5.jpg)

You should already be in the Host tab, look down through the IP address till you find the IP address mentioned in the question. Once you find it click the small + icon on the left side of it to expand the IP address and give you more information.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/de7c0548bd1cae470332c9a5356f3048_MD5.jpg)

Just like with the IP address, look down through till you find MAC. Once you find it, there will be once again a small + icon. Click this icon to expand the MAC adress.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/075af499cdf446bede9793c083751823_MD5.jpg)

After expanding the MAC address section, count the number of MAC address that in the parathensis say Same MAC addresses. After you have the count, type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/93468c51359c31cf8d82ba6fa8b28d36_MD5.jpg)

Answer: 2

**How many packets were sent from host 65.208.228.223?**

Head back to NetworkMiner, this time look for the IP address mentioned in the question. Once you find it click the small + icon on the left side of it to expand the IP address and give you more information.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/cad4a896b6cb1ecdd02ad535263b4a1a_MD5.jpg)

Look down through till you get to the Sent section, the first number in this section is the answer to the question. Once you find it, type the answer in the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/ff46e2b18e9a0dbf0ac56762237735b3_MD5.jpg)

Answer: 72

**What is the name of the webserver banner under host 65.208.228.223?**

Staying in information as the previous quesiton, look at the last section labeled Host Details. Click the small + icon to expand the Host Details section.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/ff7ad67082effa1f9ce93ac5a4c51af9_MD5.jpg)

The answer can be found at the end of the information in the expanded Host Details section. Once you find it, type the answer in the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/a13b3b43da28ad8e02a7feaea1c7ca46_MD5.jpg)

Answer: Apache

Use mx-4.pcap

In NetworkMiner, at the top left of the window is the File Tab. Click it, a dropt-down menu will appear, click the Open tab.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/be2dbaee2df8fd5e9b2b9405d8500d7f_MD5.jpg)

A window will pop-up, and you will be in your the directory that you last used, which will be the one we need. Double-Click on mx-4.pcap to open it in NetworkMiner.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/99675214b5dbb6f39796f34fc68cb829_MD5.jpg)

After opening the file, you will see it appears in the Case Panel on the right. You are now ready to answer the rest of the questions.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/697f60f1477274c9ed57d8a005e4139c_MD5.jpg)

**What is the extracted username?**

Look for Credentials Menu tab, when you find it, click on it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/8716d62b63727ef3802cdf6619c14552_MD5.jpg)

Once on this tab, look

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/1f3f646ead2fa43d3be5f2ab8cb19e9c_MD5.jpg)

Answer: `#b\Administrator`

**What is the extracted password?**

Staying on the Credentials Menu Tab, look to the Password column, which is to the right of the Username column. Right-click on the Password, on the drop-down menu click Copy Password. Then there is a small Grey Tab in the middle of the VM. Click this tab.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/3db32839e6387c856e3b08a7b677597f_MD5.jpg)

Click the clipboard icon on the pop-out bar.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/3f0f2ac0f2024936de4066630506e936_MD5.jpg)

A Clipboard window will pop-up, click inside the text box. Then use the keyboard shortcut ctrl + a to hightlight all the text inside the box. Then copy (ctrl + c) and paste (ctrl + v) in the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/5697a3f8b64f2c2d1530b745202389c9_MD5.jpg)

Answer: `$NETNTLMv2$#B$136B077D942D9A63$FBFF3C253926907AAAAD670A9037F2A5$01010000000000000094D71AE38CD60170A8D571127AE49E00000000020004003300420001001E003000310035003600360053002D00570049004E00310036002D004900520004001E0074006800720065006500620065006500730063006F002E0063006F006D0003003E003000310035003600360073002D00770069006E00310036002D00690072002E0074006800720065006500620065006500730063006F002E0063006F006D0005001E0074006800720065006500620065006500730063006F002E0063006F006D00070008000094D71AE38CD601060004000200000008003000300000000000000000000000003000009050B30CECBEBD73F501D6A2B88286851A6E84DDFAE1211D512A6A5A72594D340A001000000000000000000000000000000000000900220063006900660073002F003100370032002E00310036002E00360036002E0033003600000000000000000000000000`

# Task 5 Tool Overview 2

## Files

The file menu shows extracted files from investigated pcaps. This section provides information on;

- Frame number
- Filename
- Extension
- Size
- Source and destination address
- Source and destination port
- Protocol
- Timestamp
- Reconstructed path
- Details

Some features (OSINT hash lookup and sample submission) are available only in premium mode. The search bar is available here as well. The right-click menu is helpful in this part as well. You can easily open files and folders and view the file details in-depth.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/3118c40f575959082cd8210907df83fb_MD5.jpg)

## Images

The file menu shows extracted images from investigated pcaps. The right-click menu is helpful in this part as well. You can open files and zoom in & out easily.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/6ecf86b0be8ca8e9eb61ff738527e2bd_MD5.jpg)

Once you hover over the image, it shows the file’s detailed information (source & destination address and file path).

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/b8c1590996a920d5044b6e469a520ab6_MD5.jpg)

## Parameters

The file menu shows extracted parameters from investigated pcaps. This section provides information on;

- Parameter name
- Parameter value
- Frame number
- Source and destination host
- Source and destination port
- Timestamp
- Details

The right-click menu is helpful in this part as well. You can copy the parameters and values easily.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/e5bade08853ce35f063d2812bef416a3_MD5.jpg)

## Keywords

The file menu shows extracted keywords from investigated pcaps. This section provides information on;

- Frame number
- Timestamp
- Keyword
- Context
- Source and destination host
- source and destination port

How to filter keywords;

- Add keywords
- Reload case files!

**Note:** You can filter multiple keywords in this section; however, you must reload the case files after updating the search keywords. Keyword search investigates all possible data in the processed pcaps.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/6b2ef4219283d737da13b81bc3a0a003_MD5.jpg)

## Messages

The messages menu shows extracted emails, chats and messages from investigated pcaps. This section provides information on;

- Frame number
- Source and destination host
- Protocol
- Sender (From)
- Receiver (To)
- Timestamp
- Size

Once you filter the traffic and get a hit, you will discover additional details like attachments and attributes on the selected message. Note that the search bar is available here as well. The right-click menu is available here. You can use the built-in viewer to investigate overall information and the “open file” option to explore attachments.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/5e3867458f339675c50486f8b9d293b6_MD5.jpg)

## Anomalies

The anomalies menu shows detected anomalies in the processed pcap. Note that NetworkMiner isn’t designated as an IDS. However, developers added some detections for EternalBlue exploit and spoofing attempts.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/c79d4d087341f5ae4b86bbe8ea0cabca_MD5.jpg)

### Answer the questions below

Use mx-7 pcap

In NetworkMiner, at the top left of the window is the File Tab. Click it, a dropt-down menu will appear, click the Open tab.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/3c2e4fdb62b05ab63f61da0f118bec8d_MD5.jpg)

A window will pop-up, and you will be in your current directory. On the left side of this window is a quick find bar, click on the Desktop icon.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/1fb7266975b86c014a1dd3502beb30f6_MD5.jpg)

Double-click on the Exercise Files.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/f34784c8b2184a41ef5cb35c548c1f5f_MD5.jpg)

Double-click on the emx-7.pcap file, this will open it in NetworkMiner.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/f4c54ffdaf859e784f0b7ffe31ebf77b_MD5.jpg)

You are now ready to start finding answers to the questions.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/a56189885610f0f28f9e0aac42c62d77_MD5.jpg)

**What is the name of the Linux distro mentioned in the file associated with frame 63075?**

On NetworkMiner, look at the category tabs. When you find the Files tab, click on it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/347dc23f057f24a3abba433770cb1c73_MD5.jpg)

Once on the Files tab, there is a Filter Keywords field. Type in the field, 63075 then move to the right and click the Apply button.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/5f5c538896665711c44debdc3eb43777_MD5.jpg)

You will have one result, the answer can be found here, under the source host column. But I think that TryhackMe wants you to find it elsewhere, so double-click on the result. This will open a Details window.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/f62b3db7446f5a47da564527ff56c8ac_MD5.jpg)

In the File Details window, you will see information in the top half, and the hex value along with what it represents on the bottom half. If you look through the converted hex value, in the bottom half on the right, look for Linux/distributions/. The answer can be found after the backslash. Once you find it, type the answer in the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/3a137dee403eacb208b8e053b06d3fbb_MD5.jpg)

Answer: Centos

**What is the header of the page associated with frame 75942?**

Heading back to NetworkMiner, click on the X in the top right corner of the File Details window. Then click the Clear button that is next to the Apply button.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/81c7b27d7e72f3eb04154f4bfe32a7f6_MD5.jpg)

Now type 75942, into the Filter Keyword field. Then click the Apply button.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/57138f7485d3eb90f1cf1f012e80efcb_MD5.jpg)

Double-click on the result.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/39e8baa47d877f783b86703742c8efbf_MD5.jpg)

The File Details window will pop-up, look down through the converted hex value. The answer can be found after `pwned.se — `, or the `<h1>`. Once you find it, type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/eb34e4f9f414f5206acb02f2be5d926f_MD5.jpg)

Answer: Password-Ned AB

**What is the source address of the image “ads.bmp.2E5F0FD9.bmp”?**

Heading back to NetworkMiner, click on the X in the top right corner of the File Details window. Then click the Clear button that is next to the Apply button.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/eee0e5b9cdc42a0c045f28a1039bd5ea_MD5.jpg)

Now type ads.bmp.2E5F0FD9.bmp, into the Filter Keyword field. Then click the Apply button.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/b4e26de6c492feb2c012d88dd1c98de6_MD5.jpg)

You will only have one result, in this result look for the Source host column. Once you find it, you will see an IP address, this is the answer to the question. Once you find it, type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/dc1ae0418ad3879e1f084267aa845e6c_MD5.jpg)

Answer: 80.239.178.187

**What is the frame number of the possible TLS anomaly?**

Heading back to NetworkMiner, look for the Anomalies tab and click on it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/a67c2a50c2fe6858ea9a13d62dc9f9a8_MD5.jpg)

Once on this tab, you will see two possible Anomalies. If you look to the end of each line, you will find the frame numbers. The first result is the frame number you are looking for, for this question. Once you find it, type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/87d1c411998aa0a6f0b7582147c0679e_MD5.jpg)

Answer: 36255

Use mx-9 file

In NetworkMiner, at the top left of the window is the File Tab. Click it, a dropt-down menu will appear, click the Open tab.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/3c2e4fdb62b05ab63f61da0f118bec8d_MD5.jpg)

A window will pop-up, and you will be in your the directory that you last used, which will be the one we need. Double-Click on mx-9.pcap to open it in NetworkMiner.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/60411d52bb0628611013ce99f077f4a3_MD5.jpg)

After opening the file, you will see it appears in the Case Panel on the right. You are now ready to answer the rest of the questions.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/73dd7d09e298e457af4b06e1c7844858_MD5.jpg)

**Look at the messages. Which platform sent a password reset email?**

When the pcap file is done loading, click on the Message tab.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/096c09df5e68554fe108eb1f3cf673d5_MD5.jpg)

Once on the Messages tab, you will see only one result that says PASSWORD. This gives credit that this is the password reset we are looking for here. Click on the entry, that has PASSWORD in it. Next look to the section with the decoded email in it. You will see the word Open, next to this word is the answer we are looking for. Once you find it, type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/944d93f3b11bc5427addcc8e7b14f879_MD5.jpg)

Answer: Facebook

**What is the email address of Branson Matheson?**

Staying in the Messages Tab, if we go one result down from the previous answer, we can see the first name of the person in question. Scroll right to uncover the From column.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/2f085e2294895138ad34aa835e1a4f18_MD5.jpg)

Once you have revealed the From column, you will see Branson’s email address, and the answer to the question. Type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/8c640d7f7b4bd37a1357fb7cc296bbd0_MD5.jpg)

Answer: `branson@sandsite.org`

# Task 6 Version Differences

## Version Differences

As always, it wouldn’t be surprising to see a feature improvement as the version goes up. Unsurprisingly version upgrades provide stability, security fixes and features. Here the feature part is quite tricky. Feature upgrades can represent implementing new features and updating the existing feature (optimisation, alteration or operation mode modification). You can always check the changelog [here](https://www.netresec.com/?page=NetworkMiner).

**Since there are some significant differences between the versions, the given VM has both of the major versions (v1.6 and v2.7).**

Of course, as the program version increases, it is expected to increase feature increase and scope. Here are the significant differences between versions 1.6 and 2.7. Here are the differences;

## Mac Address Processing

NetworkMiner versions after version 2 can process MAC address specific correlation as shown in the picture below. This option will help you identify if there is a MAC Address conflict. This feature is not available before version 2.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/f26d27db44b00811b6e3b74c86b80887_MD5.jpg)

## Sent/Received Packet Processing

NetwrokMiner versions up to version 1.6. can handle packets in much detail. These options will help you investigate the sent/received

packets in a more detailed format. This feature is not available after version 1.6.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/fcaaf72fb9955fce0d7d3e72444581dd_MD5.jpg)

## Frame Processing

NetworkMiner versions up to version 1.6. can handle frames. This option provides the number of frames and essential details about the frames. This feature is not available after version 1.6.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/636a4f5077c5236d1c879f47e05aa967_MD5.jpg)

## Parameter Processing

NetworkMiner versions after version 2 can handle parameters in a much more extensive form. Therefore version 1.6.xx catches fewer parameters than version 2.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/624a1c4a4e2d5f310f5466abe37473b5_MD5.jpg)

## Cleartext Processing

NetworkMiner versions up to version 1.6. can handle cleartext data. This option provides all extracted cleartext data in a single tab; it is beneficial to investigate cleartext data about the traffic data. However, it is impossible to match the cleartext data and packets. This feature is not available after version 1.6.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/a723c2730fc91f75fdbb7ca10b9085ef_MD5.jpg)

### Answer the questions below

Since the answers can be found above, I won’t be posting the answer below. You can follow along to help you discover where they are.

**Which version can detect duplicate MAC addresses?**

Scroll up to the Mac Address Processing section, if you read through the small paragraph you discover which version can detect duplicate MAC addresses. Look at the screenshots, the version located at the top of each NetworkMiner instants, is used for the answers. Once you find it, type the answer into the TryHackMe answer field, then click submit.

Answer: 2.7

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/c79a321938e8088ad21f65fac4f773dd_MD5.jpg)

**Which version can handle frames?**

Scroll up to the Frame Processing section, if you read through the small paragraph you discover which version can handle frames. Look at the screenshots, the version located at the top of each NetworkMiner instants, is used for the answers. Once you find it, type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/91e0492cbd61c7dcb20f23d2c9bb5b28_MD5.jpg)

Answer: 1.6

**Which version can provide more details on packet details?**

Scroll up to the Frame Processing section, if you read through the small paragraph you discover which version has more packet details. Look at the screenshots, the version located at the top of each NetworkMiner instants, is used for the answers. Once you find it, type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/e611e9a57d61f74f3984df3aadec754b_MD5.jpg)

Answer: 1.6

# Task 7 Exercises

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/32335ff18aff0d1424113699513d7604_MD5.jpg)

Exercises

You’ve learned what NetworkMiner is and how to use it. Let’s put this into practice!

### Answer the questions below

Use case1.pcap

In NetworkMiner 2.7.2 version and 1.6.1 version are the same in the way to open a pcap file. Use this process to open the pcap in both versions. At the top left of the window is the File Tab. Click it, a dropt-down menu will appear, click the Open tab.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/3c2e4fdb62b05ab63f61da0f118bec8d_MD5.jpg)

A window will pop-up, and you will be in your current directory. On the left side of this window is a quick find bar, click on the Desktop icon.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/1fb7266975b86c014a1dd3502beb30f6_MD5.jpg)

Double-click on the Exercise Files.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/f34784c8b2184a41ef5cb35c548c1f5f_MD5.jpg)

Double-click on the case1.pcap file, this will open it in NetworkMiner.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/75053da4cc1a68794adb3634c9640aca_MD5.jpg)

You are now ready to start finding answers to the questions.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/ad8886df1b1204d2a0baee5efa120ce5_MD5.jpg)

**What is the OS name of the host 131.151.37.122?**

In NetworkMiner 2.7.2, you will be on the Host tab already, if you look at the last IP address it matches the one we are looking for. Click on the small + icon next to the Windows icon to expand.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/a98221adef8dd2b0df86ea9d16f5e42d_MD5.jpg)

Move down to the OS: Windows section, click the small + icon on the left side to expand this section.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/8c3ec8cdfdae6bd2074e55ef3513647a_MD5.jpg)

Look down at the Satori TCP: section, the answer is right after the name of the section. Once you find it, type the answer in the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/6af07f3199cc2c534214334d4ff4d0e8_MD5.jpg)

Answer: Windows — Windows NT 4

Investigate the hosts 131.151.37.122 and 131.151.32.91.  

**How many data bytes were received from host 131.151.32.91 to host 131.151.37.122 through port 1065?**

Head back to NetworkMiner 2.7.2, staying in the current IP address section. Look towards the bottom till you find the Incoming Sessions: section, click the small + icon on the left side of this section, to expand it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/f5d9083d866965f1e85078b1cfede877_MD5.jpg)

There are two Incoming Sessions ports, the question asks us to look at port 1065. So click on the small + icon on the left side of the Server: section with port 1065, to expand it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/2c0b973dc0f938d8ffefd40cc298cd6c_MD5.jpg)

If you look in the drop-down information about this server, look for the IP address 131.151.32.91 (this is the one given to us in the question). Once you find it, right after the protocol and port is a parenthesis, inside is the integer value of the data bytes sent. This is the answer to the question, type the answer in the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/0351f13524961896e294bd826fc9d949_MD5.jpg)

Answer: 192

Investigate the hosts 131.151.37.122 and 131.151.32.21.  

**How many data bytes were received from host 131.151.37.122 to host 131.151.32.21 through port 143?**

Head back to NetworkMiner 2.7.2, we are staying in the Incoming Sessions: section. This time, click on the small + next to the Server:, this is located below the previous questions Server:.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/78a46b9525e9c566a963b142d3a99df0_MD5.jpg)

If you look in the drop-down information about this server, look for the IP address 131.151.37.122, the reason we use this IP address is the question wants to know how many data bytes were sent to the Client IP address. Once you find it, right after the protocol and port is a parenthesis, inside is the integer value of the data bytes sent. This is the answer to the question, type the answer in the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/e46a8b0e6c1db71f064a5af7f94ec532_MD5.jpg)

Answer: 20769

**What is the sequence number of frame 9?**

Heading to NetworkMiner 1.6.1, look at the menu tabs for the Frames tab, and click on it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/75672d868912e6097c7238d01cbd9232_MD5.jpg)

Look for Frame 9, once you find it click on the small + icon to expand the Frame.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/d63b361e9996382e872dcfc78dbd03b5_MD5.jpg)

After you have expanded the frame, now click on the small + icon next to TCP.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/439898eb688227a27cc8d519a9adf80c_MD5.jpg)

The fourth result down is the Sequence Number section. The integer after the equals is the answer. Once you find it, type the answer in the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/c6b6ea1e4aa623e517af2e4335037546_MD5.jpg)

Answer: 2AD77400

**What is the number of the detected “content types”?**

Going back to the NetworkMiner 2.7.2, this time you want to click on the Parameters Tab.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/0f480747465b6c8b09afb2d04f9dfd0b_MD5.jpg)

So we have to add and change some parameters, first one is the Filter Keyword, type content type into the field. Next, move over to the first drop-down menu on the right, change it to AllWords. Move to the next drop-down menu to the right, on this menu change it to Parameter name. Now you are ready to click the apply button.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/9d5126286402d7b93a865b3a629a2931_MD5.jpg)

Now that you have filtered the content, look to the Parameter Value column. Count the different types in this column, the number of these different types is the answer to the question. Once you figure it out, type the answer in the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/b87c6a07eda1f7efb48292b1357269af_MD5.jpg)

Answer: 2

Use case2.pcap

In NetworkMiner 2.7.2 version, I only used version 2.7.2 because the VM kept crashing when I loaded the pcap into version 1.6.1. Use this process to open the pcap in both versions. At the top left of the window is the File Tab. Click it, a dropt-down menu will appear, click the Open tab.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/3c2e4fdb62b05ab63f61da0f118bec8d_MD5.jpg)

A window will pop-up, and you will be in your the directory that you last used, which will be the one we need. Double-Click on case2.pcap to open it in NetworkMiner.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/8096c2399143307ff3cca535b907bdd9_MD5.jpg)

After opening the file, you will see it appears in the Case Panel on the right. You are now ready to answer the rest of the questions.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/70da320fe216c1f41d216136f17a7713_MD5.jpg)

Investigate the files.

**What is the USB product’s brand name?**

Back in NetworkMiner 2.7.2, click on the Files menu tab.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/8109f44228ed58990075b055ebe0382c_MD5.jpg)

Once on the Files menu tab, type usb in the Filter Keywords field. Then click Apply.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/6bd2d1768292c5dd206d227030163a57_MD5.jpg)

Looking down through the results, one stands out to me. In the Filename column, we see hi-Speed-usb2.0_ax99772.htm. To me, this indicates that it is referring to the actual USB device. So if we move to the right into the Source Host column, we can see a domain name, this domain is the brand of USB and the answer to this question. Once you find it, type the answer in the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/95515ff574492faefe7eabccd93185dc_MD5.jpg)

Answer: Asix

**What is the name of the phone model?**

This one takes some researching in NetworkMiner 2.7.2, so to start off click on the Images menu tab.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/455570f0d0599b847c883419aabbbd4d_MD5.jpg)

Now being in the Images menu tab, scroll down through looking for images of phones. When you are about three quarters of the way down, you will see one, and a name Lumia.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/a60207a138abf81b6f54c3301f21e51d_MD5.jpg)

Time to head over to Files, so click on the Files menu tab.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/844d1f3cddf6f7af88e3bdbfb5531023_MD5.jpg)

Once on the Files menu tab, type Lumia in the Filter Keywords field, then click Apply.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/dfdaaa470f99ddb2044e6be22792ed14_MD5.jpg)

As we can see, we have two possible results. At first glance of both of these, the first one sounds like a store navigation, the second though with MMD could stand for Multimedia device. So If we look right after MMD we see Lumia and a set of numbers, this is the answer to the question. Type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/b8230412c0add34f35913fce83e40fcf_MD5.jpg)

Answer: Lumia 535

**What is the source IP of the fish image?**

Going back to NetworkMiner 2.7.2, we are staying in the Files menu tab. Click the Clear button, this is located to the left of the Apply button.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/99b229c5638d96ed50267c3de68dc9c3_MD5.jpg)

Type in the Filter Keyword field fish, then click Apply.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/a1bd53556593799f5f8fb375017861eb_MD5.jpg)

There is only one result, right-click on this result. In the drop-down menu, you will see Open File, click on it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/5aff73a906ac75605fc20af43fd98c03_MD5.jpg)

As we can see, this is the picture of the fish. So, look at the Source Host column, this will give you the IP address the question is asking for. Once you find it, type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/a5584b2c69f910d6e23f786763cf6709_MD5.jpg)

Answer: 50.22.95.9

**What is the password of the “homer.pwned.se@gmx.com”?**

Going back to NetworkMiner 2.7.2, we will need to go to the Credentials Menu Tab. But first, click the X at the top right of the Chrome window, to close it. Then click on the Credentials Menu tab.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/9857330fedddb78068d400e60f2e79ef_MD5.jpg)

Now that we are on the Credential menu tab, we have 312 results, to narrow down the results we can uncheck the boxes for Show NTLM Challenge-Response and Show Cookies, as this is information that we don’t need.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/05c7a42ba980ebd11428123a912832a1_MD5.jpg)

Now we only have two results, looking at the Username column we can see that we are in the right place. Scroll to the right till you can see the Password column.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/7350ce6ed5f4d8a4082e71d454d5849b_MD5.jpg)

Once you can see the Password column, you will be able to see the password for the email address, and thus the answer to the question. Type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/954db5a5e024d23007e48720ea715868_MD5.jpg)

Answer: spring2015
 
**What is the DNS Query of frame 62001?**

For the last time, go back to NetworkMiner 2.7.2, click on the DNS Menu tab.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/a06ecbbb17559257decc54c108399246_MD5.jpg)

In the Filter Keyword field, type 62001, for the Frame number. Next move over to the right to the second drop-down menu, in this menu you can choose what column you want to filter the keyword through, choose Frame nr.. Then you can click Apply.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/64796041966df95d711f9b675ac06a0c_MD5.jpg)

As we can see, we have two results from our Filter Keyword search. Now scroll to the right till you have reached the DNS Query column.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/e653118d45b493acaa5371dc2b200774_MD5.jpg)

Once you can see the DNS Query column, you will see the domain name, and thus the answer to the question. Type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/05%20Networkminer/4a93a38788f238380e6357ca3af79444_MD5.jpg)

Answer: pop.gmx.com

# Task 8 Conclusion

Congratulations! You just finished the NetworkMiner room.

In this room, we covered NetworkMiner, what it is, how it operates, and how to investigate pcap files. As I mentioned in the tasks before, there are a few things to remember about the NetworkMiner;

- Don’t use this tool as a primary sniffer.
- Use this tool to overview the traffic, then move forward with Wireshark and tcpdump for a more in-depth investigation.

**If you like this content, make sure you visit the following rooms later on THM**;

- [**Wireshark**](https://tryhackme.com/room/wireshark)
- [**Snort**](https://tryhackme.com/room/snort)
- [**Brim**](https://tryhackme.com/room/brim)