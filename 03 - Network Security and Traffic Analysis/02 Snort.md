https://www.youtube.com/watch?v=KmElfnLlpTk
https://www.youtube.com/watch?v=eekgRLBeYRE

https://github.com/AnLoMinus/TryHackMe/tree/main/Learning%20Path/SOC%20Level%201/Network%20Security%20and%20Traffic%20Analysis/Snort

https://medium.com/@haircutfish/tryhackme-snort-task-1-introduction-task-2-interactive-material-and-vm-task-3-introduction-2c4b2c768db8
https://medium.com/@haircutfish/tryhackme-snort-task-4-first-interaction-with-snort-task-5-operation-mode-1-sniffer-mode-69952d93b1af
https://medium.com/@haircutfish/tryhackme-snort-task-7-operation-mode-3-ids-ips-task-8-operation-mode-4-pcap-investigation-f70f91fc76b9
https://medium.com/@haircutfish/tryhackme-snort-task-9-snort-rule-structure-task-10-snort2-operation-logic-points-to-remember-fda26065c7f3

Learn how to use Snort to detect real-time threats, analyse recorded traffic files and identify anomalies.

# Task 1 Introduction

![](_resources/02%20Snort/45ddb96690158fe1e3cbb73871fd7bda_MD5.jpg)

This room expects you to be familiar with basic Linux command-line functionalities like general system navigation and Network fundamentals (ports, protocols and traffic data). The room aims to encourage you to start working with Snort to analyse live and captured traffic.

Before joining this room, we suggest completing the [‘Network Fundamentals’](https://tryhackme.com/module/network-fundamentals) module. If you have general knowledge of network basics and Linux fundamentals, you will be ready to begin! If you feel you need assistance in the Linux command line, you can always refer to our “Linux Fundamentals” rooms (here [1](https://tryhackme.com/room/linuxfundamentalspart1) [2](https://tryhackme.com/room/linuxfundamentalspart2) [3](https://tryhackme.com/room/linuxfundamentalspart3));

SNORT is an **open-source, rule-based** Network Intrusion Detection and Prevention System **(NIDS/NIPS)**. It was developed and still maintained by Martin Roesch, open-source contributors, and the Cisco Talos team.

[**The official description**](https://www.snort.org/)**:** _“Snort is the foremost Open Source Intrusion Prevention System (IPS) in the world. Snort IPS uses a series of rules that help define malicious network activity and uses those rules to find packets that match against them and generate alerts for users.”_

# Task 2 Interactive Material and VM

![](_resources/02%20Snort/3622021fd241c9cab9d7877c0f6cfac8_MD5.jpg)

**Interactive material and exercise setup**

Deploy the machine attached to this task; it will be visible in the **split-screen** view once it is ready. If you don’t see a virtual machine load, click the **Show Split View** button.

![](_resources/02%20Snort/dbe7e1961f0d6adbe977daeed1c581ae_MD5.jpg)

Once the machine had fully started, you will see a folder named “**Task-Exercises**” on the Desktop. Each exercise has an individual folder and files; use them accordingly to the questions.

Everything you need is located under the “**Task-Exercises**” folder.

There are two sub-folders available;

- Config-Sample **—** Sample configuration and rule files. These files are provided to show what the configuration files look like. Installed Snort instance doesn’t use them, so feel free to practice and modify them. Snort’s original base files are located under **/etc/snort** folder.
- Exercise-Files **—** There are separate folders for each task. Each folder contains pcap, log and rule files ready to play with.

![](_resources/02%20Snort/002e237de16b3a5cbfc5807a688ad976_MD5.jpg)

**Traffic Generator**

The machine is offline, but there is a script (**traffic-generator.sh**) for you to generate traffic to your snort interface. You will use this script to trigger traffic to the snort interface. Once you run the script, it will ask you to choose the exercise type and then automatically open another terminal to show you the output of the selected action.

**Note that each traffic is designed for a specific exercise. Make sure you start the snort instance and wait until to end of the script execution. Don’t stop the traffic flood unless you choose the wrong exercise.**

Run the **“traffic generator.sh”** file by executing it as sudo.

executing the traffic generator script

```
user@ubuntu$ sudo ./traffic-generator.sh
```

General desktop overview. Traffic generator script in action.

![](_resources/02%20Snort/96575bb152c8fda593707c53b004fdbe_MD5.jpg)

Once you choose an action, the menu disappears and opens a terminal instance to show you the output of the action.

![](_resources/02%20Snort/5ef59d2a6d869674e168d04a11b7b3fc_MD5.jpg)

### Answer the questions below

**Navigate to the Task-Exercises folder and run the command “./.easy.sh” and write the output**

Click the small terminal icon, in the top left of the VM.

![](_resources/02%20Snort/935741a919b5efe32a18f40595d52b8a_MD5.jpg)

In the window that pops up type, cd Desktop/Task-Exercises/ . Then press enter to navigate to this directory.

![](_resources/02%20Snort/2ad1b98616986788218acd635c919314_MD5.jpg)

Type the command, given to you by the question, into the terminal. The output is going to be the answer. Type it into the TryHackMe answer field, then click submit.

![](_resources/02%20Snort/c2839719575f7d6ee5a1ab74821268a7_MD5.jpg)

Answer: Too Easy!

# Task 3 Introduction to IDS/IPS

![](_resources/02%20Snort/fd03462b6d268890e12cceaf18243ffe_MD5.jpg)

Before diving into Snort and analysing traffic, let’s have a brief overview of what an Intrusion Detection System (IDS) and Intrusion Prevention System (IPS) is. It is possible to configure your network infrastructure and use both of them, but before starting to use any of them, let’s learn the differences.

## Intrusion Detection System (IDS)

IDS is a passive monitoring solution for detecting possible malicious activities/patterns, abnormal incidents, and policy violations. It is responsible for generating alerts for each suspicious event.

**There are two main types of IDS systems;**

- **Network Intrusion Detection System (NIDS) —** NIDS monitors the traffic flow from various areas of the network. The aim is to investigate the traffic on the entire subnet. If a signature is identified, **an alert is created**.
- **Host-based Intrusion Detection System (HIDS) —** HIDS monitors the traffic flow from a single endpoint device. The aim is to investigate the traffic on a particular device. If a signature is identified, **an alert is created.**

## Intrusion Prevention System (IPS)

IPS is an active protecting solution for preventing possible malicious activities/patterns, abnormal incidents, and policy violations. It is responsible for stopping/preventing/terminating the suspicious event as soon as the detection is performed.

**There are four main types of IPS systems;**

- **Network Intrusion Prevention System (NIPS) —** NIPS monitors the traffic flow from various areas of the network. The aim is to protect the traffic on the entire subnet. If a signature is identified, **the connection is terminated**.
- **Behaviour-based Intrusion Prevention System (Network Behaviour Analysis — NBA) —** Behaviour-based systems monitor the traffic flow from various areas of the network. The aim is to protect the traffic on the entire subnet. If a signature is identified, **the connection is terminated.**

Network Behaviour Analysis System works similar to NIPS. The difference between NIPS and Behaviour-based is; behaviour based systems require a training period (also known as “baselining”) to learn the normal traffic and differentiate the malicious traffic and threats. This model provides more efficient results against new threats.

The system is trained to know the “normal” to detect “abnormal”. The training period is crucial to avoid any false positives. In case of any security breach during the training period, the results will be highly problematic. Another critical point is to ensure that the system is well trained to recognise benign activities.

- **Wireless Intrusion Prevention System (WIPS) —** WIPS monitors the traffic flow from of wireless network. The aim is to protect the wireless traffic and stop possible attacks launched from there. If a signature is identified, **the connection is terminated**.
- **Host-based Intrusion Prevention System (HIPS) —** HIPS actively protects the traffic flow from a single endpoint device. The aim is to investigate the traffic on a particular device. If a signature is identified, **the connection is terminated.**

HIPS working mechanism is similar to HIDS. The difference between them is that **while HIDS creates alerts for threats,** **HIPS stops the threats by terminating the connection.**

## Detection/Prevention Techniques

There are three main detection and prevention techniques used in IDS and IPS solutions;

![](_resources/02%20Snort/a959d576dfdfc93d8f75ecfb92c89d93_MD5.jpg)

## Summary

**Phew!** That was a long ride and lots of information. Let’s summarise the overall functions of the IDS and IPS in a nutshell.

- **IDS** can identify threats but require user assistance to stop them.
- **IPS** can identify and block the threats with less user assistance at the detection time.

**Now let’s talk about Snort.** [**Here is the rest of the official description**](https://www.snort.org/) **of the snort;**

_“Snort can be deployed inline to stop these packets, as well. Snort has three primary uses: As a packet sniffer like tcpdump, as a packet logger — which is useful for network traffic debugging, or it can be used as a full-blown network intrusion prevention system. Snort can be downloaded and configured for personal and business use alike.”_

SNORT is an **open-source**, **rule-based** Network Intrusion Detection and Prevention System **(NIDS/NIPS)**. It was developed and still maintained by Martin Roesch, open-source contributors, and the Cisco Talos team.

**Capabilities of Snort;**

![](_resources/02%20Snort/55f890648bf6c530819f5ae55c046091_MD5.jpg)

- Live traffic analysis
- Attack and probe detection
- Packet logging
- Protocol analysis
- Real-time alerting
- Modules & plugins
- Pre-processors
- Cross-platform support! (Linux & Windows)

**Snort has three main use models;**

- **Sniffer Mode —** Read IP packets and prompt them in the console application.
- **Packet Logger Mode —** Log all IP packets (inbound and outbound) that visit the network.
- **NIDS (Network Intrusion Detection System) and NIPS (Network Intrusion Prevention System) Modes —** Log/drop the packets that are deemed as malicious according to the user-defined rules.

### Answer the questions below

Since the answers can be found above, I won’t be sharing them here. Follow along to help better locate them if you can’t find them.

**Which snort mode can help you stop the threats on a local machine?**

From the question, we are stopping threats, so we want to look at an IPS (Intrusion Prevention System). Scroll up to the IPS section, we see that there are four different types of IPS, read the bottom two. One of these holds the answer, also TryHackMe wants the acroymn of the name for the answer. Once you figure it out, highlight copy (ctrl + c) and paste (ctrl + v) or type, the answer in the TryHackMe answer field.

![](_resources/02%20Snort/0f76c02c14d21ab0a09393b4756d6166_MD5.jpg)

**Which snort mode can help you detect threats on a local network?**

From the question, we are detecting threats, so we want to look at an IDS (Intrusion Detection System). Scroll up to the IDS section, with the IDS section we only have two to look at. The one we are looking for works on a network. One of these holds the answer, also TryHackMe wants the acroymn of the name for the answer. Once you figure it out, highlight copy (ctrl + c) and paste (ctrl + v) or type, the answer in the TryHackMe answer field.

![](_resources/02%20Snort/183034437efe04df9795db39e29efd62_MD5.jpg)

**Which snort mode can help you detect the threats on a local machine?**

From the question, we are detecting threats, so we want to look at an IDS (Intrusion Detection System). Scroll up to the IDS section, with the IDS section we only have two to look at. The one we are looking for works on a single endpoint. One of these holds the answer, also TryHackMe wants the acroymn of the name for the answer. Once you figure it out, highlight copy (ctrl + c) and paste (ctrl + v) or type, the answer in the TryHackMe answer field.

![](_resources/02%20Snort/e1953b8c29e3caa21a27a5910cde7039_MD5.jpg)

**Which snort mode can help you stop the threats on a local network?**

From the question, we are stopping threats, so we want to look at an IPS (Intrusion Prevention System). Scroll up to the IPS section, we see that there are four different types of IPS, read the top two. We are looking for network traffic protection. One of these holds the answer, also TryHackMe wants the acroymn of the name for the answer. Once you figure it out, highlight copy (ctrl + c) and paste (ctrl + v) or type, the answer in the TryHackMe answer field.

![](_resources/02%20Snort/cbd5803a09ae304b448e4e51e7899ff0_MD5.jpg)

**Which snort mode works similar to NIPS mode?**

Scroll back up to the section you were just at, read the NIPS bullet point. After you have done reading, read the bullet point under it. You will found out it is quite similar. TryHackMe wants the acroymn of the name for the answer. Once you figure it out, highlight copy (ctrl + c) and paste (ctrl + v) or type, the answer in the TryHackMe answer field.

![](_resources/02%20Snort/dcfc16986fe8eb821fa51287cc1c60fc_MD5.jpg)

**According to the official description of the snort, what kind of NIPS is it?**

Reading through the qoute that TryHackMe gives on, look for network intrusion prevention system, this is NIPS. The word before network is the answer. Once you figure it out, highlight copy (ctrl + c) and paste (ctrl + v) or type, the answer in the TryHackMe answer field.

![](_resources/02%20Snort/0e1e84449393b8d23380fa91f28f2e21_MD5.jpg)

**NBA training period is also known as …**

Scroll up to the paragraph under the first two IDS, this is where you can find the answer to this question. Once you figure it out, highlight copy (ctrl + c) and paste (ctrl + v) or type, the answer in the TryHackMe answer field.

![](_resources/02%20Snort/50e943d9a7515a7b3af713bac22cb3ab_MD5.jpg)

# Task 4 First Interaction with Snort

**The First Interaction with Snort**

First, let’s verify snort is installed. The following command will show you the instance version.

version check

```
user@ubuntu$ snort -V  
   ,,_     -*> Snort! <*-  
  o"  )~   Version 2.9.7.0 GRE (Build XXXXXX)   
   ''''    By Martin Roesch & The Snort Team: http://www.snort.org/contact#team  
           Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.  
           Copyright (C) 1998-2013 Sourcefire, Inc., et al.  
           Using libpcap version 1.9.1 (with TPACKET_V3)  
           Using PCRE version: 8.39 2016-06-14  
           Using ZLIB version: 1.2.11
```

**Before getting your hands dirty, we should ensure our configuration file is valid.**

Here **“-T”** is used for testing configuration, and **“-c”** is identifying the configuration file **(snort.conf)**.  
Note that it is possible to use an additional configuration file by pointing it with **“-c”**.

configuration check

```
user@ubuntu$ sudo snort -c /etc/snort/snort.conf -T   
       --== Initializing Snort ==--  
Initializing Output Plugins!  
Initializing Preprocessors!  
Initializing Plug-ins!  
... [Output truncated]  
        --== Initialization Complete ==--  
   ,,_     -*> Snort! <*-  
  o"  )~   Version 2.9.7.0 GRE (Build XXXX)   
   ''''    By Martin Roesch & The Snort Team: http://www.snort.org/contact#team  
           Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.  
           Copyright (C) 1998-2013 Sourcefire, Inc., et al.  
           Using libpcap version 1.9.1 (with TPACKET_V3)  
           Using PCRE version: 8.39 2016-06-14  
           Using ZLIB version: 1.2.11  
           Rules Engine: SF_SNORT_DETECTION_ENGINE  Version 2.4    
           Preprocessor Object: SF_GTP  Version 1.1    
           Preprocessor Object: SF_SIP  Version 1.1    
           Preprocessor Object: SF_SSH  Version 1.1    
           Preprocessor Object: SF_SMTP  Version 1.1    
           Preprocessor Object: SF_POP  Version 1.0    
           Preprocessor Object: SF_DCERPC2  Version 1.0    
           Preprocessor Object: SF_IMAP  Version 1.0    
           Preprocessor Object: SF_DNP3  Version 1.1    
           Preprocessor Object: SF_SSLPP  Version 1.1    
           Preprocessor Object: SF_MODBUS  Version 1.1    
           Preprocessor Object: SF_SDF  Version 1.1    
           Preprocessor Object: SF_REPUTATION  Version 1.1    
           Preprocessor Object: SF_DNS  Version 1.1    
           Preprocessor Object: SF_FTPTELNET  Version 1.2    
... [Output truncated]  
Snort successfully validated the configuration!  
Snort exiting
```

Once we use a configuration file, snort got much more power! The configuration file is an all-in-one management file of the snort. Rules, plugins, detection mechanisms, default actions and output settings are identified here. It is possible to have multiple configuration files for different purposes and cases but can only use one at runtime.

Note that every time you start the Snort, it will automatically show the default banner and initial information about your setup. You can prevent this by using the “**-q”** parameter.

![](_resources/02%20Snort/c7d205239ece3a6c7149096eaf370d6f_MD5.jpg)

That was an easy one; let’s continue exploring snort modes!

### Answer the questions below

**Run the Snort instance and check the build number.**

Time to run some commands, let’s start with the one that TryHackMe first gave us for snort, snort -V .

![](_resources/02%20Snort/23c67513f7806e9cbd65ada1211903ca_MD5.jpg)

Looking through the information giving we can see we have the Build number!!! Once you find it, type the answer in the TryHackMe answer field, then click submit.

![](_resources/02%20Snort/aa47d64c8bcd3d194b7dd64eece63686_MD5.jpg)

Answer: 149

**Test the current instance with “/etc/snort/snort.conf” file and check how many rules are loaded with the current build.**

In this case we are going to run the second command given to us by TryHackMe, sudo snort -c /etc/snort/snort.conf -T . Then press enter to run it.

![](_resources/02%20Snort/35209d9c339467ac8b026b737b7e9956_MD5.jpg)

As before, we get quite the output, but we don’t see any number of rules here so time to start scrolling up.

![](_resources/02%20Snort/b2b16513c034eed015f924ecd29b4555_MD5.jpg)

Right before we get to the section where every line starts with Warning. We see a small section, the top line has a number then Snort rules read. The number at the front of this top line is the answer to the question. Once you find it, type the answer in the TryHackMe answer field, then click submit.

![](_resources/02%20Snort/9816f47f61135bd7c6d68e34fc6f05e7_MD5.jpg)

Answer: 4151

**Test the current instance with “/etc/snort/snortv2.conf” file and check how many rules are loaded with the current build.**

So we are going to run almost the same command as the previous question, but we need to change the config file. So the syntax is, sudo snort -c /etc/snort/snortv2.conf -T . Then press enter to run the command.

![](_resources/02%20Snort/93f4d8156d1d2aba4da46e01c1550658_MD5.jpg)

After it has finished running, scroll up to the section similar to where we found the answer to the previous question, to find the answer to this quesiton. Once you find it, type the answer in the TryHackMe answer field, then click submit.

![](_resources/02%20Snort/dca299e07ac5fe6443e4522a714b8824_MD5.jpg)

Answer: 1

# Task 5 Operation Mode 1: Sniffer Mode

![](_resources/02%20Snort/039da72bfcb3cd14b525aa8e4be0ca45_MD5.jpg)

**Let’s run Snort in Sniffer Mode**

Like tcpdump, Snort has various flags capable of viewing various data about the packet it is ingesting.

Sniffer mode parameters are explained in the table below;

![](_resources/02%20Snort/92fb5bb7cfc94fd70546d3b79650a287_MD5.jpg)

-**i**This parameter helps to define a specific network interface to listen/sniff. Once you have multiple interfaces, you can choose a specific interface to sniff.

Let’s start using each parameter and see the difference between them. Snort needs active traffic on your interface, so we need to generate traffic to see Snort in action.

To do this, use **the traffic-generator** script (find this in the Task-Exercise folder)

## Sniffing with parameter "-i"

Start the Snort instance in **verbose mode (-v)** and **use the interface (-i)** “eth0”; 

```
sudo snort -v-i eth0
```

In case you have only one interface, Snort uses it by default. The above example demonstrates to sniff on the interface named “eth0”. Once you simulate the parameter -v, you will notice it will automatically use the “eth0” interface and prompt it.

## Sniffing with parameter "-v"

Start the Snort instance in **verbose mode (-v)**; 

```
sudo snort -v
```

Now run the traffic-generator script as sudo and start **ICMP/HTTP traffic**. Once the traffic is generated, snort will start showing the packets in verbosity mode as follows;

sniffing with -v

```
user@ubuntu$ sudo snort -v  
                               
Running in packet dump mode  
        --== Initializing Snort ==--  
...  
Commencing packet processing (pid=64)  
12/01-20:10:13.846653 192.168.175.129:34316 -> 192.168.175.2:53  
UDP TTL:64 TOS:0x0 ID:23826 IpLen:20 DgmLen:64 DF  
Len: 36  
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+  
12/01-20:10:13.846794 192.168.175.129:38655 -> 192.168.175.2:53  
UDP TTL:64 TOS:0x0 ID:23827 IpLen:20 DgmLen:64 DF  
Len: 36  
===============================================================================  
Snort exiting
```

As you can see in the given output, verbosity mode provides tcpdump like output information. Once we interrupt the sniffing with CTRL+C, it stops and summarises the sniffed packets.

## Sniffing with parameter "-d"

Start the Snort instance in **dumping packet data mode (-d)**; 

```
sudo snort -d
```

Now run the traffic-generator script **as sudo** and start **ICMP/HTTP traffic**. Once the traffic is generated, snort will start showing the packets in verbosity mode as follows;

sniffing with -d

```
user@ubuntu$ sudo snort -d  
                               
Running in packet dump mode  
        --== Initializing Snort ==--  
...  
Commencing packet processing (pid=67)  
12/01-20:45:42.068675 192.168.175.129:37820 -> 192.168.175.2:53  
UDP TTL:64 TOS:0x0 ID:53099 IpLen:20 DgmLen:56 DF  
Len: 28  
99 A5 01 00 00 01 00 00 00 00 00 00 06 67 6F 6F  .............goo  
67 6C 65 03 63 6F 6D 00 00 1C 00 01              gle.com.....  
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+  
WARNING: No preprocessors configured for policy 0.  
12/01-20:45:42.070742 192.168.175.2:53 -> 192.168.175.129:44947  
UDP TTL:128 TOS:0x0 ID:63307 IpLen:20 DgmLen:72  
Len: 44  
FE 64 81 80 00 01 00 01 00 00 00 00 06 67 6F 6F  .d...........goo  
67 6C 65 03 63 6F 6D 00 00 01 00 01 C0 0C 00 01  gle.com.........  
00 01 00 00 00 05 00 04 D8 3A CE CE              .........:..  
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
```

As you can see in the given output, packet data payload mode covers the verbose mode and provides more data.

## Sniffing with parameter "-de"

Start the Snort instance in **dump (-d)** and **link-layer header grabbing (-e)** mode; 

```
snort -d -e
```

Now run the traffic-generator script **as sudo** and start **ICMP/HTTP traffic**. Once the traffic is generated, snort will start showing the packets in verbosity mode as follows;

sniffing with -de

```
user@ubuntu$ sudo snort -de  
                               
Running in packet dump mode  
        --== Initializing Snort ==--  
...  
Commencing packet processing (pid=70)  
12/01-20:55:26.958773 00:0C:29:A5:B7:A2 -> 00:50:56:E1:9B:9D type:0x800 len:0x46  
192.168.175.129:47395 -> 192.168.175.2:53 UDP TTL:64 TOS:0x0 ID:64294 IpLen:20 DgmLen:56 DF  
Len: 28  
6D 9C 01 00 00 01 00 00 00 00 00 00 06 67 6F 6F  m............goo  
67 6C 65 03 63 6F 6D 00 00 01 00 01              gle.com.....  
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+  
WARNING: No preprocessors configured for policy 0.  
12/01-20:55:26.965226 00:50:56:E1:9B:9D -> 00:0C:29:A5:B7:A2 type:0x800 len:0x56  
192.168.175.2:53 -> 192.168.175.129:47395 UDP TTL:128 TOS:0x0 ID:63346 IpLen:20 DgmLen:72  
Len: 44  
6D 9C 81 80 00 01 00 01 00 00 00 00 06 67 6F 6F  m............goo  
67 6C 65 03 63 6F 6D 00 00 01 00 01 C0 0C 00 01  gle.com.........  
00 01 00 00 00 05 00 04 D8 3A D6 8E              .........:..
```

## Sniffing with parameter "-X"

Start the Snort instance in **full packet dump mode (-X)**; 

```
sudo snort -X
```

Now run the traffic-generator script **as sudo** and start **ICMP/HTTP traffic**. Once the traffic is generated, snort will start showing the packets in verbosity mode as follows;

sniffing with -X

```
user@ubuntu$ sudo snort -X  
                               
Running in packet dump mode  
        --== Initializing Snort ==--  
...  
Commencing packet processing (pid=76)  
WARNING: No preprocessors configured for policy 0.  
12/01-21:07:56.806121 192.168.175.1:58626 -> 239.255.255.250:1900  
UDP TTL:1 TOS:0x0 ID:48861 IpLen:20 DgmLen:196  
Len: 168  
0x0000: 01 00 5E 7F FF FA 00 50 56 C0 00 08 08 00 45 00  ..^....PV.....E.  
0x0010: 00 C4 BE DD 00 00 01 11 9A A7 C0 A8 AF 01 EF FF  ................  
0x0020: FF FA E5 02 07 6C 00 B0 85 AE 4D 2D 53 45 41 52  .....l....M-SEAR  
0x0030: 43 48 20 2A 20 48 54 54 50 2F 31 2E 31 0D 0A 48  CH * HTTP/1.1..H  
0x0040: 4F 53 54 3A 20 32 33 39 2E 32 35 35 2E 32 35 35  OST: 239.255.255  
0x0050: 2E 32 35 30 3A 31 39 30 30 0D 0A 4D 41 4E 3A 20  .250:1900..MAN:   
0x0060: 22 73 73 64 70 3A 64 69 73 63 6F 76 65 72 22 0D  "ssdp:discover".  
0x0070: 0A 4D 58 3A 20 31 0D 0A 53 54 3A 20 75 72 6E 3A  .MX: 1..ST: urn:  
0x0080: 64 69 61 6C 2D 6D 75 6C 74 69 73 63 72 65 65 6E  dial-multiscreen  
0x0090: 2D 6F 72 67 3A 73 65 72 76 69 63 65 3A 64 69 61  -org:service:dia  
0x00A0: 6C 3A 31 0D 0A 55 53 45 52 2D 41 47 45 4E 54 3A  l:1..USER-AGENT:  
0x00B0: 20 43 68 72 6F 6D 69 75 6D 2F 39 35 2E 30 2E 34   Chromium/95.0.4  
0x00C0: 36 33 38 2E 36 39 20 57 69 6E 64 6F 77 73 0D 0A  638.69 Windows..  
0x00D0: 0D 0A                                            ..  
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+  
WARNING: No preprocessors configured for policy 0.  
12/01-21:07:57.624205 216.58.214.142 -> 192.168.175.129  
ICMP TTL:128 TOS:0x0 ID:63394 IpLen:20 DgmLen:84  
Type:0  Code:0  ID:15  Seq:1  ECHO REPLY  
0x0000: 00 0C 29 A5 B7 A2 00 50 56 E1 9B 9D 08 00 45 00  ..)....PV.....E.  
0x0010: 00 54 F7 A2 00 00 80 01 24 13 D8 3A D6 8E C0 A8  .T......$..:....  
0x0020: AF 81 00 00 BE B6 00 0F 00 01 2D E4 A7 61 00 00  ..........-..a..  
0x0030: 00 00 A4 20 09 00 00 00 00 00 10 11 12 13 14 15  ... ............  
0x0040: 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25  .......... !"#$%  
0x0050: 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35  &'()*+,-./012345  
0x0060: 36 37                                            67  
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
```

**Note that you can use the parameters both in combined and separated form as follows;**

- **snort -v**
- **snort -vd**
- **snort -de**
- **snort -v -d -e**
- **snort -X**

**Make sure you understand and practice each parameter with different types of traffic and discover your favourite combination.**

# Task 6 Operation Mode 2: Packet Logger Mode

![](_resources/02%20Snort/64ca8ae271354e9d7a121541b27d82d3_MD5.jpg)

## Let’s run Snort in Logger Mode

You can use Snort as a sniffer and log the sniffed packets via logger mode. You only need to use the packet logger mode parameters, and Snort does the rest to accomplish this.

Packet logger parameters are explained in the table below;

![](_resources/02%20Snort/3430cd6c17838f40b3082cce37d2b16c_MD5.jpeg)

Let’s start using each parameter and see the difference between them. Snort needs active traffic on your interface, so we need to generate traffic to see Snort in action.

## Logfile Ownership

Before generating logs and investigating them, we must remember the Linux file ownership and permissions. No need to deep dive into user types and permissions. The fundamental file ownership rule; **whoever creates a file becomes the owner of the corresponding file**.

Snort needs superuser (root) rights to sniff the traffic, so once you run the snort with the “sudo” command, the “root” account will own the generated log files. Therefore you will need “root” rights to investigate the log files. There are two different approaches to investigate the generated log files;

- Elevation of privileges — You can elevate your privileges to examine the files. You can use the “sudo” command to execute your command as a superuser with the following command `sudo command`. You can also elevate the session privileges and switch to the superuser account to examine the generated log files with the following command: `sudo su`
- Changing the ownership of files/directories — You can also change the ownership of the file/folder to read it as your user: `sudo chown username file` or `sudo chown username -R directory` The "-R" parameter helps recursively process the files and directories.

## Logging with parameter "-l"

First, start the Snort instance in packet logger mode; `sudo snort -dev -l .`

Now start ICMP/HTTP traffic with the traffic-generator script.

Once the traffic is generated, Snort will start showing the packets and log them in the target directory. You can configure the default output directory in snort.config file. However, you can use the “-l” parameter to set a target directory. Identifying the default log directory is useful for continuous monitoring operations, and the “-l” parameter is much more useful for testing purposes.

The `-l .` part of the command creates the logs in the current directory. You will need to use this option to have the logs for each exercise in their folder.

logging with -l

```
user@ubuntu$ sudo snort -dev -l .  
                               
Running in packet logging mode  
        --== Initializing Snort ==--  
Initializing Output Plugins!  
Log directory = /var/log/snort  
pcap DAQ configured to passive.  
Acquiring network traffic from "ens33".  
Decoding Ethernet  
        --== Initialization Complete ==--  
...  
Commencing packet processing (pid=2679)  
WARNING: No preprocessors configured for policy 0.  
WARNING: No preprocessors configured for policy 0.
```

Now, let’s check the generated log file. **Note that the log file names will be different in your case.**

checking the log file

```
user@ubuntu$ ls .  
                               
snort.log.1638459842
```

As you can see, it is a single all-in-one log file. It is a binary/tcpdump format log. This is what it looks like in the folder view.

![](_resources/02%20Snort/3b35ac39824be7c078ec13bc4ca00983_MD5.jpg)

## Logging with parameter "-K ASCII"

Start the Snort instance in packet logger mode; `sudo snort -dev -K ASCII`

Now run the traffic-generator script as sudo and start **ICMP/HTTP traffic**. Once the traffic is generated, Snort will start showing the packets in verbosity mode as follows;

logging with -K ASCII

```
user@ubuntu$ sudo snort -dev -K ASCII -l .  
                               
Running in packet logging mode  
        --== Initializing Snort ==--  
Initializing Output Plugins!  
Log directory = /var/log/snort  
pcap DAQ configured to passive.  
Acquiring network traffic from "ens33".  
Decoding Ethernet  
        --== Initialization Complete ==--  
...  
Commencing packet processing (pid=2679)  
WARNING: No preprocessors configured for policy 0.  
WARNING: No preprocessors configured for policy 0.
```

Now, let’s check the generated log file.

Checking the log file

```
user@ubuntu$ ls .  
                               
142.250.187.110  192.168.175.129  snort.log.1638459842
```

This is what it looks like in the folder view.

![](_resources/02%20Snort/7ce23413f884cabbfc0d2401e98bdab4_MD5.jpeg)

The logs created with “-K ASCII” parameter is entirely different. There are two folders with IP address names. Let’s look into them.

checking the log file

```
user@ubuntu$ ls ./192.168.175.129/  
                               
ICMP_ECHO  UDP:36648-53  UDP:40757-53  UDP:47404-53  UDP:50624-123
```

Once we look closer at the created folders, we can see that the logs are in ASCII and categorised format, so it is possible to read them without using a Snort instance.

This is what it looks like in the folder view.

![](_resources/02%20Snort/26a30a39c8411a95ecd1da9af25ca7fa_MD5.jpg)

In a nutshell, ASCII mode provides multiple files in human-readable format, so it is possible to read the logs easily by using a text editor. By contrast with ASCII format, binary format is not human-readable and requires analysis using Snort or an application like tcpdump.

Let’s compare the ASCII format with the binary format by opening both of them in a text editor. The difference between the binary log file and the ASCII log file is shown below. (Left side: binary format. Right side: ASCII format).

![](_resources/02%20Snort/c1f87b629e15710452b36bfaf2b59aff_MD5.jpg)

## Reading generated logs with parameter "-r"

Start the Snort instance in packet reader mode; `sudo snort -r`

reading log files with -r

```
user@ubuntu$ sudo snort -r snort.log.1638459842  
                               
Running in packet dump mode  
        --== Initializing Snort ==--  
Initializing Output Plugins!  
pcap DAQ configured to read-file.  
Acquiring network traffic from "snort.log.1638459842".  
        --== Initialization Complete ==--  
...  
Commencing packet processing (pid=3012)  
WARNING: No preprocessors configured for policy 0.  
12/02-07:44:03.123225 192.168.175.129 -> 142.250.187.110  
ICMP TTL:64 TOS:0x0 ID:41900 IpLen:20 DgmLen:84 DF  
Type:8  Code:0  ID:1   Seq:49  ECHO  
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+  
WARNING: No preprocessors configured for policy 0.  
12/02-07:44:26.169620 192.168.175.129 -> 142.250.187.110  
ICMP TTL:64 TOS:0x0 ID:44765 IpLen:20 DgmLen:84 DF  
Type:8  Code:0  ID:1   Seq:72  ECHO  
===============================================================================  
Packet I/O Totals:  
   Received:           51  
   Analyzed:           51 (100.000%)  
    Dropped:            0 (  0.000%)  
   Filtered:            0 (  0.000%)  
Outstanding:            0 (  0.000%)  
   Injected:            0  
===============================================================================  
Breakdown by protocol (includes rebuilt packets):  
...  
      Total:           51  
===============================================================================  
Snort exiting
```

**Note that** Snort can read and handle the binary like output (tcpdump and Wireshark also can handle this log format). However, if you create logs with “-K ASCII” parameter, Snort will not read them. As you can see in the above output, Snort read and displayed the log file just like in the sniffer mode.

Opening log file with tcpdump.

Opening the log file with tcpdump

```
user@ubuntu$ sudo tcpdump -r snort.log.1638459842 -ntc 10  
                               
reading from file snort.log.1638459842, link-type EN10MB (Ethernet)  
IP 192.168.175.129 > 142.250.187.110: ICMP echo request, id 1, seq 49, length 64  
IP 142.250.187.110 > 192.168.175.129: ICMP echo reply, id 1, seq 49, length 64  
IP 192.168.175.129 > 142.250.187.110: ICMP echo request, id 1, seq 50, length 64  
IP 142.250.187.110 > 192.168.175.129: ICMP echo reply, id 1, seq 50, length 64  
IP 192.168.175.129 > 142.250.187.110: ICMP echo request, id 1, seq 51, length 64  
IP 142.250.187.110 > 192.168.175.129: ICMP echo reply, id 1, seq 51, length 64  
IP 192.168.175.129 > 142.250.187.110: ICMP echo request, id 1, seq 52, length 64  
IP 142.250.187.110 > 192.168.175.129: ICMP echo reply, id 1, seq 52, length 64  
IP 192.168.175.1.63096 > 239.255.255.250.1900: UDP, length 173  
IP 192.168.175.129 > 142.250.187.110: ICMP echo request, id 1, seq 53, length 64
```
Opening log file with Wireshark.

![](_resources/02%20Snort/ddad76594584521463ed689e8280d104_MD5.jpg)

**"-r" parameter also allows users to filter the binary log files. You can filter the processed log to see specific packets with the “-r” parameter and Berkeley Packet Filters (BPF).**

- `sudo snort -r logname.log -X`
- `sudo snort -r logname.log icmp`
- `sudo snort -r logname.log tcp`
- `sudo snort -r logname.log 'udp and port 53'`

The output will be the same as the above, but only packets with the chosen protocol will be shown. Additionally, you can specify the number of processes with the parameter “-n”. **The following command will process only the first 10 packets:**

`snort -dvr logname.log -n 10`

Please use the following resources to understand how the BPF works and its use.

- [https://en.wikipedia.org/wiki/Berkeley_Packet_Filter](https://en.wikipedia.org/wiki/Berkeley_Packet_Filter)
- [https://biot.com/capstats/bpf.html](https://biot.com/capstats/bpf.html)
- [https://www.tcpdump.org/manpages/tcpdump.1.html](https://www.tcpdump.org/manpages/tcpdump.1.html)

**Now, use the attached VM and navigate to the Task-Exercises/Exercise-Files/TASK-6 folder to answer the questions!**

### Answer the questions below

Investigate the traffic with the default configuration file **with ASCII mode.**

`sudo snort -dev -K ASCII -l .`

Execute the traffic generator script and choose **“TASK-6 Exercise”**. Wait until the traffic ends, then stop the Snort instance. Now analyse the output summary and answer the question.

`sudo ./traffic-generator.sh`

In another terminal that you’ve been running the traffic-generator, type out the command above and press enter to run it.

![](_resources/02%20Snort/d9a468c86f7da4cceb6a79c646161bd5_MD5.jpg)

A window will pop-up, you want to click on the TASK-6 Exercise.

![](_resources/02%20Snort/cf9d4daf159ce75e1885ba464db40136_MD5.jpg)

Go back to your, and press enter to run Snort.

![](_resources/02%20Snort/afc956b5e3e9fdad16471db8761a532f_MD5.jpg)

While Snort is running, go back to the Traffic generator and click the OK button in the bottom right.

![](_resources/02%20Snort/b7da288bec46bac3a2ff39c7fa773ac2_MD5.jpg)

Once the Traffic Generator is done running, press `ctrl c` to stop Snort. Once stop you are ready to start answering the question.

![](_resources/02%20Snort/6634822db648c6f3bfde18c0658bd7b3_MD5.jpg)

**Now, you should have the logs in the current directory. Navigate to folder “145.254.160.237”. What is the source port used to connect port 53?**

Before we change move into the directory we have to change into a superuser, to do this use the command `sudo su` .

![](_resources/02%20Snort/6fa3199c7b91517aa30c0b63ebe579eb_MD5.jpg)

Change directory with `cd 145.254.160.237/` .

![](_resources/02%20Snort/732bbe4b6f0f814217b99488ff5634bd_MD5.jpg)

Now that we are in the directory let’s look to see what is in this directory with `ls` .

![](_resources/02%20Snort/ae7963d026ed171404ca33941b7c7e3c_MD5.jpg)

We can see inside the directory that we have three logs, one of which deals with port 53. Once you find it, type the answer into the TryHackMe Answer field, then click submit.

![](_resources/02%20Snort/44a7fa8b41c86e3dce79f508d40227d2_MD5.jpg)

Answer: 3009

Use **snort.log.1640048004**

Go head back to the terminal that you were doing the Traffic Generator in. Running `ls` through the directories we can see where the snort.log.1640048004 is located.

![](_resources/02%20Snort/f162a6f219c28c302eed8b7bd6444f65_MD5.jpg)

Now it is time to change directories over to the directory that holds the log file with `cd Exercise-Files/TASK-6/` .

![](_resources/02%20Snort/9d9263617cb0dbb7bc1cc6dbc71f77ba_MD5.jpg)

Now you are ready to start running the next commands, and answering the next questions.

**Read the snort.log file with Snort; what is the IP ID of the 10th packet?**

`snort -r snort.log.1640048004 -n 10`

Run the command above execpt we need to add sudo, `sudo snort -r snort.log.1640048004 -n 10` . Press enter to run, and have snort read the log.

![](_resources/02%20Snort/a01a16e5789c01557854785d928139c5_MD5.jpg)

Scroll up till you reach the last packet. If you look at the third row of the packet you will see ID:, the number after is the answer. Once you find it, type the answer into the TryHackMe Answer field, then click submit.

![](_resources/02%20Snort/6c84d0fb907d0a6324cb8235b2e6cb85_MD5.jpg)

Answer: 49313

**Read the “snort.log.1640048004” file with Snort; what is the referer of the 4th packet?**

Let’s run the command again only this time we are going to add the -X parameter to it to display the details. So the command is `sudo snort -r snort.log.1640048004 -X -n 10` .

![](_resources/02%20Snort/38b7fcba89d7e861988e9d75d0eb2fe4_MD5.jpg)

Scroll down to the 4th output, once there we see a long line of hex. But we can see some readable text on the right, if you look down at the bottom of this readable text you will find Referer:, the answer is right after this. Once you find it, type the answer into the TryHackMe Answer field, then click submit.

![](_resources/02%20Snort/41f60d213673b5d094c59c64737f18cf_MD5.jpg)

Answer: [http://www.ethereal.com/development.html](http://www.ethereal.com/development.html)

**Read the “snort.log.1640048004” file with Snort; what is the Ack number of the 8th packet?**

So scroll down till you reach packet 8 or what I did was got to packet 10 and scrolled up till I reached packet 8. But once you are there, look in the 4th row, you will see Ack:, the hex value is the answer. Once you find it, type the answer into the TryHackMe Answer field, then click submit.

![](_resources/02%20Snort/98f1e4423cba221dc0c127f31eb9f064_MD5.jpg)

Answer: 0x38AFFFF3

**Read the “snort.log.1640048004” file with Snort; what is the number of the “TCP port 80” packets?**

Time to modify the syntax a bit and run snort again, this time it should be `sudo snort -r snort.log.1640048004 'tcp port 80'` . Once you have this typed into the terminal press enter to run it.

![](_resources/02%20Snort/5ac875019439a688c07f8d80b1855e81_MD5.jpg)

When it is done running, the answer will be at the bottom in the Total row. Once you find it, type the answer into the TryHackMe Answer field, then click submit.

![](_resources/02%20Snort/9299b8871621acc4234745ee4be5cba0_MD5.jpg)

Answer: 41

# Task 7 Operation Mode 3: IDS/IPS

![](_resources/02%20Snort/6dac08fafe5c4fcc6341c7ece6e58975_MD5.jpg)

## Snort in IDS/IPS Mode

Capabilities of Snort are not limited to sniffing and logging the traffic. IDS/IPS mode helps you manage the traffic according to user-defined rules.

**Note that** (N)IDS/IPS mode depends on the rules and configuration. **TASK-10** summarises the essential paths, files and variables. Also, **TASK-3** covers configuration testing. Here, we need to understand the operating logic first, and then we will be going into rules in **TASK-9**.

## Let’s run Snort in IDS/IPS Mode

NIDS mode parameters are explained in the table below;

![](_resources/02%20Snort/4ee1b7836d1d416ff5ceefd5d95834c2_MD5.jpg)

Let’s start using each parameter and see the difference between them. Snort needs active traffic on your interface, so we need to generate traffic to see Snort in action. To do this, use **the traffic-generator** script and sniff the traffic.

**Once you start running IDS/IPS mode,** you need to use rules. As we mentioned earlier, we will use a pre-defined ICMP rule as an example. The defined rule will only generate alerts in any direction of ICMP packet activity.

```
alert icmp any any <> any any (msg: "ICMP Packet Found"; sid: 100001; rev:1;)
```

This rule is located in **“/etc/snort/rules/local.rules”**.

Remember, in this module, we will focus only on the operating modes. The rules are covered in TASK9&10. **Snort will create an “alert” file if the traffic flow triggers an alert. One last note;** once you start running IPS/IDS mode, the sniffing and logging mode will be semi-passive. However, you can activate the functions using the parameters discussed in previous tasks. **(-i, -v, -d, -e, -X, -l, -K ASCII)** If you don’t remember the purpose of these commands, **please revisit TASK4**.

**IDS/IPS mode with parameter “-c and -T”**

Start the Snort instance and test the configuration file. `sudo snort -c /etc/snort/snort.conf -T` This command will check your configuration file and prompt it if there is any misconfiguratioın in your current setting. You should be familiar with this command if you covered TASK3. If you don't remember the output of this command, **please revisit TASK4**.

## IDS/IPS mode with parameter "-N"

Start the Snort instance and disable logging by running the following command: `sudo snort -c /etc/snort/snort.conf -N`

Now run the traffic-generator script **as sudo** and start **ICMP/HTTP traffic**. This command will disable logging mode. The rest of the other functions will still be available (if activated).

The command-line output will provide the information requested with the parameters. So, if you activate **verbosity (-v)** or **full packet dump (-X)** you will still have the output in the console, but there will be no logs in the log folder.

## IDS/IPS mode with parameter "-D"

Start the Snort instance in background mode with the following command: `sudo snort -c /etc/snort/snort.conf -D`

Now run the traffic-generator script **as sudo** and start **ICMP/HTTP traffic**. Once the traffic is generated, snort will start processing the packets and accomplish the given task with additional parameters.

running in background mode

```
user@ubuntu$ sudo snort -c /etc/snort/snort.conf -D  

Spawning daemon child...  
My daemon child 2898 lives...  
Daemon parent exiting (0)
```

The command-line output will provide the information requested with the parameters. So, if you activate **verbosity (-v)** or **full packet dump (-X)** with **packet logger mode (-l)** you will still have the logs in the logs folder, but there will be no output in the console.

Once you start the background mode and want to check the corresponding process, you can easily use the “ps” command as shown below;

running in background mode

```
user@ubuntu$ ps -ef | grep snort  
root        2898    1706  0 05:53 ?        00:00:00 snort -c /etc/snort/snort.conf -D
```

If you want to stop the daemon, you can easily use the “kill” command to stop the process.

running in background mode

```
user@ubuntu$ sudo kill -9 2898
```

**Note that** daemon mode is mainly used to automate the Snort. This parameter is mainly used in scripts to start the Snort service in the background. It is not recommended to use this mode unless you have a working knowledge of Snort and stable configuration.

## IDS/IPS mode with parameter "-A"

**Remember that there are several alert modes available in snort;**

- **console:** Provides fast style alerts on the console screen.
- **cmg:** Provides basic header details with payload in hex and text format.
- **full:** Full alert mode, providing all possible information about the alert.
- **fast:** Fast mode, shows the alert message, timestamp, source and destination ıp along with port numbers.
- **none:** Disabling alerting.

In this section, only the **“console”** and **“cmg”** parameters provide alert information in the console. It is impossible to identify the difference between the rest of the alert modes via terminal. Differences can be identified by looking at generated logs.

At the end of this section, we will compare the “full”, “fast” and “none” modes. Remember that these parameters don’t provide console output, so we will continue to identify the differences through log formats.

## IDS/IPS mode with parameter "-A console"

Console mode provides fast style alerts on the console screen. Start the Snort instance in **console alert mode (-A console ) with the following command** `sudo snort -c /etc/snort/snort.conf -A console`

Now run the traffic-generator script **as sudo** and start **ICMP/HTTP traffic**. Once the traffic is generated, snort will start generating alerts according to provided ruleset defined in the configuration file.

running in console alert mode

```
user@ubuntu$ sudo snort -c /etc/snort/snort.conf -A console  
Running in IDS mode  
        --== Initializing Snort ==--  
Initializing Output Plugins!  
Initializing Preprocessors!  
Initializing Plug-ins!  
Parsing Rules file "/etc/snort/snort.conf"  
...  
Commencing packet processing (pid=3743)  
12/12-02:08:27.577495  [**] [1:366:7] ICMP PING *NIX [**] [Classification: Misc activity] [Priority: 3] {ICMP} 192.168.175.129 -> 142.250.187.110  
12/12-02:08:27.577495  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110  
12/12-02:08:27.577495  [**] [1:384:5] ICMP PING [**] [Classification: Misc activity] [Priority: 3] {ICMP} 192.168.175.129 -> 142.250.187.110  
12/12-02:08:27.609719  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129  
^C*** Caught Int-Signal  
12/12-02:08:29.595898  [**] [1:366:7] ICMP PING *NIX [**] [Classification: Misc activity] [Priority: 3] {ICMP} 192.168.175.129 -> 142.250.187.110  
12/12-02:08:29.595898  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110  
12/12-02:08:29.595898  [**] [1:384:5] ICMP PING [**] [Classification: Misc activity] [Priority: 3] {ICMP} 192.168.175.129 -> 142.250.187.110  
===============================================================================  
Run time for packet processing was 26.25844 seconds  
Snort processed 88 packets.
```

## IDS/IPS mode with parameter "-A cmg"

Cmg mode provides basic header details with payload in hex and text format. Start the Snort instance in **cmg alert mode (-A cmg ) with the following command** `sudo snort -c /etc/snort/snort.conf -A cmg`

Now run the traffic-generator script **as sudo** and start **ICMP/HTTP traffic**. Once the traffic is generated, snort will start generating alerts according to provided ruleset defined in the configuration file.

running in cmg alert mode

```
user@ubuntu$ sudo snort -c /etc/snort/snort.conf -A cmg  
Running in IDS mode  
        --== Initializing Snort ==--  
Initializing Output Plugins!  
Initializing Preprocessors!  
Initializing Plug-ins!  
Parsing Rules file "/etc/snort/snort.conf"  
...  
Commencing packet processing (pid=3743)  
12/12-02:23:56.944351  [**] [1:366:7] ICMP PING *NIX [**] [Classification: Misc activity] [Priority: 3] {ICMP} 192.168.175.129 -> 142.250.187.110  
12/12-02:23:56.944351 00:0C:29:A5:B7:A2 -> 00:50:56:E1:9B:9D type:0x800 len:0x62  
192.168.175.129 -> 142.250.187.110 ICMP TTL:64 TOS:0x0 ID:10393 IpLen:20 DgmLen:84 DF  
Type:8  Code:0  ID:4   Seq:1  ECHO  
BC CD B5 61 00 00 00 00 CE 68 0E 00 00 00 00 00  ...a.....h......  
10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F  ................  
20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F   !"#$%&'()*+,-./  
30 31 32 33 34 35 36 37                          01234567  
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
```

**Let’s compare the console and cmg outputs** before moving on to other alarm types. As you can see in the given outputs above, **console mode** provides basic header and rule information. **Cmg mode** provides full packet details along with rule information.

## IDS/IPS mode with parameter "-A fast"

Fast mode provides alert messages, timestamps, and source and destination IP addresses. **Remember, there is no console output in this mode.** Start the Snort instance in **fast alert mode (-A fast ) with the following command** `sudo snort -c /etc/snort/snort.conf -A fast`

Now run the traffic-generator script **as sudo** and start **ICMP/HTTP traffic**. Once the traffic is generated, snort will start generating alerts according to provided ruleset defined in the configuration file.

running in fast alert mode

```
user@ubuntu$ sudo snort -c /etc/snort/snort.conf -A fast  
Running in IDS mode  
        --== Initializing Snort ==--  
Initializing Output Plugins!  
Initializing Preprocessors!  
Initializing Plug-ins!  
Parsing Rules file "/etc/snort/snort.conf"  
...  
Commencing packet processing (pid=3743)  
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
```

Let’s check the alarm file;

![](_resources/02%20Snort/2b8247de0f394a392522707905fa8140_MD5.jpg)

As you can see in the given picture above, fast style alerts contain summary information on the action like direction and alert header.

## IDS/IPS mode with parameter "-A full"

Full alert mode provides all possible information about the alert. **Remember, there is no console output in this mode.** Start the Snort instance in **full alert mode (-A full ) with the following command** `sudo snort -c /etc/snort/snort.conf -A full`

Now run the traffic-generator script **as sudo** and start **ICMP/HTTP traffic**. Once the traffic is generated, snort will start generating alerts according to provided ruleset defined in the configuration file.

running in full alert mode

```
user@ubuntu$ sudo snort -c /etc/snort/snort.conf -A full  
Running in IDS mode  
        --== Initializing Snort ==--  
Initializing Output Plugins!  
Initializing Preprocessors!  
Initializing Plug-ins!  
Parsing Rules file "/etc/snort/snort.conf"  
...  
Commencing packet processing (pid=3744)  
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
```

Let’s check the alarm file;

![](_resources/02%20Snort/2c84ac416557a5f9f1a47b25c309b969_MD5.jpg)

As you can see in the given picture above, full style alerts contain all possible information on the action.

## IDS/IPS mode with parameter "-A none"

Disable alerting. This mode doesn’t create the alert file. However, it still logs the traffic and creates a log file in binary dump format. **Remember, there is no console output in this mode.** Start the Snort instance in **none alert mode (-A none) with the following command** `sudo snort -c /etc/snort/snort.conf -A none`

Now run the traffic-generator script **as sudo** and start **ICMP/HTTP traffic**. Once the traffic is generated, snort will start generating alerts according to provided ruleset defined in the configuration file.

running in none alert mode

```
user@ubuntu$ sudo snort -c /etc/snort/snort.conf -A none  
Running in IDS mode  
        --== Initializing Snort ==--  
Initializing Output Plugins!  
Initializing Preprocessors!  
Initializing Plug-ins!  
Parsing Rules file "/etc/snort/snort.conf"  
...  
Commencing packet processing (pid=3745)  
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
```

As you can see in the picture below, there is no alert file. Snort only generated the log file.

![](_resources/02%20Snort/12513f42b11e30e38d70671ee9f857c7_MD5.jpg)

## IDS/IPS mode: "Using rule file without configuration file"

It is possible to run the Snort only with rules without a configuration file. Running the Snort in this mode will help you test the user-created rules. However, this mode will provide less performance.

running without configuration file

```
user@ubuntu$ sudo snort -c /etc/snort/rules/local.rules -A console  
Running in IDS mode  
12/12-12:13:29.167955  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110  
12/12-12:13:29.200543  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129  
12/12-12:13:30.169785  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110  
12/12-12:13:30.201470  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129  
12/12-12:13:31.172101  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110  
^C*** Caught Int-Signal
```

## IPS mode and dropping packets

Snort IPS mode activated with **-Q — daq afpacket** parameters. You can also activate this mode by editing snort.conf file. However, you don’t need to edit snort.conf file in the scope of this room. Review the bonus task or snort manual for further information on daq and advanced configuration settings: `-Q --daq afpacket`

Activate the Data Acquisition (DAQ) modules and use the afpacket module to use snort as an IPS: `-i eth0:eth1`

Identifying interfaces note that Snort IPS require at least two interfaces to work. Now run the traffic-generator script **as sudo** and start **ICMP/HTTP traffic**.

running IPS mode

```
user@ubuntu$ sudo snort -c /etc/snort/snort.conf -q -Q --daq afpacket -i eth0:eth1 -A console  
Running in IPS mode  
12/18-07:40:01.527100  [Drop] [**] [1:1000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.131 -> 192.168.175.2  
12/18-07:40:01.552811  [Drop] [**] [1:1000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 172.217.169.142 -> 192.168.1.18  
12/18-07:40:01.566232  [Drop] [**] [1:1000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.131 -> 192.168.175.2  
12/18-07:40:02.517903  [Drop] [**] [1:1000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.1.18 -> 172.217.169.142  
12/18-07:40:02.550844  [Drop] [**] [1:1000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 172.217.169.142 -> 192.168.1.18  
^C*** Caught Int-Signal
```

As you can see in the picture above, Snort blocked the packets this time. **We used the same rule with a different action (drop/reject).** Remember, for the scope of this task; our point is the operating mode, not the rule.

### Answer the questions below

Investigate the traffic with the default configuration file.

```
sudo snort -c /etc/snort/snort.conf -A full -l .
```

Execute the traffic generator script and choose **“TASK-7 Exercise”**. Wait until the traffic stops, then stop the Snort instance. Now analyse the output summary and answer the question.

`sudo ./traffic-generator.sh`

**What is the number of the detected HTTP GET methods?**

Head back to the terminal that your running Snort in. After the scan is complete, scroll up till you get to the HTTP Inspect section. Once you are at this section, which is close to the bottom, look for the GET methods, the answer can be found in this row. Once you find it, type the answer into the TryHackMe Answer field, then click submit.

![](_resources/02%20Snort/fabcd489b2f3adb577360c436f85e2c9_MD5.jpg)

Answer: 2

# Task 8 Operation Mode 4: PCAP Investigation

![](_resources/02%20Snort/aa5206b698c414c98360902361a28d65_MD5.jpg)

## Let’s investigate PCAPs with Snort

Capabilities of Snort are not limited to sniffing, logging and detecting/preventing the threats. PCAP read/investigate mode helps you work with pcap files. Once you have a pcap file and process it with Snort, you will receive default traffic statistics with alerts depending on your ruleset.

Reading a pcap without using any additional parameters we discussed before will only overview the packets and provide statistics about the file. In most cases, this is not very handy. We are investigating the pcap with Snort to benefit from the rules and speed up our investigation process by using the known patterns of threats.

**Note that** we are pretty close to starting to create rules. Therefore, you need to grasp the working mechanism of the Snort, learn the discussed parameters and begin combining the parameters for different purposes.

PCAP mode parameters are explained in the table below;

![](_resources/02%20Snort/c21a66df32a73f635b15670b311719d8_MD5.jpeg)

## Investigating single PCAP with parameter "-r"

For test purposes, you can still test the default reading option with pcap by using the following command 

```
snort -r icmp-test.pcap
```

Let’s investigate the pcap with our configuration file and see what will happen. 

```
sudo snort -c /etc/snort/snort.conf -q -r icmp-test.pcap -A console -n 10
```

If you don’t remember the purpose of the parameters in the given command, please revisit previous tasks and come back again!

investigating single pcap file

```
user@ubuntu$ sudo snort -c /etc/snort/snort.conf -q -r icmp-test.pcap -A console -n 10  
12/12-12:13:29.167955  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110  
12/12-12:13:29.200543  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129  
12/12-12:13:30.169785  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110  
12/12-12:13:30.201470  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129  
12/12-12:13:31.172101  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110  
12/12-12:13:31.204104  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129  
12/12-12:13:32.174106  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110  
12/12-12:13:32.208683  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129  
12/12-12:13:33.176920  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110  
12/12-12:13:33.208359  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129
```

Our ICMP rule got a hit! As you can see in the given output, snort identified the traffic and prompted the alerts according to our ruleset.

## Investigating multiple PCAPs with parameter "--pcap-list"

Let’s investigate multiple pcaps with our configuration file and see what will happen. 

```
sudo snort -c /etc/snort/snort.conf -q --pcap-list="icmp-test.pcap http2.pcap" -A console -n 10
```

investigating multiple pcap files

```
user@ubuntu$ sudo snort -c /etc/snort/snort.conf -q --pcap-list="icmp-test.pcap http2.pcap" -A console  
12/12-12:13:29.167955  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110  
12/12-12:13:29.200543  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129  
12/12-12:13:30.169785  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110  
12/12-12:13:30.201470  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129  
12/12-12:13:31.172101  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110  
...  
12/12-12:13:31.204104  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129  
12/12-12:13:32.174106  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110  
12/12-12:13:32.208683  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129  
12/12-12:13:33.176920  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110  
12/12-12:13:33.208359  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129
```

Our ICMP rule got a hit! As you can see in the given output, snort identified the traffic and prompted the alerts according to our ruleset.

**Here is one point to notice:** we’ve processed two pcaps, and there are lots of alerts, so it is impossible to match the alerts with provided pcaps without snort’s help. We need to separate the pcap process to identify the source of the alerts.

## Investigating multiple PCAPs with parameter "--pcap-show"

Let’s investigate multiple pcaps, distinguish each one, and see what will happen. 

```
sudo snort -c /etc/snort/snort.conf -q --pcap-list="icmp-test.pcap http2.pcap" -A console --pcap-show
```

investigating multiple pcap files wth pcap info

```
user@ubuntu$ sudo snort -c /etc/snort/snort.conf -q --pcap-list="icmp-test.pcap http2.pcap" -A console --pcap-show   
Reading network traffic from "icmp-test.pcap" with snaplen = 1514  
12/12-12:13:29.167955  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110  
12/12-12:13:29.200543  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129  
12/12-12:13:30.169785  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110  
...Reading network traffic from "http2.pcap" with snaplen = 1514  
12/12-12:13:35.213176  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129  
12/12-12:13:36.182950  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110  
12/12-12:13:38.223470  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129  
...
```

Our ICMP rule got a hit! As you can see in the given output, snort identified the traffic, distinguished each pcap file and prompted the alerts according to our ruleset.

Now, use the attached VM and navigate to the Task-Exercises/Exercise-Files/TASK-8 folder to answer the questions!

### Answer the questions below

Investigate the **mx-1.pcap** file with the default configuration file.

```
sudo snort -c /etc/snort/snort.conf -A full -l . -r mx-1.pcap
```

**What is the number of the generated alerts?**

Once Snort is done running we need to find how many alerts were generated. Scroll up till you see a section with Action Stats, this is the section with the number of Alerts. Look to the number on the right, in the Alerts column, this is the answer. Once you find it, type the answer into the TryHackMe Answer field, then click submit.

![](_resources/02%20Snort/ca00ce61caf33eacade8bdfbfe307926_MD5.jpg)

Answer: 170

**Keep reading the output. How many TCP Segments are Queued?**

Scroll two sections down, you will see Stream Statistics. In this section you will find the TCP Segments Queued, look to the number to the right and you will find the answer. Once you find it, type the answer into the TryHackMe Answer field, then click submit.

![](_resources/02%20Snort/a8fbe0084dbff40296c8a7c4b264af2e_MD5.jpg)

Answer: 18

**Keep reading the output.How many “HTTP response headers” were extracted?**

Scroll down to the next section under the Stream Statistics, which will be the HTTP Inspect. In this section you will find the HTTP response Headers extracted, look to the number to the right and you will find the answer. Once you find it, type the answer into the TryHackMe Answer field, then click submit.

![](_resources/02%20Snort/cb81345884dce00ad4e17d82206487c6_MD5.jpg)

Answer: 3

Investigate the **mx-1.pcap** file **with the second** configuration file.

```
sudo snort -c /etc/snort/snortv2.conf -A full -l . -r mx-1.pcap
```

Type into the terminal the command above, then press enter to run it.

![](_resources/02%20Snort/ba61c3967779a49dc7a100829e124cd9_MD5.jpg)

**What is the number of the generated alerts?**

Like before scroll up to the Action Stats section, once you are there look for Alerts. When you find it, look to the number on the right this is the answer. Once you find it, type the answer into the TryHackMe Answer field, then click submit.

![](_resources/02%20Snort/890ca3419caab3fbe6965f97aea71705_MD5.jpg)

Answer: 68

Investigate the **mx-2.pcap** file with the default configuration file.

```
sudo snort -c /etc/snort/snort.conf -A full -l . -r mx-2.pcap
```

Type into the terminal the command above, then press enter to run it.

![](_resources/02%20Snort/12d4fc7eac98f6ea219cc6e2c92ee39f_MD5.jpg)

**What is the number of the generated alerts?**

Like before scroll up to the Action Stats section, once you are there look for Alerts. When you find it, look to the number on the right this is the answer. Once you find it, type the answer into the TryHackMe Answer field, then click submit.

![](_resources/02%20Snort/ec780e4143a8a6e396073b639dbd8793_MD5.jpg)

Answer: 340

**Keep reading the output. What is the number of the detected TCP packets?**

Scroll up to the next section, Breakdown by Protocol. Look for TCP, then look for the number on the right, this is the answer. Once you find it, type the answer into the TryHackMe Answer field, then click submit.

![](_resources/02%20Snort/a69e55f9bc54a5583ef858932931da94_MD5.jpg)

Answer: 82

Investigate the **mx-2.pcap and mx-3.pcap** files with the default configuration file.

```
sudo snort -c /etc/snort/snort.conf -A full -l . --pcap-list="mx-2.pcap mx-3.pcap"
```

Type into the terminal the command above, then press enter to run it.

![](_resources/02%20Snort/1c14eb63bdb050d415495efff6f4e163_MD5.jpg)

**What is the number of the generated alerts?**

For the last time, scroll up to the Action Stats section, once you are there look for Alerts. When you find it, look to the number on the right this is the answer. Once you find it, type the answer into the TryHackMe Answer field, then click submit.

![](_resources/02%20Snort/ba04bf9cbdd67f32cc52b2a8a26e95c5_MD5.jpg)

Answer: 1020

# Task 9 Snort Rule Structure

![](_resources/02%20Snort/02d9506343af3aecbc874855e25e79a5_MD5.jpg)

**Let’s Learn Snort Rules!**

Understanding the Snort rule format is essential for any blue and purple teamer. The primary structure of the snort rule is shown below;

![](_resources/02%20Snort/2ffa9215e83bbed9c1190d79266448cb_MD5.jpg)

Each rule should have a type of action, protocol, source and destination IP, source and destination port and an option. Remember, Snort is in passive mode by default. So most of the time, you will use Snort as an IDS. You will need to start **“inline mode” to turn on IPS mode.** But before you start playing with inline mode, you should be familiar with Snort features and rules.

The Snort rule structure is easy to understand but difficult to produce. You should be familiar with rule options and related details to create efficient rules. It is recommended to practice Snort rules and option details for different use cases.

We will cover the basic rule structure in this room and help you take a step into snort rules. You can always advance your rule creation skills with different rule options by practising different use cases and studying rule option details in depth. We will focus on two actions; **“alert”** for IDS mode and **“reject”** for IPS mode.

Rules cannot be processed without a header. Rule options are “optional” parts. However, it is almost impossible to detect sophisticated attacks without using the rule options.

![](_resources/02%20Snort/f4bf5862773565a64f5da99bf29f2565_MD5.jpg)

## IP and Port Numbers

These parameters identify the source and destination IP addresses and associated port numbers filtered for the rule.

![](_resources/02%20Snort/d2ada3da0d746562a9d56c13e8d03aaf_MD5.jpg)

## Direction

The direction operator indicates the traffic flow to be filtered by Snort. The left side of the rule shows the source, and the right side shows the destination.

- **->** Source to destination flow.
- **<>** Bidirectional flow

**Note that there is no “<-” operator in Snort.**

![](_resources/02%20Snort/37df96c307ca03a2e14d046ed176c848_MD5.jpg)

## There are three main rule options in Snort

- **General Rule Options —** Fundamental rule options for Snort.
- **Payload Rule Options —** Rule options that help to investigate the payload data. These options are helpful to detect specific payload patterns.
- **Non-Payload Rule Options —** Rule options that focus on non-payload data. These options will help create specific patterns and identify network issues.

## General Rule Options

![](_resources/02%20Snort/882d5425a14116eabe6c3e9646f893fb_MD5.jpg)

## Payload Detection Rule Options

![](_resources/02%20Snort/9de2d8258d76de8bc121ef0f78a771a7_MD5.jpg)

## Non-Payload Detection Rule Options

There are rule options that focus on non-payload data. These options will help create specific patterns and identify network issues.

![](_resources/02%20Snort/b935b1f3ab0fcae3da6f9ea5b7090aed_MD5.jpg)

Remember, once you create a rule, it is a local rule and should be in your “local.rules” file. This file is located under “/etc/snort/rules/local.rules”. A quick reminder on how to edit your local rules is shown below.

modifying the local rules

```
user@ubuntu$ sudo gedit /etc/snort/rules/local.rules
```

That is your “local.rules” file.

![](_resources/02%20Snort/609cb0e6c73034e7f5a1348bb3bfb355_MD5.jpg)

Note that there are some default rules activated with snort instance. These rules are deactivated to manage your rules and improve your exercise experience. For further information, please refer to the TASK-10 or [Snort manual](http://manual-snort-org.s3-website-us-east-1.amazonaws.com/).

By this point, we covered the primary structure of the Snort rules. Understanding and practicing the fundamentals is suggested before creating advanced rules and using additional options.

Wow! We have covered the fundamentals of the Snort rules! Now, use the attached VM and navigate to the Task-Exercises/Exercise-Files/TASK-9 folder to answer the questions! Note that you can use the following command to create the logs in the **current directory:** `**-l .**`

![](_resources/02%20Snort/c76afd9aafce33e82c0f2c8a50154f20_MD5.jpg)

### Answer the questions below

Use **“task9.pcap”.**

**Write a rule to filter IP ID “35369” and run it against the given pcap file. What is the request name of the detected packet?**

```
snort -c local.rules -A full -l . -r task9.pcap
```

While in the TASK-9 directory, use the command `sudo gedit local.rules` and press enter to open a text editor, so we can start writing our Snort rules.

![](_resources/02%20Snort/668cd60508bd55126264820dd4d46497_MD5.jpg)

Now that we have our text editor open, we have to write our first rule. Let’s start it off with `alert icmp any any <> any any`, we start it off this way because we don’t have an IP address to check, so we use the any on both sides of the directional arrows. The protocol we aren’t sure on yet either, so we can start with icmp. Next we want to do the Rule options, so this is what I did `(msg:"Sus IP ID found"; id:35369; sid:1000001; rev:1;)`, the message can be whatever you want it to be but it should be descriptive, then I added the id given to me by TryHackMe. Then to finish it up since it it the first rule the sid is 1000001, and the first revision as well.

![](_resources/02%20Snort/9e0f0eee2553000b903edafd503ac1a7_MD5.jpg)

Use the keyboard shortcut to save the rule ctrl + s . Then you can click the X in the top right of the window, after you do this you will be back at the terminal and should see this below.

![](_resources/02%20Snort/e4ab79604df4cb4c42e049a2c138b2f3_MD5.jpg)

Now run the command given above to use you newly written rule against the pcap file in this directory. The command is `sudo snort -c local.rules -A full -l . -r task9.pcap`. Press enter to run the command.

![](_resources/02%20Snort/fd4d3413eb9336c4d9fbc32fa05a7692_MD5.jpg)

After Snort is done running, we can run `ls`to see what all is in the directory, and we see the Snort log file.

![](_resources/02%20Snort/626de287a9e2a8e164f3a396b4e3e7c2_MD5.jpg)

So as we learned back in task 6 we can read the log file with the command `sudo snort -r snort.log.1671635190`, your log file may be named different but you get the gist.

![](_resources/02%20Snort/da8bf50c2bc66eea207ef9328982966a_MD5.jpg)

When it is done, scroll back up towards the top till you reach the one packet that is in the log. In this packet is the answer to the question, look to the last line any it is the final two words. Once you find it, type the answer into the TryHackMe answer field, then click submit.

![](_resources/02%20Snort/0b15130df206bcaafbbd0e2e24997ebe_MD5.jpg)

Answer: TIMESTAMP REQUEST

**Create a rule to filter packets with Syn flag and run it against the given pcap file. What is the number of detected packets?**

Once again use the command `sudo gedit local.rules`, then press enter to open the text editor

![](_resources/02%20Snort/4c4740bad7c29218657d3e94e47b19ed_MD5.jpg)

Time for the second rule, this time it is much like the first. The command go as such `alert tcp any any <> any any (msg:"Flag SYN Test"; flags:S;sid:1000002;rev:1;)`. We just indicate that we are searching for anything with a SYN flag.

![](_resources/02%20Snort/a250cba7343a1973c98e0f49d765592d_MD5.jpg)

So as before, save (ctrl + s) and X out of the text editor window, and your back in the terminal.

![](_resources/02%20Snort/36ca1a33f51cecf8d41926534b41f4df_MD5.jpg)

Now run the command given above to use you newly written rule against the pcap file in this directory. The command is `sudo snort -c local.rules -A full -l . -r task9.pcap`. Press enter to run the command.

![](_resources/02%20Snort/fd4d3413eb9336c4d9fbc32fa05a7692_MD5.jpg)

After Snort is done running, we can run `ls`to see what all is in the directory, and we see a new Snort log file.

![](_resources/02%20Snort/d66978277141a39db6e71a8051e1cde8_MD5.jpg)

So as we learned back in task 6 we can read the log file with the command `sudo snort -r snort.log.1671635190`, your log file may be named different but you get the gist.

![](_resources/02%20Snort/785b51109a598fbccca419f7837b420d_MD5.jpg)

Scroll back up to the packets sections, looks like we have two. But if you remember, that first packet is being detected by our first rule so we can’t count that one. So how many do we really have? Once you have it figured out, type the answer into the TryHackMe answer field, then click submit.

![](_resources/02%20Snort/b48bf3dfa93f200051ed4f8413eb8e52_MD5.jpg)

Answer: 1

Clear the previous log and alarm files and deactivate/comment out the old rule.

Opening up the text editor again with `sudo gedit local.rules`.

![](_resources/02%20Snort/36fb9582b6463244b603803060d55406_MD5.jpg)

To comment out the rules, put a `#` in from of the rule, then snort will not run it, and think it is just text like above.

![](_resources/02%20Snort/7a35a647dd569f3acc3516eacd05aab8_MD5.jpg)

So as before, save (ctrl + s) and X out of the text editor window, and your back in the terminal.

![](_resources/02%20Snort/faa550d167cbb69177f53ce5fc5e91d9_MD5.jpg)

Now to remove the Alerts and the logs. To do this we can use the `rm` command. So start with the `ls` command to view what is in the directory. From there you want to then use the command `sudo rm snort.log.167635190 snort.log.1671638632`, we use sudo because you have to have admin rights to remove the files the the rm command to remove, then the file names. Do not remove the alert file you could break the Snort scanning, not sure why but it does.

![](_resources/02%20Snort/ed47e5c6b1c0a691faf0dad8d0491baa_MD5.jpg)

You are ready to move onto the next question.

**Write a rule to filter packets with Push-Ack flags and run it against the given pcap file. What is the number of detected packets?**

Opening up the text editor again with `sudo gedit local.rules`.

![](_resources/02%20Snort/76be592ca825329a73c0f991971cc15f_MD5.jpg)

The rule is going to be made up just like rule two, but we are going to Which will make the command, `alert tcp any any <> any any (msg:"Flag Push-Ack Test"; flags:P,A; sid:1000003; rev:1;)`.

![](_resources/02%20Snort/24a589dd026d0bb6bdd227ff2d3fbdc1_MD5.jpg)

So as before, save (ctrl + s) and X out of the text editor window, and your back in the terminal.

![](_resources/02%20Snort/faa550d167cbb69177f53ce5fc5e91d9_MD5.jpg)

Now run the command given by TryHackMe above to use you newly written rule against the pcap file in this directory. The command is `sudo snort -c local.rules -A full -l . -r task9.pcap`. Press enter to run the command.

![](_resources/02%20Snort/fd4d3413eb9336c4d9fbc32fa05a7692_MD5.jpg)

After Snort is done running, we can run `ls`to see what all is in the directory, and we see a new Snort log file.

![](_resources/02%20Snort/d759a9d8c9aef6f8a7a0e2f9ad5a4eaa_MD5.jpg)

So as we learned back in task 6 we can read the log file with the command `sudo snort -r snort.log.1671643846`, your log file may be named different but you get the gist.

![](_resources/02%20Snort/bf1e73184f927b68daf28feae0b07f30_MD5.jpg)

When Snort is done outputing the file, you will see Total at the bottom. The number to the right of this is the answer to the question. Once you find it, type the answer into the TryHackMe Answer field, then click submit.

![](_resources/02%20Snort/de962b0280fff46a1c46ae5f636f3638_MD5.jpg)

Answer: 216

Clear the previous log and alarm files and deactivate/comment out the old rule.

Opening up the text editor again with `sudo gedit local.rules`.

![](_resources/02%20Snort/6f4ab7af19632275aea54f53d4aaf6e9_MD5.jpg)

To comment out the rules, put a `#` in from of the rule, then snort will not run it, and think it is just text like above.

![](_resources/02%20Snort/f3c80e43365e758b3ab40d88cfb83732_MD5.jpg)

So as before, save (ctrl + s) and X out of the text editor window, and your back in the terminal.

![](_resources/02%20Snort/faa550d167cbb69177f53ce5fc5e91d9_MD5.jpg)

Now to remove log file. To do this we can use the `rm` command. So start with the `ls` command to view what is in the directory. From there you want to then use the command `sudo rm snort.log.1671643846`, we use sudo because you have to have admin rights to remove the files the the rm command to remove, then the file names.

![](_resources/02%20Snort/338526e16cbe94e4442e4cda322709b5_MD5.jpg)

You are ready to move onto the next question.

**Create a rule to filter packets with the same source and destination IP and run it against the given pcap file. What is the number of detected packets?**

Opening up the text editor again with `sudo gedit local.rules`.

![](_resources/02%20Snort/c0f70546a28ebe2b42af1c0b4ae76dd6_MD5.jpg)

We learned about this in the above section **Non-Payload Detection Rule Options,** it is at the bottom of the table. After taking a look at it, we have our rule layed out for us nicely. The rule then is `alert ip any any <> any any (msg:"Same IP"; sameip; sid:1000004; rev:1;)`. But we need to filter out both tcp and udp, unfortunately you can’t do both protocols in one rule so you must do two rules. In the front after alert the first one I have tcp and the second I have udp. But the rest is pretty much the same.

![](_resources/02%20Snort/5babac5c67c06411330bbba99925fa03_MD5.jpg)

So as before, save (ctrl + s) and X out of the text editor window, and your back in the terminal.

![](_resources/02%20Snort/faa550d167cbb69177f53ce5fc5e91d9_MD5.jpg)

Now run the command given by TryHackMe above to use you newly written rule against the pcap file in this directory. The command is `sudo snort -c local.rules -A full -l . -r task9.pcap`. Press enter to run the command.

![](_resources/02%20Snort/fd4d3413eb9336c4d9fbc32fa05a7692_MD5.jpg)

After Snort is done running, we can run `ls`to see what all is in the directory, and we see a new Snort log file.

![](_resources/02%20Snort/a622db93601e3908a69dc4047de39064_MD5.jpg)

So as we learned back in task 6 we can read the log file with the command `sudo snort -r snort.log.1671651153`, your log file may be named different but you get the gist.

![](_resources/02%20Snort/c73f57d0c3fbb066813439bc04f0bc81_MD5.jpg)

Like after running the previous rule through snort, the answer is going to be found at the bottom. Look at the Total row and move to the right, the number is the answer. Once you find it, type the answer into the TryHackMe Answer field, then click submit.

![](_resources/02%20Snort/6402b49c7152e273ffeaca028f2e283d_MD5.jpg)

Answer: 10

_Edit: I had someone inform me that the answer to this question is different at this point. After running through the same process above they got 7. So it could be the case that something changed and the new answer is 7. Thank you, for letting me know and keeping these blogs accurate._

**Case Example — An analyst modified an existing rule successfully. Which rule option must the analyst change after the implementation?**

Since you can find the answer above I won’t be sharing it here, but follow along to help discover it if you need help. Scroll up to the General Rule Options, at the bottom of this table is where you can find the answer. Once you find it, type the answer into the TryHackMe Answer field, then click submit.

![](_resources/02%20Snort/68d92c47fd7dfeb24f4973bd42ddeec9_MD5.jpg)

# Task 10 Snort2 Operation Logic: Points to Remember

## Points to Remember

**Main Components of Snort**

- **Packet Decoder —** Packet collector component of Snort. It collects and prepares the packets for pre-processing.
- **Pre-processors —** A component that arranges and modifies the packets for the detection engine.
- **Detection Engine —** The primary component that process, dissect and analyse the packets by applying the rules.
- **Logging and Alerting —** Log and alert generation component.
- **Outputs and Plugins —** Output integration modules (i.e. alerts to syslog/mysql) and additional plugin (rule management detection plugins) support is done with this component.

## There are three types of rules available for snort

- **Community Rules —** Free ruleset under the GPLv2. Publicly accessible, no need for registration.
- **Registered Rules —** Free ruleset (requires registration). This ruleset contains subscriber rules with 30 days delay.
- **Subscriber Rules (Paid) —** Paid ruleset (requires subscription). This ruleset is the main ruleset and is updated twice a week (Tuesdays and Thursdays).

You can download and read more on the rules [here](https://www.snort.org/downloads).

**Note:** Once you install Snort2, it automatically creates the required directories and files. However, if you want to use the community or the paid rules, you need to indicate each rule in the **snort.conf** file.

Since it is a long, all-in-one configuration file, editing it without causing misconfiguration is troublesome for some users. **That is why Snort has several rule updating modules and integration tools. To sum up, never replace your configured Snort configuration files; you must edit your configuration files manually or update your rules with additional tools and modules to not face any fail/crash or lack of feature.**

- **snort.conf:** _Main configuration file._
- **local.rules:** _User-generated rules file._

**Let’s start with overviewing the main configuration file (snort.conf)** `sudo gedit /etc/snort/snort.conf`

**Navigate to the “Step #1: Set the network variables.” section.**

This section manages the scope of the detection and rule paths.

![](_resources/02%20Snort/7bf40ef7a3dd28a52d918f3613ad48dc_MD5.jpg)

## Navigate to the “Step #2: Configure the decoder.” section.

In this section, you manage the IPS mode of snort. The single-node installation model IPS model works best with “afpacket” mode. You can enable this mode and run Snort in IPS.

![](_resources/02%20Snort/70ee6b639029e7f42d316c41867e79e3_MD5.jpg)

Data Acquisition Modules (DAQ) are specific libraries used for packet I/O, bringing flexibility to process packets. It is possible to select DAQ type and mode for different purposes.

There are six DAQ modules available in Snort;

- **Pcap:** Default mode, known as Sniffer mode.
- **Afpacket:** Inline mode, known as IPS mode.
- **Ipq:** Inline mode on Linux by using Netfilter. It replaces the snort_inline patch.
- **Nfq:** Inline mode on Linux.
- **Ipfw:** Inline on OpenBSD and FreeBSD by using divert sockets, with the pf and ipfw firewalls.
- **Dump:** Testing mode of inline and normalisation.

The most popular modes are the default (pcap) and inline/IPS (Afpacket).

## Navigate to the “Step #6: Configure output plugins” section.

This section manages the outputs of the IDS/IPS actions, such as logging and alerting format details. The default action prompts everything in the console application, so configuring this part will help you use the Snort more efficiently.

## Navigate to the “Step #7: Customise your ruleset” section.

![](_resources/02%20Snort/9370685c7c4848efee462de23144976c_MD5.jpg)

**Note that “#” is commenting operator. You should uncomment a line to activate it.**

# Task 11 Conclusion

In this room, we covered Snort, what it is, how it operates, and how to create and use the rules to investigate threats.

- Understanding and practising the fundamentals is crucial before creating advanced rules and using additional options.
- Do not create complex rules at once; try to add options step by step to notice possible syntax errors or any other problem easily.
- Do not reinvent the wheel; use it or modify/enhance it if there is a smooth rule.
- Take a backup of the configuration files before making any change.
- Never delete a rule that works properly. Comment it if you don’t need it.
- Test newly created rules before migrating them to production.

Now, we invite you to complete the snort challenge room: [Snort Challenge — Live Attacks](https://tryhackme.com/room/snortchallenges1)

A great way to quickly recall snort rules and commands is to download and refer to the TryHackMe snort cheatsheet.

![](_resources/02%20Snort/f8ddfd4a9a97258360c86f200b38a781_MD5.jpg)

![](_resources/02%20Snort/68bbcf26a61c990ae126735186df33ab_MD5.jpg)