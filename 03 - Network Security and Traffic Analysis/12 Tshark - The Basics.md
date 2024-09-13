https://www.youtube.com/watch?v=KXdUqBgmcWU
https://www.youtube.com/watch?v=E0Q9hGRUc0o
https://medium.com/@buntybabu023/tshark-the-basics-tryhackme-walkthrough-1d5e40199a84

# Task 1 Introduction

TShark is an open-source command-line network traffic analyser. It is created by the Wireshark developers and has most of the features of Wireshark. It is commonly used as a command-line version of Wireshark. However, it can also be used like tcpdump. Therefore it is preferred for comprehensive packet assessments.

## Learning Objectives

- Filtering the traffic with TShark
- Implementing Wireshark filters in TShark
- Expanding and automating packet filtering with TShark

We have prepared a VM with TShark and the necessary files. You can start the machine by pressing the green **Start Machine** button attached to this task. The machine will start in split view. In case it is not opening the split view, you can press the blue **Show Split View** button at the top of the page.

We suggest completing the [**Network Fundamentals**](https://tryhackme.com/module/network-fundamentals) and [**Wireshark**](https://tryhackme.com/module/wireshark) modules before starting this room.

# Task 2 Command-Line Packet Analysis Hints | TShark and Supplemental CLI Tools

## Command-Line Packet Analysis Hints

TShark is a text-based tool, and it is suitable for data carving, in-depth packet analysis, and automation with scripts. This strength and flexibility come out of the nature of the CLI tools, as the produced/processed data can be pipelined to additional tools. The most common tools used in packet analysis are listed below.

![](_resources/12%20Tshark%20-%20The%20Basics/86128f3fa974cbdad1d32725e8142e8e_MD5.jpg)

**Note:** Sample usage of these tools is covered in the [**Zeek**](https://tryhackme.com/room/zeekbro) **room**.

Open the terminal and follow the given instructions. You can follow along with the interactive materials by switching to the following directory.

- `cd Desktop/exercise-files/`

```bash
# Capinfos demo

user@ubuntu$ capinfos demo.pcapng   
File name:           demo.pcapng  
File type:           Wireshark/tcpdump/... - pcap  
File encapsulation:  Ethernet  
File timestamp precision:  microseconds (6)  
Packet size limit:   file hdr: 65535 bytes  
Number of packets:   4...  
File size:           25 kB  
Data size:           25 kB  
Capture duration:    30.393704 seconds  
First packet time:   2004-05-13 10:17:07.311224  
Last packet time:    2004-05-13 10:17:37.704928  
Data byte rate:      825 bytes/s  
Data bit rate:       6604 bits/s  
Average packet size: 583.51 bytes  
Average packet rate: 1 packets/s  
SHA256:              25a72bdf10339...  
RIPEMD160:           6ef5f0c165a1d...  
SHA1:                3aac91181c3b7...  
Strict time order:   True  
Number of interfaces in file: 1  
Interface #0 info:  
                     Encapsulation = Ethernet (1 - ether)  
                     Capture length = 65535  
                     Time precision = microseconds (6)  
                     Time ticks per second = 1000000  
                     Number of stat entries = 0  
                     Number of packets = 4...
```


### Answer the question below

**Find the task files on the Desktop in the “exercise-files” folder?**

No answer needed

**View the details of the demo.pcapng file with “capinfos”. What is the “RIPEMD160” value?**

To find the answer just change you directory to ~/Desktop/exercise-files you will find **demo.pcapng** file then you need to run this command **capinfos demo.pcapng** after that you will find the answer

![](_resources/12%20Tshark%20-%20The%20Basics/4870f2a8f5ab5c77a905204568ce2be6_MD5.jpg)

Answer : 6ef5f0c165a1db4a3cad3116b0c5bcc0cf6b9ab7

# Task 3 TShark Fundamentals I | Main Parameters I

## Command-Line Interface and Parameters

TShark is a text-based (command-line) tool. Therefore, conducting an in-depth and consecutive analysis of the obtained results is easy. Multiple built-in options are ready to use to help analysts conduct such investigations. However, learning the parameters is essential; you will need the built-in options and associated parameters to keep control of the output and not be flooded with the detailed output of TShark. The most common parameters are explained in the given table below. Note that TShark requires superuser privileges to sniff live traffic and list all available interfaces.

![](_resources/12%20Tshark%20-%20The%20Basics/6f7dae15e326b81ebac38e1fead1135c_MD5.jpg)

Let’s view the version info of the TShark instance in the given VM. Open the terminal and follow the given instructions.

View version
```bash
user@ubuntu$ tshark -v                             
TShark (Wireshark) 3 (Git v3. packaged as 3.)  
Copyright 1998-2020 Gerald Combs and contributors. License GPLv2+: GNU GPL version 2 or later.  
This is free software; see the source for copying conditions.
```

## Sniffing

Sniffing is one of the essential functionalities of TShark. A computer node can have multiple network interfaces that allow the host to communicate and sniff the traffic through the network. Specific interfaces might be associated with particular tasks/jobs. Therefore, the ability to choose a sniffing interface helps users decide and set the proper interface for sniffing.

Let’s view the available interfaces in the given VM.

List interfaces

```bash
user@ubuntu$ sudo tshark -D  
1. ens5  
2. lo (Loopback)  
3. any  
4. bluetooth-monitor  
5. nflog  
..
```

Sniffing can be done with and without selecting a specific interface. When a particular interface is selected, TShark uses that interface to sniff the traffic. TShark will use the first available interface when no interface is selected, usually listed as 1 in the terminal. Having no interface argument is an alias for `-i 1`. You can also set different sniffing interfaces by using the parameter `-i`. TShark always echoes the used interface name at the beginning of the sniffing.

Sniff traffic

```bash
# Sniffing with the default interface.  
user@ubuntu$ tshark                             
Capturing on 'ens5'  
    1   0.000000 aaa.aaa.aaa.aaa ? bbb.bbb.bbb.bbb TCP 3372 ? 80 [SYN] Seq=0 Win=8760 Len=0 MSS=1460 SACK_PERM=1   
    2   0.911310 aaa.aaa.aaa.aaa ? bbb.bbb.bbb.bbb TCP 80 ? 3372 [SYN, ACK] Seq=0 Ack=1 Win=5840 Len=0 MSS=1380 SACK_PERM=1   
    3   0.911310 aaa.aaa.aaa.aaa ? bbb.bbb.bbb.bbb TCP 3372 ? 80 [ACK] Seq=1 Ack=1 Win=9660 Len=0   
...  
100 packets captured  

# Choosing an interface  
user@ubuntu$ tshark -i 2  
Capturing on 'Loopback: lo'
```

### Answer the questions below

**What is the installed TShark version in the given VM?**

To find the answer just run this command **tshark -v** you will find the answer

![](_resources/12%20Tshark%20-%20The%20Basics/f75988421e164038f71f11fda8ec090a_MD5.jpg)

Answer : 3.2.3

**List the available interfaces with TShark. What is the number of available interfaces in the given VM?**

To find the answer just run this command **tshark -D** you will find the answer

![](_resources/12%20Tshark%20-%20The%20Basics/f4ceb6e9f2ae873ebaef20f0aa632c63_MD5.jpg)

Answer: 12

# Task 4 TShark Fundamentals I | Main Parameters II

## Command-Line Interface and Parameters II

Let’s continue discovering main parameters of TShark.

![](_resources/12%20Tshark%20-%20The%20Basics/a020430bc6d9d4f924c0c803d410ae3a_MD5.jpg)

![](_resources/12%20Tshark%20-%20The%20Basics/9a9b95a8a60ea0ad10ca007b30b83980_MD5.jpg)

## Read Capture Files

TShark can also process PCAP files. You can use the `-r` parameter to process the file and investigate the packets. You can limit the number of shown packets using the `-c` parameter.

Read data

```bash
user@ubuntu$ tshark -r demo.pcapng  
    1   0.000000 145.254.160.237 ? 65.208.228.223 TCP 3372 ? 80 [SYN] Seq=0 Win=8760 Len=0 MSS=1460 SACK_PERM=1   
    2   0.911310 65.208.228.223 ? 145.254.160.237 TCP 80 ? 3372 [SYN, ACK] Seq=0 Ack=1 Win=5840 Len=0 MSS=1380 SACK_PERM=1   
    3   0.911310 145.254.160.237 ? 65.208.228.223 TCP 3372 ? 80 [ACK] Seq=1 Ack=1 Win=9660 Len=0
..  

# Read by count, show only the first 2 packets.  
user@ubuntu$ tshark -r demo.pcapng -c 2  
    1   0.000000 145.254.160.237 ? 65.208.228.223 TCP 3372 ? 80 [SYN] Seq=0 Win=8760 Len=0 MSS=1460 SACK_PERM=1   
    2   0.911310 65.208.228.223 ? 145.254.160.237 TCP 80 ? 3372 [SYN, ACK] Seq=0 Ack=1 Win=5840 Len=0 MSS=1380 SACK_PERM=1
```

## Write Data

TShark can also write the sniffed or filtered packets to a file. You can save the sniffed traffic to a file using the `-w` parameter. This option helps analysts to separate specific packets from the file/traffic and save them for further analysis. It also allows analysts to share only suspicious packets/scope with higher-level investigators.

Write data

```
# Read the first packet of the demo.pcapng, create write-demo.pcap and save the first packet there.  
user@ubuntu$ tshark -r demo.pcapng -c 1 -w write-demo.pcap  

# List the contents of the current folder.  
user@ubuntu$ ls  
demo.pcapng  write-demo.pcap  

# Read the write-demo.pcap and show the packet bytes/details.  
user@ubuntu$ tshark -r write-demo.pcap   
    1   0.000000 145.254.160.237 ? 65.208.228.223 TCP 3372 ? 80 [SYN] Seq=0 Win=8760 Len=0 MSS=1460 SACK_PERM=1
```

## Show Packet Bytes

TShark can show packet details in hex and ASCII format. You can view the dump of the packets by using the `-x` parameter. Once you use this parameter, all packets will be shown in hex and ASCII format. Therefore, it might be hard to spot anomalies at a glance, so using this option after reducing the number of packets will be much more efficient.

Show packet bytes

```bash
# Read the packets from write-demo.pcap  
user@ubuntu$ tshark -r write-demo.pcap   
    1   0.000000 145.254.160.237 ? 65.208.228.223 TCP 3372 ? 80 [SYN] Seq=0 Win=8760 Len=0 MSS=1460 SACK_PERM=1   

# Read the packets from write-demo.pcap and show the packet bytes/details.  
user@ubuntu$ tshark -r write-demo.pcap -x  
0000  fe ff 20 00 01 00 00 00 01 00 00 00 08 00 45 00   .. ...........E.  
0010  00 30 0f 41 40 00 80 06 91 eb 91 fe a0 ed 41 d0   .0.A@.........A.  
0020  e4 df 0d 2c 00 50 38 af fe 13 00 00 00 00 70 02   ...,.P8.......p.  
0030  22 38 c3 0c 00 00 02 04 05 b4 01 01 04 02         "8............
```

## Verbosity

Default TShark packet processing and sniffing operations provide a single line of information and exclude verbosity. The default approach makes it easy to follow the number of processed/sniffed packets; however, TShark can also provide verbosity for each packet when instructed. Verbosity is provided similarly to Wireshark’s “Packet Details Pane”. As verbosity offers a long list of packet details, it is suggested to use that option for specific packets instead of a series of packets.

Verbosity

```
# Default view  
user@ubuntu$ tshark -r demo.pcapng -c 1  
    1   0.000000 145.254.160.237 ? 65.208.228.223 TCP 3372 ? 80 [SYN] Seq=0 Win=8760 Len=0 MSS=1460 SACK_PERM=1   

# Verbosity  
user@ubuntu$ tshark -r demo.pcapng -c 1 -V  
Frame 1: 62 bytes on wire (496 bits), 62 bytes captured (496 bits)  
...  
Ethernet II, Src: 00:00:01:00:00:00, Dst: fe:ff:20:00:01:00  
...  
Internet Protocol Version 4, Src: 145.254.160.237, Dst: 65.208.228.223  
    0100 .... = Version: 4  
    .... 0101 = Header Length: 20 bytes (5)  
    Total Length: 48  
    Identification: 0x0f41 (3905)  
    Flags: 0x4000, Don't fragment  
    Fragment offset: 0  
    Time to live: 128  
    Protocol: TCP (6)  
    Source: 145.254.160.237  
    Destination: 65.208.228.223  
Transmission Control Protocol, Src Port: 3372, Dst Port: 80, Seq: 0, Len: 0  
 ...
```

Verbosity provides full packet details and makes it difficult to investigate (long and complex terminal output for each packet). However, it is still helpful for in-depth packet analysis and scripting, making TShark stand out. Remember, the best utilisation time of verbosity is after filtering the packets. You can compare the above output with the below screenshot and see the scripting, carving, and correlation opportunities you have!

![](_resources/12%20Tshark%20-%20The%20Basics/44517eaf6bb24954b1b6757f4d144d09_MD5.jpg)

### Answer the questions below

**Read the “demo.pcapng” file with TShark. 
What are the assigned TCP flags in the 29th packet?**

To find the answer just run this command **tshark -r demo.pcapng -c 29** you will find the answer

![](_resources/12%20Tshark%20-%20The%20Basics/2ad5b834177d1c9652215dfe55c090b9_MD5.jpg)

Answer : PSH, ACK

**What is the “Ack” value of the 25th packet?**

![](_resources/12%20Tshark%20-%20The%20Basics/f03c9dbe230aa62ae22b74e26894cea0_MD5.jpg)

Answer : 12421

**What is the “Window size value” of the 9th packet?**

![](_resources/12%20Tshark%20-%20The%20Basics/91225f14bdceefca16907be12b157169_MD5.jpg)

Answer : 9660

# Task 5 TShark Fundamentals II | Capture Conditions

## Capture Condition Parameters

As a network sniffer and packet analyser, TShark can be configured to count packets and stop at a specific point or run in a loop structure. The most common parameters are explained below.

![](_resources/12%20Tshark%20-%20The%20Basics/5a4f07717b290422965a7f04bb674078_MD5.jpg)

![](_resources/12%20Tshark%20-%20The%20Basics/6ed8a844a790961ba99ca7e840740b6e_MD5.jpg)

Capture condition parameters only work in the “capturing/sniffing” mode. You will receive an error message if you try to read a pcap file and apply the capture condition parameters. The idea is to save the capture files in specific sizes for different purposes during live capturing. If you need to extract sorts of packets from a specific capture file, you will need to use the read&write options discussed in the previous task.

**Hint:** TShark supports combining autostop (`-a`) parameters with ring buffer control parameters (`-b`). You can combine the parameters according to your needs. Use the infinite loop options carefully; remember, you must use at least one autostop parameter to stop the infinite loop.

Sample autostop query

```
# Start sniffing the traffic and stop after 2 seconds, and save the dump into 5 files, each 5kb.  

user@ubuntu$ tshark -w autostop-demo.pcap -a duration:2 -a filesize:5 -a files:5
Capturing on 'ens5'
13   

# List the contents of the current folder.  
user@ubuntu$ ls  
-rw------- 1 ubuntu ubuntu   autostop-demo_..1_2022.pcap  
-rw------- 1 ubuntu ubuntu   autostop-demo_..2_2022.pcap  
-rw------- 1 ubuntu ubuntu   autostop-demo_..3_2022.pcap  
-rw------- 1 ubuntu ubuntu   autostop-demo_..4_2022.pcap  
-rw------- 1 ubuntu ubuntu   autostop-demo_..5_2022.pcap
```

### Answer the questions below

**Which parameter can help analysts to create a continuous capture dump?**

Answer : `-b`

**Can we combine autostop and ring buffer parameters with TShark? y/n**

Answer : `y`

# Task 6 TShark Fundamentals III | Packet Filtering Options: Capture vs. Display Filters

## Packet Filtering Parameters | Capture & Display Filters

There are two dimensions of packet filtering in TShark; live (capture) and post-capture (display) filtering. These two dimensions can be filtered with two different approaches; using a predefined syntax or Berkeley Packet Filters (BPF). TShark supports both, so you can use Wireshark filters and BPF to filter traffic. As mentioned earlier, TShark is a command-line version of Wireshark, so we will need to use different filters for capturing and filtering packets. A quick recap from the [Wireshark: Packet Operations](https://tryhackme.com/r/room/wiresharkpacketoperations) room:

![](_resources/12%20Tshark%20-%20The%20Basics/a01c29497daa26502c8ce203964d31a4_MD5.jpg)

Capture filters are used to have a specific type of traffic in the capture file rather than having everything. Capture filters have limited filtering features, and the purpose is to implement a scope by range, protocol, and direction filtering. This might sound like bulk/raw filtering, but it still provides organised capture files with reasonable file size. The display filters investigate the capture files in-depth without modifying the packet.

![](_resources/12%20Tshark%20-%20The%20Basics/1323f5f726dc13012ba9936ddd0397d4_MD5.jpg)

Check out the [**Wireshark: Packet Operations**](https://tryhackme.com/room/wiresharkpacketoperations) room (Task 4 & 5) if you want to review the principles of packet filtering.

### Answer the questions below

**Which parameter is used to set “Capture Filters”?**

Answer : `-f`

**Which parameter is used to set “Display Filters”?**

Answer : `-Y`

# Task 7 TShark Fundamentals IV | Packet Filtering Options: Capture Filters

## Capture Filters

Wireshark’s capture filter syntax is used here. The basic syntax for the Capture/BPF filter is shown below. You can read more on capture filter syntax [here](https://www.wireshark.org/docs/man-pages/pcap-filter.html) and [here](https://gitlab.com/wireshark/wireshark/-/wikis/CaptureFilters#useful-filters). Boolean operators can also be used in both types of filters.

![](_resources/12%20Tshark%20-%20The%20Basics/758c0c10808b2da95d34cf501cf3f17e_MD5.jpg)

![](_resources/12%20Tshark%20-%20The%20Basics/574f12dae3f6c8f33c2a51b67d352f8b_MD5.jpg)

![](_resources/12%20Tshark%20-%20The%20Basics/afc1f3e52c32b7d2739e0d37bdf0728b_MD5.jpg)

We need to create traffic noise to test and simulate capture filters. We will use the “terminator” terminal instance to have a split-screen view in a single terminal. The “terminator” will help you craft and sniff packets using a single terminal interface. Now, run the `terminator` command and follow the instructions using the new terminal instance.

- First, run the given TShark command in Terminal-1 to start sniffing traffic.
- Then, run the given cURL command in Terminal-2 to create network noise.
- View sniffed packets results in Terminal-1.

“Terminator” Terminal Emulator Application

Terminal-1

```bash
user@ubuntu$ tshark -f "host 10.10.10.10"  
Capturing on 'ens5'  
    1 0.000000000 YOUR-IP → 10.10.10.10  TCP 74 36150 → 80 [SYN] Seq=0 Win=62727 Len=0 MSS=8961 SACK_PERM=1 TSval=2045205701 TSecr=0 WS=128  
    2 0.003452830  10.10.10.10 → YOUR-IP TCP 74 80 → 36150 [SYN, ACK] Seq=0 Ack=1 Win=62643 Len=0 MSS=8961 SACK_PERM=1 TSval=744450747 TSecr=2045205701 WS=64  
    3 0.003487830 YOUR-IP → 10.10.10.10  TCP 66 36150 → 80 [ACK] Seq=1 Ack=1 Win=62848 Len=0 TSval=2045205704 TSecr=744450747  
    4 0.003610800 YOUR-IP → 10.10.10.10  HTTP 141 GET / HTTP/1.1
```

Terminal-2

```bash
user@ubuntu$ curl -v 10.10.10.10  
*   Trying 10.10.10.10:80...  
* TCP_NODELAY set  
* Connected to 10.10.10.10 (10.10.10.10) port 80 (#0)  
> GET / HTTP/1.1  
> Host: 10.10.10.10  
> User-Agent: curl/7.68.0  
> Accept: */*  
>   
* Mark bundle as not supporting multiuse  
< HTTP/1.1 200 OK  
< Accept-Ranges: bytes  
< Content-Length: 1220  
< Content-Type: text/html; charset=utf-8
```

Being comfortable with the command line and TShark filters requires time and practice. You can use the below table to practice TShark capture filters.

![](_resources/12%20Tshark%20-%20The%20Basics/990b333bd523a1fafa1711b1295a8e7c_MD5.jpg)

![](_resources/12%20Tshark%20-%20The%20Basics/9571668fa8ca894d7234cdd962e65300_MD5.jpg)

![](_resources/12%20Tshark%20-%20The%20Basics/1723017fb8ee8b818ae4c50fd5d296c7_MD5.jpg)

### Answer the questions below

Run the commands from the above Terminator terminals on the target machine and answer the questions.

**What is the number of packets with SYN bytes?**

To find the answer just run this command on **terminal 1 tshark -f “host 10.10.10.10”** now on the **terminal 2** run this command **curl -v 10.10.10.10** now the packets gets captured on the terminal 1 and now you will need to count the number of SYN packets you will find the answer

![](_resources/12%20Tshark%20-%20The%20Basics/514e9ece8a63a6213abcada42ba78b85_MD5.jpg)

Answer : 2

**What is the number of packets sent to the IP address “10.10.10.10”?**

To find the answer count the number of packets to 10.10.10.10 you will need to manually count the packets from the previous results or my screenshot that has been attached you will find the answer

Answer : 7

**What is the number of packets with ACK bytes?**

To find the answer count the number of ACK packets on the given results or from my screenshot you will find the answer

Answer : 8

# Task 8 TShark Fundamentals V | Packet Filtering Options: Display Filters

## Display Filters

Wireshark’s display filter syntax is used here. You can use the official [**Display Filter Reference**](https://www.wireshark.org/docs/dfref/) to find the protocol breakdown for filtering. Additionally, you can use Wireshark’s build-in “Display Filter Expression” menu to break down protocols for filters. Note that Boolean operators can also be used in both types of filters. Common filtering options are shown in the given table below.

**Note:** Using single quotes for capture filters is recommended to avoid space and bash expansion problems. Once again, you can check the [**Wireshark: Packet Operations**](https://tryhackme.com/room/wiresharkpacketoperations) room (Task 4 & 5) if you want to review the principles of packet filtering.

![](_resources/12%20Tshark%20-%20The%20Basics/345fcd8daff1e8a7c1d545f6d7a775b2_MD5.jpg)

![](_resources/12%20Tshark%20-%20The%20Basics/433e1ea3e47d2c5969f2ad59a635f554_MD5.jpg)

We will use the “demo.pcapng” to test display filters. Let’s see the filters in action!

Sample filtering query

```bash
user@ubuntu$ tshark -r demo.pcapng -Y 'ip.addr == 145.253.2.203'  
13 2.55 145.254.160.237 ? 145.253.2.203 DNS Standard query 0x0023 A ..  
17 2.91 145.253.2.203 ? 145.254.160.237 DNS Standard query response 0x0023 A ..
```

The above terminal demonstrates using the “IP filtering” option. TShark filters the packets and provides the output in our terminal. It is worth noting that TShark doesn’t count the “total number of filtered packets”; it assigns numbers to packets according to the capture time, but only displays the packets that match our filter.

Look at the above example. There are two matched packets, but the associated numbers don’t start from zero or one; “13” and “17” are assigned to these filtered packets. Keeping track of these numbers and calculating the “total number of filtered packets” can be confusing if your filter retrieves more than a handful of packets. Another example is shown below.

Sample filtering query

```bash
user@ubuntu$ tshark -r demo.pcapng -Y 'http'  
  4   0.911 145.254.160.237 ? 65.208.228.223 HTTP GET /download.html HTTP/1.1    
 18   2.984 145.254.160.237 ? 216.239.59.99 HTTP GET /pagead/ads?client...   
 27   3.955 216.239.59.99 ? 145.254.160.237 HTTP HTTP/1.1 200 OK  (text/html)   
 38   4.846 65.208.228.223 ? 145.254.160.237 HTTP/XML HTTP/1.1 200 OK
```

You can use the `nl` command to get a numbered list of your output. Therefore you can easily calculate the "total number of filtered packets" without being confused with "assigned packet numbers". The usage of the `nl` command is shown below.

Sample filtering query

```bash
user@ubuntu$ tshark -r demo.pcapng -Y 'http' | nl  
1    4  0.911 145.254.160.237 ? 65.208.228.223 HTTP GET /download.html HTTP/1.1
2   18  2.984 145.254.160.237 ? 216.239.59.99 HTTP GET /pagead/ads?client...
3   27   3.955 216.239.59.99 ? 145.254.160.237 HTTP HTTP/1.1 200 OK (text/html)
4   38   4.846 65.208.228.223 ? 145.254.160.237 HTTP/XML HTTP/1.1 200 OK 
```

### Answer the questions below

Use the “demo.pcapng” file to answer the questions.

**What is the number of packets with a “65.208.228.223” IP address**

To find the answer you need to run this command **tshark -r demo.pcapng -Y “ip.addr == 65.208.228.223” | wc -l** after which you will find the answer

Answer: 34

**What is the number of packets with a “TCP port 3371”?**

To find the answer you need to run this command **tshark -r demo.pcapng -Y “tcp.port == 3371” | wc -l** after which you will find the answer

Answer : 7

**What is the number of packets with a “145.254.160.237” IP address as a source address?**

To find the answer you need to run this command **tshark -r demo.pcapng -Y “ip.src == 145.254.160.237” | wc -l** after which you will find the answer

Answer : 20

![](_resources/12%20Tshark%20-%20The%20Basics/43241fceea48c79079c468701bfbef32_MD5.jpg)

**Rerun the previous query and look at the output. What is the packet number of the “Duplicate” packet?**

Answer : 37

# Task 9 Conclusion

**Congratulations!** You just finished the TShark: The Basics room. In this room, we covered TShark, what it is, how it operates, and how to use it to investigate traffic captures.

Now, we invite you to complete the [TShark: CLI Wireshark Features](https://tryhackme.com/r/room/tsharkcliwiresharkfeatures) room to boost your CLI packet hunting skills by implementing Wireshark features with TShark.
