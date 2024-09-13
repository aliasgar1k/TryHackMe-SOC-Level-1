https://www.youtube.com/watch?v=DVpJCIseieM
https://medium.com/@haircutfish/tryhackme-traffic-analysis-essentials-room-29b7482aeb91

Learn Network Security and Traffic Analysis foundations and take a step into probing network anomalies.

# Task 1 Introduction

Network Security is a set of operations for protecting data, applications, devices and systems connected to the network. It is accepted as one of the significant subdomains of cyber security. It focuses on the system design, operation and management of the architecture/infrastructure to provide network accessibility, integrity, continuity and reliability. Traffic analysis (often called Network Traffic Analysis) is a subdomain of the Network Security domain, and its primary focus is investigating the network data to identify problems and anomalies.

This room will cover the foundations of Network Security and Traffic analysis and introduce the essential concepts of these disciplines to help you step into Traffic/Packet Analysis. We suggest completing the “[**Network Fundamentals**](https://tryhackme.com/module/network-fundamentals)” module before starting working in this room.

# Task 2 Network Security and Network Data

![](_resources/01%20Traffic%20Analysis%20Essentials/91cca1936a9d13e88d012ff4f6811e0f_MD5.jpg)

## Network Security

The essential concern of Network Security focuses on two core concepts: authentication and authorization. There are a variety of tools, technologies, and approaches to ensure and measure implementations of these two key concepts and go beyond to provide continuity and reliability. Network security operations contain three base control levels to ensure the maximum available security management.

**Base Network Security Control Levels:**

![](_resources/01%20Traffic%20Analysis%20Essentials/bba93358438eb24785eda0a95ee4a0af_MD5.jpg)

There are two main approaches and multiple elements under these control levels. The most common elements used in network security operations are explained below.

**The main approaches:**

![](_resources/01%20Traffic%20Analysis%20Essentials/61a23a038d56d79534423f1d2df2e333_MD5.jpg)

**The key elements of Access Control:**

![](_resources/01%20Traffic%20Analysis%20Essentials/2c3623db618534e4e191220bcb18c8f7_MD5.jpg)

**The key elements of Threat Control:**

![](_resources/01%20Traffic%20Analysis%20Essentials/2bbdd164699d5ec8d16109477311308b_MD5.jpg)

**Typical Network Security Management Operation is explained in the given table:**

![](_resources/01%20Traffic%20Analysis%20Essentials/c0509a8ea2472305f7ae07f93a6c1fc4_MD5.jpg)

## Managed Security Services

Not every organisation has enough resources to create dedicated groups for specific security domains. There are plenty of reasons for this: budget, employee skillset, and organisation size could determine how security operations are handled. At this point, Managed Security Services (MSS) come up to fulfil the required effort to ensure/enhance security needs. MSS are services that have been outsourced to service providers. These service providers are called Managed Security Service Providers (MSSPs). Today, most MSS are time and cost effective, can be conducted in-house or outsourced, are easy to engage, and ease the management process. There are various elements of MSS, and the most common ones are explained below.

![](_resources/01%20Traffic%20Analysis%20Essentials/c4b67844be8ee2b60d3fb5ac6b500986_MD5.jpg)

### Answer the questions below

Since the answer can be found above, I won’t be posting the answers below. Follow along to help find the answer.

**Which Security Control Level covers contain creating security policies?**

Go up to the Base Network Security Control Levels table, in this table you will find the answer, just read through. Once you find it, Highlight copy (ctrl + c) and paste (ctrl + v) or type, the answer into the TryHackMe answer Field, then click submit.

![](_resources/01%20Traffic%20Analysis%20Essentials/2b79b49be3bb5f53fd18b81df2e5d00b_MD5.jpg)

**Which Access Control element works with data metrics to manage data flow?**

Scroll up to The Key Elements of Access Control table, in this table you will find the answer, manage data flow is the key. Once you find it, Highlight copy (ctrl + c) and paste (ctrl + v) or type, the answer into the TryHackMe answer Field, then click submit.

![](_resources/01%20Traffic%20Analysis%20Essentials/aaca8e89e57cc85520f6cb587c24ba90_MD5.jpg)

**Which technology helps correlate different tool outputs and data sources?**

Scroll up to The Key Elements of Threat Control table, the answer can be found towards the bottom of this table. TryHackMe is looking for the acronym for the answer. Once you find it, Highlight copy (ctrl + c) and paste (ctrl + v) or type, the answer into the TryHackMe answer Field, then click submit.

![](_resources/01%20Traffic%20Analysis%20Essentials/abc31ac865de4879b52e9187785127cb_MD5.jpg)

# Task 3 Traffic Analysis

![](_resources/01%20Traffic%20Analysis%20Essentials/7206327e3576780efb27089db2eec166_MD5.jpg)

## Traffic Analysis / Network Traffic Analysis

Traffic Analysis is a method of intercepting, recording/monitoring, and analysing network data and communication patterns to detect and respond to system health issues, network anomalies, and threats. The network is a rich data source, so traffic analysis is useful for security and operational matters. The operational issues cover system availability checks and measuring performance, and the security issues cover anomaly and suspicious activity detection on the network.

Traffic analysis is one of the essential approaches used in network security, and it is part of multiple disciplines of network security operations listed below:

- Network Sniffing and Packet Analysis (Covered in [**Wireshark room**](https://tryhackme.com/room/wiresharkthebasics))
- Network Monitoring (Covered in [**Zeek room**](https://tryhackme.com/room/zeekbro))
- Intrusion Detection and Prevention (Covered in [**Snort room**](https://tryhackme.com/room/snort))
- Network Forensics (Covered in [**NetworkMiner room**](https://tryhackme.com/room/networkminer))
- Threat Hunting (Covered in [**Brim room**](https://tryhackme.com/room/brim))

There are two main techniques used in Traffic Analysis:

![](_resources/01%20Traffic%20Analysis%20Essentials/594f8401c2d2421d1512137b344dab3c_MD5.jpg)

Benefits of the Traffic Analysis:

- Provides full network visibility.
- Helps comprehensive baselining for asset tracking.
- Helps to detect/respond to anomalies and threats.

## Does the Traffic Analysis Still Matter?

The widespread usage of security tools/services and an increasing shift to cloud computing force attackers to modify their tactics and techniques to avoid detection. Network data is a pure and rich data source. Even if it is encoded/encrypted, it still provides a value by pointing to an odd, weird or unexpected pattern/situation. Therefore traffic analysis is still a must-to-have skill for any security analyst who wants to detect and respond to advanced threats.

Now you know what Traffic Analysis is and how it operates. Now use the static site to simulate a traffic analysis operation and find the flags.

### Answer the questions below

At the top of the task, click the green View Site button.

![](_resources/01%20Traffic%20Analysis%20Essentials/fd80134b177271cebdee1767e0920ac6_MD5.jpg)

The screen will split, and you will be ready to start.

![](_resources/01%20Traffic%20Analysis%20Essentials/53fb578bdad8df1edcb41f4aca312ee1_MD5.jpg)

#### Level-1

**Level-1** is simulating the identification and filtering of malicious IP addresses.

Click the black Start Network Traffic button.

![](_resources/01%20Traffic%20Analysis%20Essentials/cf9d8f348efa3a23f9c6faa897cca3f1_MD5.jpg)

You will see traffic running across the network, but uh-no we got malware!!! So a black button labeled Restore the Network and record the traffic for further investigation, click this button.

![](_resources/01%20Traffic%20Analysis%20Essentials/6fefc333c34c44c7a30d4ecb2a562f04_MD5.jpg)

So we will have traffic run over the network again, this time we are getting logs of what is running over it. Once we have enough logs, you will be instructed to analyze the data to find two IP addresses to filter through the firewall. Looking through the IDS/IPS system, we can see a couple of suspicious IP addesses.

![](_resources/01%20Traffic%20Analysis%20Essentials/70fe3280b6e29247e3746eb1d96b1cf6_MD5.jpg)

Highlight copy (ctrl + c) and paste (ctrl + v) or type the IP addresses into the Filter box, then click the blue Add to Filter.

![](_resources/01%20Traffic%20Analysis%20Essentials/55347083fd03f937b7defaaf0ca7c0cc_MD5.jpg)

Once you have added both of them, you will have a black Restart Network Traffic Button. Click it.

![](_resources/01%20Traffic%20Analysis%20Essentials/d6432af183afc68a57c7f4e6b07fd11f_MD5.jpg)

After restarting the Network Traffic, you will have successfully block the malware. You will get a pop-up window, this window will contain the first flag. Type the answer into the TryHackMe answer field, then click submit.

![](_resources/01%20Traffic%20Analysis%20Essentials/31fba05b791fc10bfcec04a35635febb_MD5.jpg)

**What is the flag?**

Answer: `THM{PACKET_MASTER}`


#### Level-2

Level 2 is simulating the identification and filtering of malicious IP and Port addresses.

Now we are tasked with blocking destination ports, we need to get these from the Traffic Analyzer table. If we look at the sus IP addresses from the previous question, along with number five, since it is labeled as Suspicious ARP Behavior. We can see the destination ports they correlate to in the Traffic Analyzer table on the right.

![](_resources/01%20Traffic%20Analysis%20Essentials/0576f4d208f1e491a394ce89d4450635_MD5.jpg)

Since we only need the port numbers, Highlight copy (ctrl + c) and paste (ctrl + v) or type, the port number into the Filter box, then click the blue Add to Filter.

![](_resources/01%20Traffic%20Analysis%20Essentials/174982bc2474615977901af4de61cceb_MD5.jpg)

Once you have added all the ports, a black Restart Network Traffic button will apper. Click it.

![](_resources/01%20Traffic%20Analysis%20Essentials/2a9499a26c72d7abb1e0b3653f03fa27_MD5.jpg)

After restarting the Network Traffic, you will have successfully block the malware. You will get a pop-up window, this window will contain the first flag. Type the answer into the TryHackMe answer field, then click submit.

![](_resources/01%20Traffic%20Analysis%20Essentials/e8293271d3b8e7054d2085c05ddff61e_MD5.jpg)

**What is the flag?**

Answer: `THM{DETECTION_MASTER}`

# Task 4 Conclusion

**Congratulations!** You just finished the “Traffic Analysis Essentials” room.

In this room, we covered the foundations of the network security and traffic analysis concepts:

- Network Security Operations
- Network Traffic Analysis

Now, you are ready to complete the **“Network Security and Traffic Analysis”** module.