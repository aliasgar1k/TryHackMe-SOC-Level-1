https://www.youtube.com/watch?v=BT4c0UKMYhg

https://medium.com/@haircutfish/tryhackme-brim-task-1-introduction-task-2-what-is-brim-task-3-the-basics-32772c13d8c2
https://medium.com/@haircutfish/tryhackme-brim-task-4-default-queries-task-5-use-cases-cd31926a1905
https://medium.com/@haircutfish/tryhackme-brim-task-6-exercise-threat-hunting-with-brim-malware-c2-detection-ea94926f577d
https://medium.com/@haircutfish/tryhackme-brim-task-7-exercise-threat-hunting-with-brim-crypto-mining-task-8-conclusion-6b7856e90938

Learn and practice log investigation, pcap analysis and threat hunting with Brim.

# Task 1 Introduction

[BRIM](https://www.brimdata.io/) is an open-source desktop application that processes pcap files and logs files. Its primary focus is providing search and analytics. In this room, you will learn how to use Brim, process pcap files and investigate log files to find the needle in the haystack! This room expects you to be familiar with basic security concepts and processing Zeek log files. We suggest completing the “[**Network Fundamentals**](https://tryhackme.com/module/network-fundamentals)” path and the “[**Zeek room**](https://tryhackme.com/room/zeekbro)” before starting working in this room.

A VM is attached to this room. You don’t need SSH or RDP; the room provides a **“Split View”** feature. Exercise files are located in the folder on the desktop.  
**NOTE: DO NOT** directly interact with any domains and IP addresses in this room.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/b47dd33a338905cba29a0241222bc5a4_MD5.jpg)

# Task 2 What is Brim?

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/0f79b9286879252f404fc55a5cc864ed_MD5.jpg)

## What is Brim?

Brim is an open-source desktop application that processes pcap files and logs files, with a primary focus on providing search and analytics. It uses the Zeek log processing format. It also supports Zeek signatures and Suricata Rules for detection.

It can handle two types of data as an input;

- **Packet Capture Files:** Pcap files created with tcpdump, tshark and Wireshark like applications.
- **Log Files:** Structured log files like Zeek logs.

Brim is built on open-source platforms:

- **Zeek:** Log generating engine.
- **Zed Language:** Log querying language that allows performing keywoırd searches with filters and pipelines.
- **ZNG Data Format:** Data storage format that supports saving data streams.
- **Electron and React:** Cross-platform UI.

## Why Brim?

Ever had to investigate a big pcap file? Pcap files bigger than one gigabyte are cumbersome for Wireshark. Processing big pcaps with tcpdump and Zeek is efficient but requires time and effort. Brim reduces the time and effort spent processing pcap files and investigating the log files by providing a simple and powerful GUI application.

## Brim vs Wireshark vs Zeek

While each of them is powerful and useful, it is good to know the strengths and weaknesses of each tool and which one to use for the best outcome. As a traffic capture analyser, some overlapping functionalities exist, but each one has a unique value for different situations.

**The common best practice is handling medium-sized pcaps with Wireshark, creating logs and correlating events with Zeek, and processing multiple logs in Brim.**

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/06022b71e7979becc383e2894c7a8173_MD5.jpg)

# Task 3 The Basics

## Landing Page

Once you open the application, the landing page loads up. The landing page has three sections and a file importing window. It also provides quick info on supported file formats.

- **Pools:** Data resources, investigated pcap and log files.
- **Queries:** List of available queries.
- **History:** List of launched queries.

## Pools and Log Details

Pools represent the imported files. Once you load a pcap, Brim processes the file and creates Zeek logs, correlates them, and displays all available findings in a timeline, as shown in the image below.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/f018c315c5a21afe1c0ac566543330ff_MD5.jpg)

The timeline provides information about capture start and end dates. Brim also provides information fields. You can hover over fields to have more details on the field. The above image shows a user hovering over the Zeek’s conn.log file and uid value. This information will help you in creating custom queries. The rest of the log details are shown in the right pane and provides details of the log file fields. Note that you can always export the results by using the export function located near the timeline.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/3f12b960a78a9828792376fed6834660_MD5.jpg)

You can correlate each log entry by reviewing the correlation section at the log details pane (shown on the left image). This section provides information on the source and destination addresses, duration and associated log files. This quick information helps you answer the “Where to look next?” question and find the event of interest and linked evidence.

You can also right-click on each field to filter and accomplish a list of tasks.

- Filtering values
- Counting fields
- Sorting (A-Z and Z-A)
- Viewing details
- Performing whois lookup on IP address
- Viewing the associated packets in Wireshark

The image below demonstrates how to perform whois lookup and Wireshark packet inspection.

**See image**

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/9e2bcd3b50f080266173653d8fa76e97_MD5.jpg)

## Queries and History

Queries help us to correlate finding and find the event of the interest. History stores executed queries.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/673c6ed78e9c7afb2ccc971d96ba5bc5_MD5.jpg)

The image on the left demonstrates how to browse the queries and load a specific query from the library.

Queries can have names, tags and descriptions. Query library lists the query names, and once you double-click, it passes the actual query to the search bar.

You can double-click on the query and execute it with ease. Once you double-click on the query, the actual query appears on the search bar and is listed under the history tab.

The results are shown under the search bar. In this case, we listed all available log sources created by Brim. In this example, we only insert a pcap file, and it automatically creates nine types of Zeek log files.

Brim has 12 premade queries listed under the “Brim” folder. These queries help us discover the Brim query structure and accomplish quick searches from templates. You can add new queries by clicking on the “+” button near the “Queries” menu.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/d968c410b5f3369de37cd111acd99b88_MD5.jpg)

### Answer the questions below

**Process the “sample.pcap” file and look at the details of the first DNS log that appear on the dashboard. What is the “qclass_name”?**

On the desktop, double-click the Exercise-Files directory icon and Brim icon.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/0a46309377a7fcbfdc007f5f0c2dc518_MD5.jpg)

When both open, click and drag the sample.pcap file from the Exercise-Files directory to the Brim application.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/0d7dff8138a7c55ed07c7c46285a54c7_MD5.jpg)

Then Brim will start to import the file.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/13d3181c949a0e75302c287d030393d0_MD5.jpg)

After the sample pcap loads, we first want to go to the view tab. It is the fourth tab on the right at the top of Brim. Click on it and a drop-down menu will appear, then click the Right Pane choice.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/737efc716ef319dacece658bb1529455_MD5.jpg)

Now that the Right Pane is visible, look at the dashboard in the middle of Brim. We want to look for the DNS entry, it can be found in the seventh result down. Once you find it, click on the entry.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/79b1a30711d7f3edc6c88ef9daeefe17_MD5.jpg)

After you have clicked on the DNS entry, look at the Right Pane which is the Log Details. In the Log Details, we are looking for the qclass_name in the left column. Look down through till you find it, once you do the answer will be found in the column on the right. Type the answer into the TryHackMe answer field, then type submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/43b0534c445580474789555e7e9ad5bf_MD5.jpg)

Answer: C_INTERNET

**Look at the details of the first NTP log that appear on the dashboard. What is the “duration” value?**

Head back to the VM and in the dashboard look for NTP, once you find it click on the entry. The details of this entry will show up in the Log Details on the right panel. Go to the Log Details and scroll to the bottom.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/109acc82adaf7efd8310b880d9131af6_MD5.jpg)

Once you reach the bottom, you will see the Duration column. To the right of this column is the answer. Once you find it, type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/f0069eafe470287a0599813091703fb0_MD5.jpg)

Answer: 0.005

**Look at the details of the STATS packet log that is visible on the dashboard. What is the “reassem_tcp_size”?**

Head back to the VM and in the dashboard scroll down till find STATS.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/c55b225f9a13b39b1be36d12b7ffc307_MD5.jpg)

Once you find STATS, click on it. Then look to the Log Details panel on the right. Watching the column on the left as you scroll for the label, reassem_tcp_size.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/fa649bc8eef775dbb93f7d15c891f5f2_MD5.jpg)

Once you find the column labeled reassem_tcp_size, look to the right of this column and you will see the answer. Once you find it, type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/538efd9db8a8a781e4609aac8bb3cc86_MD5.jpg)

Answer: 540

# Task 4 Default Queries

## Default Queries

We mentioned that Brim had 12 premade queries in the previous task. Let’s see them in action! Now, open Brim, import the sample pcap and go through the walkthrough.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/a5e339134359d4918c39f128ca576b09_MD5.jpg)

## Reviewing Overall Activity

This query provides general information on the pcap file. The provided information is valuable for accomplishing further investigation and creating custom queries. It is impossible to create advanced or case-specific queries without knowing the available log files.

The image on the left shows that there are 20 logs generated for the provided pcap file.

## Windows Specific Networking Activity

This query focuses on Windows networking activity and details the source and destination addresses and named pipe, endpoint and operation detection. The provided information helps investigate and understand specific Windows events like SMB enumeration, logins and service exploiting.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/f46b2d286f0a0389266116fb24f33992_MD5.jpg)

## Unique Network Connections and Transferred Data

These two queries provide information on unique connections and connection-data correlation. The provided info helps analysts detect weird and malicious connections and suspicious and beaconing activities. The uniq list provides a clear list of unique connections that help identify anomalies. The data list summarises the data transfer rate that supports the anomaly investigation hypothesis.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/7c132dc50eadf519ebb41b057da52505_MD5.jpg)

## DNS and HTTP Methods

These queries provide the list of the DNS queries and HTTP methods. The provided information helps analysts to detect anomalous DNS and HTTP traffic. You can also narrow the search by viewing the “HTTP POST” requests with the available query and modifying it to view the “HTTP GET” methods.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/5b58ba3fcbb022abd4dbd86f0723f2ea_MD5.jpg)

## File Activity

This query provides the list of the available files. It helps analysts to detect possible data leakage attempts and suspicious file activity. The query provides info on the detected file MIME and file name and hash values (MD5, SHA1).

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/391c07731e89ebde18ed4c5ea4747b55_MD5.jpg)

## IP Subnet Statistics

This query provides the list of the available IP subnets. It helps analysts detect possible communications outside the scope and identify out of ordinary IP addresses.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/566c9650da738e93940d7a586cbde312_MD5.jpg)

## Suricata Alerts

These queries provide information based on Suricata rule results. Three different queries are available to view the available logs in different formats (category-based, source and destination-based, and subnet based).

**Note:** Suricata is an open-source threat detection engine that can act as a rule-based Intrusion Detection and Prevention System. It is developed by the Open Information Security Foundation (OISF). Suricata works and detects anomalies in a similar way to [**Snort**](https://tryhackme.com/room/snort) and can use the same signatures.

See image

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/9c56967049a90d66b7ba197bf6e5da58_MD5.jpg)

### Answer the questions below

**Investigate the files. What is the name of the detected GIF file?**

On the VM, look to the left side panel of Brim. On this panel, you will see Queries, inside this panel you will see File Activity. Click on File Activity.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/975caa8fd7837e7d615d560c989ef14f_MD5.jpg)

Go to the center of Brim and you see all the instances that have to deal with files. Look down through the mime_type column till you find image/gif. Once you find it look to the row to the right, this is the answer to the question. Once you find it type the answer into the answer field on TryHackMe, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/4381b9a982bf7a165cb7571cf2b2e516_MD5.jpg)

Answer: cat01_with_hidden_text.gif

**Investigate the conn logfile. What is the number of the identified city names?**

Heading back to Brim, we need to sort through some files similar to how we did it in Zeek. There is a search bar above the table in the middle of Brim, click on it. Type in the search bar `_path=="conn"`, then press enter to search it. When it is finished, we need to look at the names of the columns to find the right one. Start scrolling to the right.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/a7cc250d2806a810cece8defe8f21cfd_MD5.jpg)

Since we need to know how many city names were identified, I think geo.resp.city is a good start.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/78d458d881db3ede9b19e75c96219447_MD5.jpg)

Time to use some skills learned from the Zeek room, and using the column name we found, let's build the command out. So the command we want to use is `_path=="conn" | cut geo.resp.city | sort | uniq -c`, then press enter to search with this command. We keep the first part of the command along ( `_path=="conn"`), we then pipe the result of the first part into cut. Using cut, we “cut” out the column that we specifically, in this case it is geo.resp.city, so that we can look at just that column (or any other that we would specify). We take the results from cut and pipe it through sort, this will sort the results alphabetically. The results of sort are then finally piped through uniq -c, this will take away any duplicates with the uniq then the -c counts them. After you have run this command through our pcap, you will be left with a result that all you need to do is count the number of city names you find. The answer is the number of city names that you counted. Type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/fb68b7e12d10c9810a04d22373450484_MD5.jpg)

Answer: 2

**Investigate the Suricata alerts. What is the Signature id of the alert category “Potential Corporate Privacy Violation”?**

Heading back to the VM, and in Brim look to the left side of the application. You will see the Queries panel, click on any of the Suricata Alerts.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/90a132841f5033a2b41ddfb7a4a4a2b2_MD5.jpg)

Move to the center of the Brim application you will see the search field has the syntax used to narrow down the alerts to information the query was looking for. So highlight everything from the first pipe ( | ) on the left to the end, then press delete to remove it. Press enter to search for `event_type=="alert"`.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/e77ce11c21f8987b4ba84bb19d6d08ec_MD5.jpg)

Time to scroll to the right looking that the column names for anything interesting.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/9cf3fcbdaa37f828707b7d9ca2c4aeac_MD5.jpg)

We found a column at looks interesting, the alert.signature_id. If you look we can see the answer below but lets see if we can declutter up the center display a bit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/ca38361ff64ec684c5bce5076eaeb449_MD5.jpg)

Go back up to the search field, type in the field `| cut alert.category, alert.signature_id`, the press enter to run the search with these parameters.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/06e83795946e9448429647683a133900_MD5.jpg)

Now that it looks cleaner, we can see the alert id that is related to Potential Corporate Privacy Violation. Once you find it, type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/497052abc3c5e89122d5488e22e2af7e_MD5.jpg)

Answer: 2,012,887

# Task 5 Use Cases

## Custom Queries and Use Cases

There are a variety of use case examples in traffic analysis. For a security analyst, it is vital to know the common patterns and indicators of anomaly or malicious traffic. In this task, we will cover some of them. Let’s review the basics of the Brim queries before focusing on the custom and advanced ones.

## Brim Query Reference

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/519c798712fecf1a5fb8576c64329c36_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/6fcb8dc12dfec3fd8c2750b2aa38d802_MD5.jpg)

**Note:** It is highly suggested to use field names and filtering options and not rely on the blind/irregular search function. Brim provides great indexing of log sources, but it is not performing well in irregular search queries. The best practice is always to use the field filters to search for the event of interest.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/93adf0e81f310ae477684f42d4841cfe_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/f1248fb4382d4e0efe7e5ec2c0495eaf_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/ea368c5d4a8c41ab0b43ef3b51ecb802_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/886763d456fe736c04c483a54827bba0_MD5.jpg)

# Task 6 Exercise Threat Hunting with Brim | Malware C2 Detection

It is just another malware campaign spread with CobaltStrike. We know an employee clicks on a link, downloads a file, and then network speed issues and anomalous traffic activity arises. Now, open Brim, import the sample pcap and go through the walkthrough.

**Let’s investigate the traffic sample to detect malicious C2 activities!**

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/9ed90199374a8b41f57c687e741b3d65_MD5.jpg)

Let’s look at the available logfiles first to see what kind of data artefact we could have. The image on the left shows that we have many alternative log files we could rely on. Let’s review the frequently communicated hosts before starting to investigate individual logs.

**Query:** `cut id.orig_h, id.resp_p, id.resp_h | sort | uniq -c | sort -r count`

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/9175d258149fa0f107642969e582182c_MD5.jpg)

This query provides sufficient data that helped us decide where to focus. The IP addresses “10.22.xx” and “104.168.xx” draw attention in the first place. Let’s look at the port numbers and available services before focusing on the suspicious IP address and narrowing our search.

**Query:** `_path=="conn" | cut id.resp_p, service | sort | uniq -c | sort -r count`

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/78aacfc4649286cd21563f9654bc2ae1_MD5.jpg)

Nothing extremely odd in port numbers, but there is a massive DNS record available. Let’s have a closer look.

**Query:** `_path=="dns" | count() by query | sort -r`

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/ac389d8b0f827b901461ecca3ad30594_MD5.jpg)

There are out-of-ordinary DNS queries. Let’s enrich our findings by using VirusTotal to identify possible malicious domains.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/39d9479d7cfe33f8d61e3efa83b6c728_MD5.jpg)

We have detected two additional malicious IP addresses (we have the IP 45.147.xx from the log files and gathered the 68.138.xx and 185.70.xx from VirusTotal) linked with suspicious DNS queries with the help of external research. Let’s look at the HTTP requests before narrowing down our investigation with the found malicious IP addresses.

**Query:** `_path=="http" | cut id.orig_h, id.resp_h, id.resp_p, method, host, uri | uniq -c | sort value.uri`

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/cbadb5b1473c3989e7e1d841af258890_MD5.jpg)

We detect a file download request from the IP address we assumed was malicious. Let’s validate this idea with VirusTotal and validate our hypothesis.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/b3b00e47bf01278835d16dad90269f64_MD5.jpg)

VirusTotal results show that the IP address “104.xx” is linked with a file. Once we investigated that file, we discover that these two findings are associated with CobaltStrike. Up to here, we’ve followed the abnormal activity and found the malicious IP addresses. Our findings represent the C2 communication. Now let’s conclude our hunt by gathering the low-hanging fruits with Suricata logs.

**Query:** `event_type=="alert" | count() by alert.severity,alert.category | sort count`

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/6ef3b9bfeb2e3071dfbf8e9445b9c4c7_MD5.jpg)

Now we can see the overall malicious activities detected by Suricata. Note that you can investigate the rest of the IP addresses to identify the secondary C2 traffic anomaly without using the Suricata logs. This task demonstrates two different approaches to detecting anomalies.

Investigating each alarm category and signature to enhance the threat-hunting activities and post-hunting system hardening operations is suggested. Please note, Adversaries using CobaltStrike are usually skilled threats and don’t rely on a single C2 channel. Common experience and use cases recommend digging and keeping the investigation by looking at additional C2 channels.

This concludes our hunt for the given case. Now, repeat this exercise in the attached VM and ask the questions below.

### Answer the questions below

**What is the name of the file downloaded from the CobaltStrike C2 connection?**

On Brim look at the Queries column on the left side of the tool. Inside this is HTTP Requests, it should be the fourth one down. Click on it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/fc83dbace7d2960e84500f651913dadf_MD5.jpg)

Move to the center of Brim now, we only have a handful of results. Start to scroll to the right.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/3f965ec6e70e3295c098362c63b54de0_MD5.jpg)

Look for the `Value>URI` section, looking down there this section you will see `/download/`, what follows is the name of the file that was downloaded to the system, and thus the answer to the question. Type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/06c47a0d228c8325fe1161e031445ac4_MD5.jpg)

Answer: 4564.exe

**What is the number of CobaltStrike connections using port 443?**

Going back to Brim, staying in the same row, move to the left to the host column. Click on the IP address, this is the IP address for CobaltStrike.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/f8b3e189e8e539e1e8c3dd1ceb704330_MD5.jpg)

This will put the details into the Details panel on the Right side of Brim.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/164b84fccb701d3d0d7f49f2baa18a87_MD5.jpg)

Now it’s time to build our filter so that we can find how many times a connection was made to CobaltStrike on port 443. So I will put the command filter here and then explain what it is doing, here is the command `_path=="conn" | 104.168.44.45 | cut id.orig_h, id.resp_p, id.resp_h | sort | uniq -c`. So first we are going to look at the `conn` path, then pipe that into the IP address for CobaltStrike. From the IP address, we then pipe the results into the cut function. The cut function then removes the id.orig_h, id.resp_p, id.resp_h to display in the main field, the results from cut are then piped into sort. Then Sort will then sort the results so far numerically, then those results are piped through uniq -c. Uniq will then remove any time an instance appears more than once., leaving one instance only, the `-c` will then show how many times the instance appears. Pressing enter will then run the filtering command.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/ad9ea78ec15814ceb86b4380986c2422_MD5.jpg)

Then, looking down at the results from the filter, you will have two results. Look at the results for port 443, it should be the second result. The amount of time the connection was made will be all the way to the right. Type the answer you find there into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/149d22836157d4e4d34041a58283d15e_MD5.jpg)

Answer: 328

**There is an additional C2 channel in used the given case. What is the name of the secondary C2 channel?**

Heading back to Brim, go to the IP address of the Value>id>resp_h, and right-click on it. A drop-down menu will appear, click copy on this menu.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/745933aaa0073b9bf57dc887d01d2516_MD5.jpg)

Open a new tab in your browser, and go to the website [VirusTotal.com](http://virustotal.com). Once there, click on the SEARCH button.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/aecaa5194ebf9673c5a567a9968ff322_MD5.jpg)

Now you will see a search bar in the bottom middle of the screen. Click on the search bar then press ctrl + v to paste IP address into it. After you have pasted in the IP address, press enter to search the IP address.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/020dee3bb827beb0818e74603cf7f1e5_MD5.jpg)

Once the page loads, click the RELATIONS tab.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/737301b044d12d0a4b8f6127050570db_MD5.jpg)

Now that you are on the RELATIONS tab, look down in the section labeled “Files Referring”. In this section you will see two files in the Name column. Since we already know that it is Cobalt Strike they were using, and DarkVNC would be another C2. So the other name in here is the name of the actual malware that will infect a system, and thus the answer to this question. Once you have found it, type the answer into the TryHackMe answer field, and click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/dd1c9c705f9e48f2b4f6b4f447aa139e_MD5.jpg)

Answer: IcedID

# Task 7 Exercise Threat Hunting with Brim | Crypto Mining

Cryptocurrencies are frequently on the agenda with their constantly rising value and legal aspect. The ability to obtain cryptocurrencies by mining other than purchasing is becoming one of the biggest problems in today’s corporate environments. Attackers not only compromise the systems and ask for a ransom, but sometimes they also install mining tools (cryptojacking). Other than the attackers and threat actors, sometimes internal threats and misuse of trust and privileges end up installing coin miners in the corporate environment.

Usually, mining cases are slightly different from traditional compromising activities. Internal attacks don’t typically contain major malware samples. However, this doesn’t mean they aren’t malicious as they are exploiting essential corporate resources like computing power, internet, and electricity. Also, crypto mining activities require third party applications and tool installations which could be vulnerable or create backdoors. Lastly, mining activities are causing network performance and stability problems. Due to these known facts, coin mining is becoming one of the common use cases of threat hunters.

Now, open Brim, import the sample pcap and go through the walkthrough.

**Let’s investigate a traffic sample to detect a coin mining activity!**

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/9c909c2de9fb1d05a355c8b4d09bfdee_MD5.jpg)

Let’s look at the available logfiles first to see what kind of data artefact we could have. The image on the left shows that we don’t have many alternative log files we could rely on. Let’s review the frequently communicated hosts to see if there is an anomaly indicator.

**Query:** `cut id.orig_h, id.resp_p, id.resp_h | sort | uniq -c | sort -r`

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/40528a54673efe4ec168f0df489338ab_MD5.jpg)

This query provided sufficient data that helped us decide where to focus. The IP address “192.168.xx” draws attention in the first place. Let’s look at the port numbers and available services before focusing on the suspicious IP address and narrowing our search.

**Query:** `_path=="conn" | cut id.resp_p, service | sort | uniq -c | sort -r count`

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/9d83836799d33751045f12308053c410_MD5.jpg)

There is multiple weird port usage, and this is not usual. Now, we are one step closer to the identification of the anomaly. Let’s look at the transferred data bytes to support our findings and find more indicators.

**Query:** `_path=="conn" | put total_bytes := orig_bytes + resp_bytes | sort -r total_bytes | cut uid, id, orig_bytes, resp_bytes, total_bytes`

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/233e2598f1581cbf61df7f260ee95ce5_MD5.jpg)

The query result proves massive traffic originating from the suspicious IP address. The detected IP address is suspicious. However, we don’t have many supportive log files to correlate our findings and detect accompanying activities. At this point, we will hunt the low hanging fruits with the help of Suricata rules. Let’s investigate the Suricata logs.  
**Query:** `event_type=="alert" | count() by alert.severity,alert.category | sort count`

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/9c65016738da38a30dfa956a99e0f455_MD5.jpg)

Suricata rules have helped us conclude our hunt quickly, as the alerts tell us we are investigating a “Crypto Currency Mining” activity. Let’s dig deeper and discover which data pool is used for the mining activity. First, we will list the associated connection logs with the suspicious IP, and then we will run a VirusTotal search against the destination IP.

**Query:** `_path=="conn" | 192.168.1.100`

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/5edac08653d4a27cdc90b72f439897df_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/c17c1c3cfa216e9abc93667d5cea37e6_MD5.jpg)

We investigated the first destination IP address and successfully identified the mining server. In real-life cases, you may need to investigate multiple IP addresses to find the event of interest.

Lastly, let’s use Suricata logs to discover mapped out MITRE ATT&CK techniques.

**Query:** `event_type=="alert" | cut alert.category, alert.metadata.mitre_technique_name, alert.metadata.mitre_technique_id, alert.metadata.mitre_tactic_name | sort | uniq -c`

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/375e6878fb3e2892a47adeca9a63f46f_MD5.jpg)

Now we can identify the mapped out MITRE ATT&CK details as shown in the table below.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/34df36d4fdc78de2bcb967a8cceceaa1_MD5.jpg)

This concludes our hunt for the given case. Now, repeat this exercise in the attached VM and ask the questions below.

### Answer the questions below

**How many connections used port 19999?**

To start off, look to the left side of Brim, in the queries section. Look for the query `Connection Received Data` and click on it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/cd38609947d8380c86bcdda679cf3f2c_MD5.jpg)

Now look to the middle section of Brim, we are going to need to modify the query. But first, we need to figure out the search term. Looking at the question, we need to find the port that it was connected to first, then the number of connections to that port. Since we are looking for the port it was connected to, then the term we need is `id.resp_p`.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/30a0de2f636e3b70a08412fa18b8d687_MD5.jpg)

Time to modify the query, delete everything after cut so that the query looks like this: `_path=="conn" | put total_bytes := orig_bytes | sort -r total_bytes | cut`.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/4c1a27a2b845931f8b1a3a9ee5e45723_MD5.jpg)

After the `cut` type `id.resp_p | sort | uniq -c | 19999`. Id.resp_p is the receiving port, sort will sort the whats left numerically, uniq -c with drop and duplicates and count it, and finally 19999 is searching for that number. so the full query should be `_path=="conn" | put total_bytes := orig_bytes | sort -r total_bytes | cut | id.resp | sort | uniq -c | 19999`.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/b931a50091e23f5967fe6efc781566fb_MD5.jpg)

You will only have one result in the bottom section, and the answer will be the column next to the port number. Once you see it, type the answer into the TryHackMe answer field and click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/9c51d080be16c35aeaeee2453e573d65_MD5.jpg)

Answer: 22

**What is the name of the service used by port 6666?**

You can find a hint above in the text. Scroll up till you see the query: `_path=="conn" | cut id.resp_p, service | sort | uniq -c | sort -r count`, we can use this with only minor modifications.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/7b0ac928756da362a9249ea126bdff60_MD5.jpg)

So let’s modify the query and put it into the Brim query field. You want to delete everything after `uniq`, then add `| 6666`. With this query we are looking at the connects because of the _path==”conn”. Then `cut`, literally cuts out these columns for the query. We then use `sort` to sort the answers so far, numerically. The `uniq` parameter takes away any duplicates and only shows one instance in the results. Finally `6666` searches for the number in the results. So the final query is `_path=="conn" | cut id.resp_p, service | sort | uniq | 6666`, that's it!! Type the query into the query field on Brim.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/9080b8c5c1a9b37ee3491237325c9a3c_MD5.jpg)

Now look below at the results of the query we searched. You will see the answer in the column to the right of the port. Once you see it, type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/e5462e35a1d3a8356c559d53c17025a5_MD5.jpg)

Answer: irc

**What is the amount of transferred total bytes to “101.201.172.235:8888”?**

To start off, look to the left side of Brim, in the queries section. Look for the query `Connection Received Data` and click on it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/cd38609947d8380c86bcdda679cf3f2c_MD5.jpg)

Now look to the middle section of Brim, we are going to need to modify the query. We need to delete out `uid, id, orig_bytes,and resp_bytes` from the query.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/2363ace174866b1faf20860548cf7014_MD5.jpg)

We are going to add `id.resp_h, id.resp_p,` in between cut and total_bytes.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/6febde9f8c1f25ac2ddede00a18cdd8c_MD5.jpg)

To finish up our query we need to add `sort | uniq | 101.201.172.235 | 8888` to the end. Then press enter to search this query

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/0493102d34cf1a10a0ef80d0c9b34b41_MD5.jpg)

Look at the results field under the query, you should only see one result. The column on the right will have the Total Bytes that the question is asking for. Once you see it, type the answer into the TryHackMe answer field, and click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/5e5b9501afc91df682ea153112e3267e_MD5.jpg)

Answer: 3,729

**What is the detected MITRE tactic id?**

If you look at the last section from the above reading we can see what we need to use in our query. From what we see we can understand how we must lay out the query.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/7ebe2025cc9f258b639cc31092e093a8_MD5.jpg)

To set up the query, we start with `event_type=="alert"` when then pipe to the next command. Since we want to see the tactic id and from looking at what the categories look like, the next part should be `cut alert.metadata.mitre_tactic_id`. Then finish up the query with my favorite two commands here, `sort` and `uniq`. So the final command should look like `event_type=="alert" | alert.metadata.mitre_tactic_id | sort | uniq`.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/dcaa35bfde51202a49f833cdfd95c8ae_MD5.jpg)

After typing in the command, press enter to search with the query. You will have two results in the below results field. The first one being the answer the second being an error. Once you see the answer, type it into the TryHackMe answer field, and press enter.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/08%20Brim/c2f0007ecdcbbc1fdd368e7421b4f868_MD5.jpg)

Answer: TA0040

# Task 8 Conclusion

**Congratulations!** You just finished the Brim room.

In this room, we covered Brim, what it is, how it operates, and how to use it to investigate threats.

Now, we invite you to complete the Brim challenge room: [**Masterminds**](https://tryhackme.com/room/mastermindsxlq)
