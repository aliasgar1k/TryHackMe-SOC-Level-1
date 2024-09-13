
https://www.youtube.com/watch?v=e1cwKwshC9I&t=863s
https://www.youtube.com/watch?v=-44q-q9ZQR0&pp=ygUOdHJ5aGFja21lIHplZWs%3D
https://www.youtube.com/watch?v=POC5Pjb2dOk&pp=ygUOdHJ5aGFja21lIHplZWs%3D

https://medium.com/@haircutfish/tryhackme-zeek-task-1-introduction-task-2-network-security-monitoring-and-zeek-task-3-zeek-929215235259
https://medium.com/@haircutfish/tryhackme-zeek-task-4-cli-kung-fu-recall-processing-zeek-logs-task-5-zeek-signatures-task-6-2aa827e24a41
https://medium.com/@haircutfish/tryhackme-zeek-task-7-zeek-scripts-scripts-and-signatures-task-8-zeek-scripts-frameworks-1bbab9f9be74

https://github.com/AnLoMinus/TryHackMe/tree/main/Learning%20Path/SOC%20Level%201/Network%20Security%20and%20Traffic%20Analysis/Zeek

Introduction to hands-on network monitoring and threat detection with Zeek (formerly Bro).

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/b48a48699a062813e625e6ea2b275f7a_MD5.jpg)

Zeek (formerly Bro) is an open-source and commercial network monitoring tool (traffic analyser).

[The official description;](https://docs.zeek.org/en/master/about.html) “Zeek (formerly Bro) is the world’s leading platform for network security monitoring. Flexible, open-source, and powered by defenders.” “Zeek is a passive, open-source network traffic analyser. Many operators use Zeek as a network security monitor (NSM) to support suspicious or malicious activity investigations. Zeek also supports a wide range of traffic analysis tasks beyond the security domain, including performance measurement and troubleshooting.”

The room aims to provide a general network monitoring overview and work with Zeek to investigate captured traffic. This room will expect you to have basic Linux familiarity and Network fundamentals (ports, protocols and traffic data). We suggest completing the “[**Network Fundamentals**](https://tryhackme.com/module/network-fundamentals)” path before starting working in this room.

A VM is attached to this room. You don’t need SSH or RDP; the room provides a “Split View” feature. Exercise files are located in the folder on the desktop. Log cleaner script **“clear-logs.sh”** is available in each exercise folder.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/91f56314050097ae33790cf967e3779f_MD5.jpg)

# Task 2 Network Security Monitoring and Zeek

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/5b71e46d5a9d9a897f5d69631479b523_MD5.jpg)

## Introduction to Network Monitoring Approaches

Network monitoring is a set of management actions to watch/continuously overview and optionally save the network traffic for further investigation. This action aims to detect and reduce network problems, improve performance, and in some cases, increase overall productivity. It is a main part of the daily IT/SOC operations and differs from Network Security Monitoring (NSM) in its purpose.

### Network Monitoring

Network monitoring is highly focused on IT assets like uptime (availability), device health and connection quality (performance), and network traffic balance and management (configuration). Monitoring and visualising the network traffic, troubleshooting, and root cause analysis are also part of the Network Monitoring process**.** This model is helpful for network administrators and usually doesn’t cover identifying non-asset in-depth vulnerabilities and significant security concerns like internal threats and zero-day vulnerabilities. Usually, Network Monitoring is not within the SOC scope. It is linked to the enterprise IT/Network management team.

### Network Security Monitoring

Network Security Monitoring is focused on network anomalies like rogue hosts, encrypted traffic, suspicious service and port usage, and malicious/suspicious traffic patterns in an intrusion/anomaly detection and response approach. Monitoring and visualising the network traffic and investigating suspicious events is a core part of Network Security Monitoring. This model is helpful for security analysts/incident responders, security engineers and threat hunters and covers identifying threats, vulnerabilities and security issues with a set of rules, signatures and patterns. Network Security Monitoring is part of the SOC, and the actions are separated between tier 1–2–3 analyst levels.

## What is ZEEK?

Zeek (formerly Bro) is an open-source and commercial passive Network Monitoring tool (traffic analysis framework) developed by Lawrence Berkeley Labs. Today, Zeek is supported by several developers, and Corelight provides an Enterprise-ready fork of Zeek. Therefore this tool is called both open source and commercial. The differences between the open-source version and the commercial version are detailed [here](https://corelight.com/products/compare-to-open-source-zeek?hsLang=en).

Zeek differs from known monitoring and IDS/IPS tools by providing a wide range of detailed logs ready to investigate both for forensics and data analysis actions. Currently, Zeek provides 50+ logs in 7 categories.

## Zeek vs Snort

While both are called IDS/NIDS, it is good to know the cons and pros of each tool and use them in a specific manner. While there are some overlapping functionalities, they have different purposes for usage.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/c983ab9dc41b929f288022d1c0203274_MD5.jpg)

## Zeek Architecture

Zeek has two primary layers; “Event Engine” and “Policy Script Interpreter”. The Event Engine layer is where the packets are processed; it is called the event core and is responsible for describing the event without focusing on event details. It is where the packages are divided into parts such as source and destination addresses, protocol identification, session analysis and file extraction. The Policy Script Interpreter layer is where the semantic analysis is conducted. It is responsible for describing the event correlations by using Zeek scripts.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/fb41362a5c5ebeed183153e010c31451_MD5.jpg)

## Zeek Frameworks

Zeek has several frameworks to provide extended functionality in the scripting layer. These frameworks enhance Zeek’s flexibility and compatibility with other network components. Each framework focuses on the specific use case and easily runs with Zeek installation. For instance, we will be using the “Logging Framework” for all cases. Having ide on each framework’s functionality can help users quickly identify an event of interest.

## Available Frameworks

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/2d417dccddd83856dd63bdb04757afe3_MD5.jpg)

You can read more on frameworks [**here**](https://docs.zeek.org/en/master/frameworks/index.html).

## Zeek Outputs

As mentioned before, Zeek provides 50+ log files under seven different categories, which are helpful in various areas such as traffic monitoring, intrusion detection, threat hunting and web analytics. This section is not intended to discuss the logs in-depth. The logs are covered in **TASK 3**.

Once you run Zeek, it will automatically start investigating the traffic or the given pcap file and generate logs automatically. Once you process a pcap with Zeek, it will create the logs in the working directory. If you run the Zeek as a service, your logs will be located in the default log path. The default log path is:`/opt/zeek/logs/`

## Working with Zeek

There are two operation options for Zeek. The first one is running it as a service, and the second option is running the Zeek against a pcap. Before starting working with Zeek, let’s check the version of the Zeek instance with the following command: `zeek -v`

Now we are sure that we have Zeek installed. Let’s start the Zeek as a service! To do this, we need to use the “ZeekControl” module, as shown below. The “ZeekControl” module requires superuser permissions to use. You can elevate the session privileges and switch to the superuser account to examine the generated log files with the following command: `sudo su`

Here we can manage the Zeek service and view the status of the service. Primary management of the Zeek service is done with three commands; “status”, “start”, and “stop”.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/5c5bb0e0b0a851037b13d1e84e977d77_MD5.jpg)

You can also use the “ZeekControl” mode with the following commands as well;

- `zeekctl status`
- `zeekctl start`
- `zeekctl stop`

The only way to listen to the live network traffic is using Zeek as a service. Apart from using the Zeek as a network monitoring tool, we can also use it as a packet investigator. To do so, we need to process the pcap files with Zeek, as shown below. Once you process a pcap file, Zeek automatically creates log files according to the traffic.

In pcap processing mode, logs are saved in the working directory. You can view the generated logs using the `ls -l` command.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/cc109c494213973f4e7d66ee85017611_MD5.jpg)

Main Zeek command line parameters are explained below;

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/15f6aff9b9c4245570626cd4299449c5_MD5.jpg)

Investigating the generated logs will require command-line tools (cat, cut, grep sort, and uniq) and additional tools (zeek-cut). We will cover them in the following tasks.

### Answer the questions below

Each exercise has a folder. Ensure you are in the right directory to find the pcap file and accompanying files. **Desktop/Exercise-Files/TASK-2**

On the VM, you will see a terminal icon in the middle of the VM screen on the right. Click on it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/589479031148fb985fd6b899d99baf98_MD5.jpg)

A terminal window will pop-up, time to move to the TASK-2 directory. To do this we will use the `cd` command, which stands for change directory. We will using this command in combination with Tab completion. With Tab complete, you only have to press Tab after starting to type, and if it only has one entry that matches, it will auto complete it. So let’s type out the command `cd Desktop/Exercise-Files/TASK-2`, then press enter to run the command.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/e79c1dae4df30ddeab486fbfcba491d5_MD5.jpg)

You are now in the proper directory, use the command `ls` to list the contents of the directory. We are now ready to move on to the next question.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/a8bd83ebe0ec1cfacabe71597b00fc03_MD5.jpg)

**What is the installed Zeek instance version number?**

If we look up above in the Working With Zeek section, we can find the correct parameter to run to get the version number of Zeek. In this case it is `zeek -v`.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/07a131b569d6aa8fdf10de98e35d100e_MD5.jpg)

Heading back to the terminal, we use the command from above, `zeek -v`, and press enter. It will output the current version of Zeek, and thus the answer to the question. Type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/72f511c6f605640e8143d87c835ec890_MD5.jpg)

Answer: 4.2.1

**What is the version of the ZeekControl module?**

From the table at the bottom of this task, we learned that we can use the command `zeekctl`, to start in the ZeekControl module.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/39ff9bf0516eb1404b70101dbb655a24_MD5.jpg)

Heading back to the terminal, we use the command from above, `zeekctl`, and press enter. It will output the current version of ZeekControl, and thus the answer to the question. Type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/436da02f0b9018981472bd5e6345dd9b_MD5.jpg)

Answer: 2.4.0

**Investigate the “sample.pcap” file. What is the number of generated alert files?**

Again we look at the table at the bottom of this task to get ther proper parameters. In our case we want to use the `-r`, this will process a pcap file and give use the log files.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/395bc2672320ffbbadbdad23ca6bdeae_MD5.jpg)

Heading back to the terminal, we use the command `zeek -r sample.pcap`, TryHackMe gave us the name of the file, so that is how we know name of the pcap file we want to parse.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/1b7e97bcacbb9a90e545b1b9229a8171_MD5.jpg)

After Zeek is done running we need to count the number of logs generated. To do this we can use the command `ls`, to list out the contents of the directory. Once the output of the dirctory is listed in the output, we just count everything that ends with .log. After counting them we will have our answer to the question. Type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/e3cbf618db0d42a025f913d0fbd652d9_MD5.jpg)

Answer: 8

# Task 3 Zeek Logs

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/87011a4ae001dfef97833ed645123dcb_MD5.jpg)

## Zeek Logs

Zeek generates log files according to the traffic data. You will have logs for every connection in the wire, including the application level protocols and fields. Zeek is capable of identifying 50+ logs and categorising them into seven categories. Zeek logs are well structured and tab-separated ASCII files, so reading and processing them is easy but requires effort. You should be familiar with networking and protocols to correlate the logs in an investigation, know where to focus, and find a specific piece of evidence.

Each log output consists of multiple fields, and each field holds a different part of the traffic data. Correlation is done through a unique value called “UID”. The “UID” represents the unique identifier assigned to each session.

### Zeek logs in a nutshell;

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/0230739d0913c52cdc236f07b86fe21c_MD5.jpg)

Please refer to [Zeek’s official documentation](https://docs.zeek.org/en/current/script-reference/log-files.html) and [Corelight log cheat sheet](https://corelight.com/about-zeek/zeek-data) for more information. Although there are multiple log files, some log files are updated daily, and some are updated in each session. Some of the most commonly used logs are explained in the given table.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/7683b871f8deb974ca900585945c6e80_MD5.jpg)

This is too much protocol and log information! Yes, it is true; a difficulty of working with Zeek is having the required network knowledge and investigation mindset. Don’t worry; you can have both of these and even more knowledge by working through TryHackMe paths. Just keep the streak!

### Brief log usage primer table;

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/5e040e73f0c6d6b45813e6cddee33b35_MD5.jpg)

You can categorise the logs before starting an investigation. Thus, finding the evidence/anomaly you are looking for will be easier. The given table is a brief example of using multiple log files. You can create your working model or customise the given one. Make sure you read each log description and understand the purpose to know what to expect from the corresponding log file. Note that these are not the only ones to focus on. Investigated logs are highly associated with the investigation case type and hypothesis, so do not just rely only on the logs given in the example table!

The table shows us how to use multiple logs to identify anomalies and run an investigation by correlating across the available logs.

- **Overall Info:** The aim is to review the overall connections, shared files, loaded scripts and indicators at once. This is the first step of the investigation.
- **Protocol Based:** Once you review the overall traffic and find suspicious indicators or want to conduct a more in-depth investigation, you focus on a specific protocol.
- **Detection:** Use the prebuild or custom scripts and signature outcomes to support your findings by having additional indicators or linked actions.
- **Observation:** The summary of the hosts, services, software, and unexpected activity statistics will help you discover possible missing points and conclude the investigation.

Remember, we mention the pros and cons of the Zeek logs at the beginning of this task. Now let’s demonstrate the log viewing and identify the differences between them.

**Recall 1:** Zeek logs are well structured and tab-separated ASCII files, so reading and processing them is easy but requires effort.

**Recall 2:** Investigating the generated logs will require command-line tools (cat, cut, grep sort, and uniq) and additional tools (zeek-cut).

**Opening a Zeek log with a text editor and built-in commands;**

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/b9d5a7d4eded2ecc1e4185c5571f4fd0_MD5.jpg)

The above image shows that reading the logs with tools is not enough to spot an anomaly quickly. Logs provide a vast amount of data to investigate and correlate. You will need to have technical knowledge and event correlation ability to carry out an investigation. It is possible to use external visualisation and correlation tools such as ELK and Splunk. We will focus on using and processing the logs with a hands-on approach in this room.

In addition to Linux command-line tools, one auxiliary program called `zeek-cut` reduces the effort of extracting specific columns from log files. Each log file provides "field names" in the beginning. This information will help you while using `zeek-cut`. Make sure that you use the "fields" and not the "types".

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/ef138ec577381474453647e048cec975_MD5.jpg)

Let’s see the “zeek-cut” in action. Let’s extract the uid, protocol, source and destination hosts, and source and destination ports from the conn.log. We will first read the logs with the `cat` command and then extract the event of interest fields with `zeek-cut` auxiliary to compare the difference.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/f74b6df601b87be888c68a401694cd6d_MD5.jpg)

As shown in the above output, the “zeek-cut” auxiliary provides massive help to extract specific fields with minimal effort. Now take time to read log formats, practice the log reading/extracting operations and answer the questions.

### Answer the questions below

Each exercise has a folder. Ensure you are in the right directory to find the pcap file and accompanying files. **Desktop/Exercise-Files/TASK-3**

You should still be in the TASK-2 directory, so we need to back up then move forward. To do this we use the command `cd ..`, which will back it up one directory. Then using the command `cd TASK-3`, we move forward into the TASK-3 directory. Finally use the `ls` command to list the contents.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/2c4c1263640ada4c5bfe534c299015a5_MD5.jpg)

**Investigate the sample.pcap file. Investigate the dhcp.log file. What is the available hostname?**

As we learned from the previous task to investigate the sample.pcap file, we need to use the command `zeek -r sample.pcap`, then press enter to run Zeek.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/cfc481ba03f3ba748c47064413dc379a_MD5.jpg)

Using `cat dhcp.log`, we will display the log file on the terminal. The reasoning behind this is to see what the fields names are. As we can see the one we want to look at is host_name.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/207c13a4f19f2cbbdc28ab5aca891c77_MD5.jpg)

If we look to the table in the above reading, we learn about a command called `zeek-cut`, we can use this command to cut different parts of the log file and output them to the terminal.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/81cee29d5b165acf11a98c5c21dd68f0_MD5.jpg)

Using the `zeek-cut` command, we then will display the log file to the terminal and pipe that through Zeek-cut. The full command will be `cat dhcp.log | zeek-cut host_name`, press enter to run the command. You will have the same name displayed twice, this is the hostname, and thus the answer to the question. Type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/086121fcf511889bc92a9f566a9ca8ad_MD5.jpg)

Answer: Microknoppix

**Investigate the dns.log file. What is the number of unique DNS queries?**

Using `cat dns.log`, we will display the log file on the terminal. The reasoning behind this is to see what the fields names are. As we can see the one we want to look at is query.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/37b8ba69b5596e7909960be244e0a8cb_MD5.jpg)

Now that we know the field name we need to use the command `cat dns.log | zeek-cut query | uniq`, we will pipe our zeek-cut response through the `uniq` command to get rid of multiples of the same response. So after running the command, count the number of responses output in the terminal, this is the answer to the question. Type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/1353a9e58f458b46e9f77a5d18695218_MD5.jpg)

Answer: 2

**Investigate the conn.log file. What is the longest connection duration?**

Using `cat conn.log`, we will display the log file on the terminal. The reasoning behind this is to see what the fields names are. As we can see the one we want to look at is duration.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/3556826238147318dd5327c47eaaec03_MD5.jpg)

So we will need to add some extra commands to get what we are looking for. First one is `sort -n`, which will sort the ouput and the -n will make that sorting numerical. Next is `tail -1`, this will normailly display the bottom 10 results, but since we use the -1, it will only show the final result. So the full command is `cat conn.log | zeek-cut duration | sort -n | tail -1`, after you have all this typed out, the result should be the longest duration, and thus the answer to the question. Type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/10db502d166a76d937259a121561a0b6_MD5.jpg)

Answer: 332.319364

# Task 4 CLI Kung-Fu Recall: Processing Zeek Logs

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/f5b76219cbffdc1970cee7d1285bdb9f_MD5.jpg)

## CLI Kung-Fu Recall: Processing Zeek Logs

Graphical User Interfaces (GUI) are handy and good for accomplishing tasks and processing information quickly. There are multiple advantages of GUIs, especially when processing the information visually. However, when processing massive amounts of data, GUIs are not stable and as effective as the CLI (Command Line Interface) tools.

The critical point is: What if there is no “function/button/feature” for what you want to find/view/extract?

Having the power to manipulate the data at the command line is a crucial skill for analysts. Not only in this room but each time you deal with packets, you will need to use command-line tools, Berkeley Packet Filters (BPF) and regular expressions to find/view/extract the data you are looking for. This task provides quick cheat-sheet like information to help you write CLI queries for your event of interest.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/6be620ae668c04c2acf24532efc5a963_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/c12cb886efd8192e0191ed0359538f02_MD5.jpg)

# Task 5 Zeek Signatures

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/5f7d2eb11f7e9a00242c7b88bf48b28a_MD5.jpg)

## Zeek Signatures

Zeek supports signatures to have rules and event correlations to find noteworthy activities on the network. Zeek signatures use low-level pattern matching and cover conditions similar to Snort rules. Unlike Snort rules, Zeek rules are not the primary event detection point. Zeek has a scripting language and can chain multiple events to find an event of interest. We focus on the signatures in this task, and then we will focus on Zeek scripting in the following tasks.

Zeek signatures are composed of three logical paths; signature id, conditions and action. The signature breakdown is shown in the table below;

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/2fa1e8f44d0c488ee2b0755b6452d8bc_MD5.jpg)

Now let’s dig more into the Zeek signatures. The below table provides the most common conditions and filters for the Zeek signatures.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/cd7a9cffc59bc51ab82b834b6be8104b_MD5.jpg)

**Run Zeek with signature file**

```
ubuntu@ubuntu$ zeek -C -r sample.pcap -s sample.sig
```

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/f5c912fae189e9d3202c38571c4cad95_MD5.jpg)

## Example | Cleartext Submission of Password

Let’s create a simple signature to detect HTTP cleartext passwords.

```
signature http-password {  
     ip-proto == tcp  
     dst_port == 80  
     payload /.*password.*/  
     event "Cleartext Password Found!"  
}  
  
# signature: Signature name.  
# ip-proto: Filtering TCP connection.  
# dst-port: Filtering destination port 80.  
# payload: Filtering the "password" phrase.  
# event: Signature match message.
```

Remember, Zeek signatures support regex. Regex “.*” matches any character zero or more times. The rule will match when a “password” phrase is detected in the packet payload. Once the match occurs, Zeek will generate an alert and create additional log files (signatures.log and notice.log).

**Signature Usage and Log Analysis**

```
ubuntu@ubuntu$ zeek -C -r http.pcap -s http-password.sig   
ubuntu@ubuntu$ ls  
clear-logs.sh  conn.log  files.log  http-password.sig  http.log  http.pcap  notice.log  packet_filter.log  signatures.log  
ubuntu@ubuntu$ cat notice.log  | zeek-cut id.orig_h id.resp_h msg   
10.10.57.178 44.228.249.3 10.10.57.178: Cleartext Password Found!  
10.10.57.178 44.228.249.3 10.10.57.178: Cleartext Password Found!  
ubuntu@ubuntu$ cat signatures.log | zeek-cut src_addr dest_addr sig_id event_msg   
10.10.57.178  http-password 10.10.57.178: Cleartext Password Found!  
10.10.57.178  http-password 10.10.57.178: Cleartext Password Found!
```
As shown in the above terminal output, the signatures.log and notice.log provide basic details and the signature message. Both of the logs also have the application banner field. So it is possible to know where the signature match occurs. Let’s look at the application banner!

**Log Analysis**

```
ubuntu@ubuntu$ cat signatures.log | zeek-cut sub_msg  
POST /userinfo.php HTTP/1.1\x0d\x0aHost: testphp.vulnweb.com\x0d\x0aUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:98.0) Gecko/20100101 Firefox/...  
ubuntu@ubuntu$ cat notice.log  | zeek-cut sub  
POST /userinfo.php HTTP/1.1\x0d\x0aHost: testphp.vulnweb.com\x0d\x0aUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:98.0) Gecko/20100101 Firefox/...
```

We will demonstrate only one log file output to avoid duplication after this point. You can practice discovering the event of interest by analysing notice.log and signatures.log.

## Example | FTP Brute-force

Let’s create another rule to filter FTP traffic. This time, we will use the FTP content filter to investigate command-line inputs of the FTP traffic. The aim is to detect FTP “admin” login attempts. This basic signature will help us identify the admin login attempts and have an idea of possible admin account abuse or compromise events.

```
signature ftp-admin {  
     ip-proto == tcp  
     ftp /.*USER.*dmin.*/  
     event "FTP Admin Login Attempt!"  
}
```
Let’s run the Zeek with the signature and investigate the signatures.log and notice.log.

**FTP Signature**

```
ubuntu@ubuntu$ zeek -C -r ftp.pcap -s ftp-admin.sig  
ubuntu@ubuntu$ cat signatures.log | zeek-cut src_addr dst_addr event_msg sub_msg | sort -r| uniq  
10.234.125.254 10.121.70.151 10.234.125.254: FTP Admin Login Attempt! USER administrator  
10.234.125.254 10.121.70.151 10.234.125.254: FTP Admin Login Attempt! USER admin 
```

Our rule shows us that there are multiple logging attempts with account names containing the “admin” phrase. The output gives us great information to notice if there is a brute-force attempt for an admin account.

This signature can be considered a case signature. While it is accurate and works fine, we need global signatures to detect the “known threats/anomalies”. We will need those case-based signatures for significant and sophistical anomalies like zero-days and insider attacks in the real-life environment. Having individual rules for each case will create dozens of logs and alerts and cause missing the real anomaly. The critical point is logging logically, not logging everything.

We can improve our signature by not limiting the focus only to an admin account. In that case, we need to know how the FTP protocol works and the default response codes. If you don’t know these details, please refer to [RFC documentation](https://datatracker.ietf.org/doc/html/rfc765).

**Let’s optimise our rule and make it detect all possible FTP brute-force attempts.**

This signature will create logs for each event containing “FTP 530 response”, which allows us to track the login failure events regardless of username.

```
signature ftp-brute {  
     ip-proto == tcp  
     payload /.*530.*Login.*incorrect.*/  
     event "FTP Brute-force Attempt"  
}
```

Zeek signature files can consist of multiple signatures. Therefore we can have one file for each protocol/situation/threat type. Let’s demonstrate this feature in our global rule.

```
signature ftp-username {  
    ip-proto == tcp  
    ftp /.*USER.*/  
    event "FTP Username Input Found!"  
}  
  
signature ftp-brute {  
    ip-proto == tcp  
     payload /.*530.*Login.*incorrect.*/  
    event "FTP Brute-force Attempt!"  
}
```

Let’s merge both of the signatures in a single file. We will have two different signatures, and they will generate alerts according to match status. The result will show us how we benefit from this action. Again, we will need the “CLI Kung-Fu” skills to extract the event of interest.

This rule should show us two types of alerts and help us to correlate the events by having “FTP Username Input” and “FTP Brute-force Attempt” event messages. Let’s investigate the logs. We’re grepping the logs in range 1001–1004 to demonstrate that the first rule matches two different accounts (admin and administrator).

**FTP Signature**

```
ubuntu@ubuntu$ zeek -C -r ftp.pcap -s ftp-admin.sig  
ubuntu@ubuntu$ cat notice.log | zeek-cut uid id.orig_h id.resp_h msg sub | sort -r| nl | uniq | sed -n '1001,1004p'  
  1001 CeMYiaHA6AkfhSnd 10.234.125.254 10.121.70.151 10.234.125.254: FTP Username Input Found! USER admin  
  1002 CeMYiaHA6AkfhSnd 10.234.125.254 10.121.70.151 10.121.70.151: FTP Brute-force Attempt! 530 Login incorrect.  
  1003 CeDTDZ2erDNF5w7dyf 10.234.125.254 10.121.70.151 10.234.125.254: FTP Username Input Found! USER administrator  
  1004 CeDTDZ2erDNF5w7dyf 10.234.125.254 10.121.70.151 10.121.70.151: FTP Brute-force Attempt! 530 Login incorrect.
```

## Snort Rules in Zeek?

While Zeek was known as Bro, it supported Snort rules with a script called snort2bro, which converted Snort rules to Bro signatures. However, after the rebranding, workflows between the two platforms have changed. [The official Zeek document](https://docs.zeek.org/en/master/frameworks/signatures.html) mentions that the script is no longer supported and is not a part of the Zeek distribution.

### Answer the questions below

Each exercise has a folder. Ensure you are in the right directory to find the pcap file and accompanying files. **Desktop/Exercise-Files/TASK-5**

On the VM, you will see a terminal icon in the middle of the VM screen on the right. Click on it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/589479031148fb985fd6b899d99baf98_MD5.jpg)

A terminal window will pop-up, time to move to the TASK-5 directory. To do this we will use the `cd` command, which stands for change directory. We will using this command in combination with Tab completion. With Tab complete, you only have to press Tab after starting to type, and if it only has one entry that matches, it will auto complete it. So let’s type out the command `cd Desktop/Exercise-Files/TASK-5`, then press enter to run the command. Follow up with the `ls` command to see the contents of the directory.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/70b750367e8f722ef42dcf921a935202_MD5.jpg)

Investigate the **http.pcap** file. 
**Create the HTTP signature shown in the task and investigate the pcap. What is the source IP of the first event?**

We need to move over to the http directory first, so using the command `cd http/`, and press enter to move forward into the directory. Then use the command `ls` to list the contents of the directory.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/aa86cbba1a086b283c39f712a0401655_MD5.jpg)

Time to open up the http-password.sig file in nano, use the command `nano http-password.sig`, then press enter.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/04d0af718c88264aa27d7a72075ec779_MD5.jpg)

The signature file will open in nano and you are just about ready to write the signature file.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/e06d663b011eab4e1e13efe1222d9c5e_MD5.jpg)

On the left side with the tasks, scroll up to the **Example | Cleartext Submission of Password**, you will see a carot with View Signature next to it. Click on an part of that to drop down the simple signature.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/181b57954a80104597639631b363c27a_MD5.jpg)

The code block will drop down, and you will see what we will be typing into the signature file in nano.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/577761d35fc21fb75e876a8dca83fcd1_MD5.jpg)

Going back to the VM type in the payload and event as shown in the example. After you are done press ctrl + s to save what you have typed.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/d8ce488dc64586f3aa3c266ad3046ea7_MD5.jpg)

Then press ctrl + x to close out of nano and go back to the terminal.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/7aa41c3547f49bf787634e064665889a_MD5.jpg)

Time to run our signature against, to do this we will use the command `zeek -C -r http.pcap -s http-password.sig`, then press enter to run Zeek. Then use the `ls` command to see the content of the directory.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/791cb3b2c5f343fd0a31fc50dacd3358_MD5.jpg)

Let’s find the source IP address of the first event, to do this we will use the command `cat signatures.log | zeek-cut src_addr sig_id`, then press enter for it to be output to the screen.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/38a1fea01bd6af8b07d25e075657567d_MD5.jpg)

The answer will be the IP address that appears in the output. Type it into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/29186947ed4688c9fb0ff27e2097eec2_MD5.jpg)

Answer: 10.10.57.178

**What is the source port of the second event?**

The answer to this can be found by running almost the same exact command, we just need to change one of the field in zeek-cut. So the command is `cat signatures.log | zeek-cut src_port sig_id`, then press enter. In the output look at the second result, that is the answer you are looking for. Type it into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/e26c04d3b80118d47a102b2e76686cbf_MD5.jpg)

Answer: 38712

Investigate the conn.log.
**What is the total number of the sent and received packets from source port 38706?**

This took some trial and error, but in the end when it comes to using zeek-cut, its all about having the right field. So when you figure out the proper field that’s when you are able to answer the question easliy.

For this one the fields was want to look at are the id.orig_p (port), orig_pkts (sent packets), and resp_pkts(recieved packets). So the command is `cat conn.log | zeek-cut id.orig_p orig_pkts resp_pkts | grep 38706`, then press enter to run. In the output will be the three fields, the one in red is the port that we grepped for. So the other two are the packets sent and recieved, add these two numbers together and you will have your answer to the question. Type it into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/639bd25b57d61891bb402fd421f4d73e_MD5.jpg)

Answer: 20

Create the global rule shown in the task and investigate the **ftp.pcap** file.

First we need to move over to the ftp directory, to do this we must move backward with `cd ..`, then forward with `cd ftp/`. Now we are in the ftp directory, we can list the contents of said directory with the `ls`command.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/e745b04be0b21f257bb4cd7a7eca4fce_MD5.jpg)

Now open the signature file with `nano ftp-bruteforce.sig`, and press enter.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/1d6442db283ba01d9ba775f6360fc333_MD5.jpg)

Go back to the left side of the page with the taskes on it, scroll up to the **Example | FTP Brute-force.** Then scroll down till you see the third **View Signature** and click on it. This will drop-down the code box, now we just need to copy two sections of this over to our signature file. Those sections being the ftp section in the ftp-username signature and the payload in the ftp-brute signature.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/8b9c18a5f5735208a4cfdc75b40a772d_MD5.jpg)

Go back to the VM and type the ftp and payload as shown in the example. After you are done press ctrl + s to save what you have typed.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/8d44b395286891a13413f55254913216_MD5.jpg)

Then press ctrl + x to close out of nano and go back to the terminal.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/460aba616a3a4d87407c39d6ec416691_MD5.jpg)

Time to run our signature against, to do this we will use the command `zeek -C -r ftp.pcap -s ftp-bruteforce.sig`, then press enter to run Zeek. Then use the `ls` command to see the content of the directory.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/4f4c2870f3e907fe52a692e1d62f9c5e_MD5.jpg)

**Investigate the notice.log. What is the number of unique events?**

To achieve this we need to preform several pipings, so the command is `cat notice.log | zeek-cut uid | sort | uniq | wc -l`, then press enter. So after we get the results from zeek-cut we pipe that into sort, where it is sorted alphabetically. Then we pipe the sorted results through uniq which will get rid of the dupicates. Finally we pipe the uniq results through wc -l which will count the number of lines, or in our case the number of results from uniq, and thus giving us the answer to the question. Type it into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/11499020e233c41af8bfd33a233a2255_MD5.jpg)

Answer: 1413

**What is the number of ftp-brute signature matches?**

To best figure this out we will look at the signatures.log file. Time to use zeek-cut once again, this time the command being `cat signatures.log | zeek-cut sig_id | grep "ftp-brute" | wc -l`, then click enter to run. So we are pulling the sig_id field with zeek-cut. We then pipe the results of that into grep, where we search for the string ftp-brute. Finally we pipe the grep results into wc -l, which will count the number of lines, or in our case the number of results from grep. The number that it outputs is the answer to the question, type it into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/d1f253f02f3ee39b2496933c2368ddeb_MD5.jpg)

Answer: 1410

# Task 6 Zeek Scripts | Fundamentals

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/74c287729a1146d0505647132628d1bf_MD5.jpg)

## Zeek Scripts

Zeek has its own event-driven scripting language, which is as powerful as high-level languages and allows us to investigate and correlate the detected events. Since it is as capable as high-level programming languages, you will need to spend time on Zeek scripting language in order to become proficient. In this room, we will cover the basics of Zeek scripting to help you understand, modify and create basic scripts. Note that scripts can be used to apply a policy and in this case, they are called policy scripts.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/2a84221e51273c0224f09934321d7417_MD5.jpg)

- Zeek scripts use the “.zeek” extension.
- Do not modify anything under the “zeek/base” directory. User-generated and modified scripts should be in the “zeek/site” directory.
- You can call scripts in live monitoring mode by loading them with the command `load @/script/path` or `load @script-name` in local.zeek file.
- Zeek is event-oriented, not packet-oriented! We need to use/write scripts to handle the event of interest.

**running Zeek with signature**

```
ubuntu@ubuntu$ zeek -C -r sample.pcap -s sample.sig
```

## GUI vs Scripts

Have you ever thought about automating tasks in Wireshark, tshark or tcpdump? Zeek provides that chance to us with its scripting power. Let’s say we need to extract all available DHCP hostnames from a pcap file. In that case, we have several options like using tcpdump, Wireshark, tshark or Zeek.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/1fe96b2dd9267745b62a380e6cbada7d_MD5.jpg)

Let’s see Wireshark on the stage first. You can have the same information with Wireshark. However, while this information can be extracted using Wireshark is not easy to transfer the data to another tool for processing. Tcpdump and tshark are command-line tools, and it is easy to extract and transfer the data to another tool for processing and correlating.

**extracting hostnames with tcpdump and tshark**

```
ubuntu@ubuntu$ sudo tcpdump -ntr smallFlows.pcap port 67 or port 68 -e -vv | grep 'Hostname Option' | awk -F: '{print $2}' | sort -nr | uniq | nl  
     1  "vinlap01"  
     2  "student01-PC"  
ubuntu@ubuntu$ tshark -V -r smallFlows.pcap -Y "udp.port==67 or udp.port==68" -T fields -e dhcp.option.hostname | nl | awk NF  
     1 student01-PC  
     2 vinlap01
```

Now let’s see Zeek scripts in action. First, let’s look at the components of the Zeek script. Here the first, second and fourth lines are the predefined syntaxes of the scripting language. The only part we created is the third line which tells Zeek to extract DHCP hostnames. Now compare this automation ease with the rest of the methods. Obviously, this four-line script is easier to create and use. While tcpdump and tshark can provide similar results, transferring uncontrolled data through multiple pipelines is not much preferred.

```
event dhcp_message (c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)  
{  
print options$host_name;  
}
```

Now let’s use the Zeek script and see the output.

**extracting hostnames with tcpdump and tshark**

```
ubuntu@ubuntu$ zeek -C -r smallFlows.pcap dhcp-hostname.zeek   
student01-PC  
vinlap01
```

The provided outputs show that our script works fine and can extract the requested information. This should show why Zeek is helpful in data extraction and correlation. Note that Zeek scripting is a programming language itself, and we are not covering the fundamentals of Zeek scripting. In this room, we will cover the logic of Zeek scripting and how to use Zeek scripts. You can learn and practice the Zeek scripting language by using [Zeek’s official training platform](https://try.bro.org/#/?example=hello) for free.

There are multiple options to trigger conditions in Zeek. Zeek can use “Built-In Function” (Bif) and protocols to extract information from traffic data. You can find supported protocols and Bif either by looking in your setup or visiting the [Zeek repo](https://docs.zeek.org/en/master/script-reference/scripts.html).

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/e3799d682b4a404070e4f92bd39caf3c_MD5.jpg)

### Answer the questions below

Each exercise has a folder. Ensure you are in the right directory to find the pcap file and accompanying files. **Desktop/Exercise-Files/TASK-6**

So we first have to take two steps back, then one step forward. We do this with preforming the command `cd ..` twice, followed by `cd TASK-6`. Finally we check the contents of the directory with the `ls` command.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/782b5212bdbf0b909dfe63812965b885_MD5.jpg)

**Investigate the smallFlows.pcap file. Investigate the dhcp.log file. What is the domain value of the “vinlap01” host?**

Move into the smallflow directory with `cd smallflow/`, then us `ls` to view the contents of the directory.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/5d3184d2516afe1531384dc93eb70e7a_MD5.jpg)

Now we are going to run Zeek against the smallflows.pcap with the dhcp-hostname.zeek, we do this with the command `zeek -C -r smallFlows.pcap dhcp-hostname.zeek`, then press enter to run it. Use `ls` to view the content of the directory now that Zeek has run.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/be2e1dac452a0527d18a13e2aac5b861_MD5.jpg)

Now time to widdle down some results with zeek-cut and piping, so after we cat dhcp.log we then pipe it into zeek-cut. With zeek-cut we just need the host name (host_name) and domain name (domain). We then pipe those results into grep, since we know the host name is vinlap01, that is what we are using in grep. The results from that will be the host name in red and the domain name in white, which will be your answer. Type it into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/2b38cc265f03e19babc78f3d9305d916_MD5.jpg)

Answer: astaro_vineyard

**Investigate the bigFlows.pcap file. Investigate the dhcp.log file. What is the number of identified unique hostnames?**

We have to move over to the bigflow directory, to do this we first back out of the current directory with `cd ..`, then forward with `cd bigflow/`. Then use `ls` to see the contents of the directory.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/aef39b3e71821ad4dc00e3e4f6133786_MD5.jpg)

Now we are going to run Zeek against the bigFlows.pcap with the dhcp-hostname.zeek, we do this with the command `zeek -C -r bigFlows.pcap dhcp-hostname.zeek`, then press enter to run it. This is a bigger file so give time to finish.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/59997d42ab10de95379c9f284c54974a_MD5.jpg)

When finished, use `ls`again to view the contents of the directory.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/d888cc2c6eab82a271e38a84ddf6cd4d_MD5.jpg)

Now usinging zeek-cut and piping let’s get this answer. The command we want to use is `cat dhcp.log | zeek-cut host_name | sort -nr | uniq`, then press enter. We will pipe the results of zeek-cut through sort, sorting it numerically and recursivly. Then use uniq to remove any dupicates, then all we have to do is count the output except the last one which isn’t a valid host name. The total number of the count is the answer to the question. Once you figure it out, type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/20644f41d1e5f1b6b9f1e529d34287c7_MD5.jpg)

Answer: 17

**Investigate the dhcp.log file. What is the identified domain value?**

Time to widdle down with zeek-cut and piping. The command we want to run is `cat dhcp.log | zeek-cut domain | sort | uniq`, then press enter. As before, after we get the results from zeek-cut we pipe that into sort, where it is sorted alphabetically. Then we pipe the sorted results through uniq which will get rid of the dupicates. You will have two outputs, one of which is clearly the answer. Once you figure it out, type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/ab87a7f4a271b8f579615299f02bb7ce_MD5.jpg)

Answer: jaalam.net

**Investigate the dns.log file. What is the number of unique queries?**

Now usinging zeek-cut and piping let’s get this answer. The command we want to use is `cat dns.log | zeek-cut query | sort -nr | uniq | grep -v -e ‘*’ -e ‘-’ | wc -l`, then press enter. We will pipe the results of zeek-cut through sort, sorting it numerically and recursivly. Then we pipe the sorted results through uniq which will get rid of the dupicates. Now we use grep not to find but to filter with the -v command, and the -e is for adding more or more filtering parameters/strings. Then finally we use wc -l which will count the number of lines, or in our case the number of results from grep, and thus giving us the answer to the question. Now type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/2671b95fd60db8be23a823687c367ebd_MD5.jpg)

Answer: 1109

# Task 7 Zeek Scripts | Scripts and Signatures

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/1c89a335b5cb9dc70e3adda77e2a46db_MD5.jpg)

## Scripts 101 | Write Basic Scripts

Scripts contain operators, types, attributes, declarations and statements, and directives. Let’s look at a simple example event called “zeek_init” and “zeek_done”. These events work once the Zeek process starts and stops. Note that these events don’t have parameters, and some events will require parameters.

**Sample Script**

```
event zeek_init()  
    {  
     print ("Started Zeek!");  
    }  
event zeek_done()  
    {  
    print ("Stopped Zeek!");  
    }  
# zeek_init: Do actions once Zeek starts its process.  
# zeek_done: Do activities once Zeek finishes its process.  
# print: Prompt a message on the terminal.
```

Run Zeek with the script

```
ubuntu@ubuntu$ zeek -C -r sample.pcap 101.zeek   
Started Zeek!  
Stopped Zeek!
```

The above output shows how the script works and provides messages on the terminal. Zeek will create logs in the working directory separately from the scripts tasks.

Let’s print the packet data to the terminal and see the raw data. In this script, we are requesting details of a connection and extracting them without any filtering or sorting of the data. To accomplish this, we are using the “new_connection” event. This event is automatically generated for each new connection. This script provides bulk information on the terminal. We need to get familiar with Zeek’s data structure to reduce the amount of information and focus on the event of interest. To do so, we need to investigate the bulk data.

**Sample Script**

```
event new_connection(c: connection)  
{  
 print c;  
}
```

Run Zeek with the script

```
ubuntu@ubuntu$ zeek -C -r sample.pcap 102.zeek   
[id=[orig_h=192.168.121.40, orig_p=123/udp, resp_h=212.227.54.68, resp_p=123/udp], orig=[size=48, state=1, num_pkts=0, num_bytes_ip=0, flow_label=0, l2_addr=00:16:47:df:e7:c1], resp=[size=0, state=0, num_pkts=0, num_bytes_ip=0, flow_label=0, l2_addr=00:00:0c:9f:f0:79], start_time=1488571365.706238, duration=0 secs, service={}, history=D, uid=CajwDY2vSUtLkztAc, tunnel=, vlan=121, inner_vlan=, dpd=, dpd_state=, removal_hooks=, conn=, extract_orig=F, extract_resp=F, thresholds=, dce_rpc=, dce_rpc_state=, dce_rpc_backing=, dhcp=, dnp3=, dns=, dns_state=, ftp=, ftp_data_reuse=F, ssl=, http=, http_state=, irc=, krb=, modbus=, mysql=, ntlm=, ntp=, radius=, rdp=, rfb=, sip=, sip_state=, snmp=, smb_state=, smtp=, smtp_state=, socks=, ssh=, syslog=]
```

The above terminal provides bulk data for each connection. This style is not the best usage, and in real life, we will need to filter the information for specific purposes. If you look closely at the output, you can see an ID and field value for each part.

To filter the event of interest, we will use the primary tag (in this case, it is c — comes from “c: connection” — ), id value (id=), and field name. You should notice that the fields are the same as the fields in the log files.

**Sample Script**

```
event new_connection(c: connection)  
{  
 print ("###########################################################");  
 print ("");  
 print ("New Connection Found!");  
 print ("");  
 print fmt ("Source Host: %s # %s --->", c$id$orig_h, c$id$orig_p);  
 print fmt ("Destination Host: resp: %s # %s <---", c$id$resp_h, c$id$resp_p);  
 print ("");  
}  
# %s: Identifies string output for the source.  
# c$id: Source reference field for the identifier.
```

Now you have a general idea of running a script and following the provided output on the console. Let’s look closer to another script that extracts specific information from packets. The script above creates logs and prompts each source and destination address for each connection.

Let’s see this script in action.

ubuntu@ubuntu$ zeek -C -r sample.pcap 103.zeek   
###########################################################  
New Connection Found! Source Host: 192.168.121.2 # 58304/udp --->   
Destination Host: resp: 192.168.120.22 # 53/udp <---   
###########################################################

The above output shows that we successfully extract specific information from the events. Remember that this script extracts the event of interest (in this example, a new connection), and we still have logs in the working directory. We can always modify and optimise the scripts at any time.

## Scripts 201 | Use Scripts and Signatures Together

Up to here, we covered the basics of Zeek scripts. Now it is time to use scripts collaboratively with other scripts and signatures to get one step closer to event correlation. Zeek scripts can refer to signatures and other Zeek scripts as well. This flexibility provides a massive advantage in event correlation.

Let’s demonstrate this concept with an example. We will create a script that detects if our previously created “**ftp-admin**” rule has a hit.

**Sample Script**

```
event signature_match (state: signature_state, msg: string, data: string)  
{  
if (state$sig_id == "ftp-admin")  
    {  
    print ("Signature hit! --> #FTP-Admin ");  
    }  
}
```

This basic script quickly checks if there is a signature hit and provides terminal output to notify us. We are using the “signature_match” event to accomplish this. You can read more about events [here](https://docs.zeek.org/en/master/scripts/base/bif/event.bif.zeek.html?highlight=signature_match). Note that we are looking only for “ftp-admin” signature hits. The signature is shown below.

**Sample Script**

```
signature ftp-admin {  
    ip-proto == tcp  
    ftp /.*USER.*admin.*/  
    event "FTP Username Input Found!"  
}
```

Let’s see this script in action.

```
ubuntu@ubuntu$ zeek -C -r ftp.pcap -s ftp-admin.sig 201.zeek   
Signature hit! --> #FTP-Admin Signature hit! --> #FTP-Admin  
Signature hit! --> #FTP-Admin Signature hit! --> #FTP-Admin
```

The above output shows that we successfully combined the signature and script. Zeek processed the signature and logs then the script controlled the outputs and provided a terminal output for each rule hit.

## Scripts 202 | Load Local Scripts

### Load all local scripts

We mentioned that Zeek has base scripts located in “/opt/zeek/share/zeek/base”. You can load all local scripts identified in your “local.zeek” file. Note that base scripts cover multiple framework functionalities. You can load all base scripts by easily running the `local` command.

```
ubuntu@ubuntu$ zeek -C -r ftp.pcap local   
ubuntu@ubuntu$ ls  
101.zeek  103.zeek          clear-logs.sh  ftp.pcap            packet_filter.log  stats.log  
102.zeek  capture_loss.log  conn.log       loaded_scripts.log  sample.pcap        weird.log
``` 

The above output demonstrates how to run all base scripts using the “local” command. Look at the above terminal output; Zeek provided additional log files this time. Loaded scripts generated loaded_scripts.log, capture_loss.log, notice.log, stats.log files. Note that, in our instance, 465 scripts loaded and used by using the “local” command. However, Zeek doesn’t provide log files for the scripts doesn’t have hits or results.

### Load Specific Scripts

Another way to load scripts is by identifying the script path. In that case, you have the opportunity of loading a specific script or framework. Let’s go back to FTP brute-forcing case. We created a script that detects multiple admin login failures in previous steps. Zeek has an FTP brute-force detection script as well. Now let’s use the default script and identify the differences.

```
ubuntu@ubuntu$ zeek -C -r ftp.pcap /opt/zeek/share/zeek/policy/protocols/ftp/detect-bruteforcing.zeek   

ubuntu@ubuntu$ cat notice.log | zeek-cut ts note msg   
1024380732.223481 FTP::Bruteforcing 10.234.125.254 had 20 failed logins on 1 FTP server in 0m1s
```

### Answer the questions below

Each exercise has a folder. Ensure you are in the right directory to find the pcap file and accompanying files. **Desktop/Exercise-Files/TASK-7**

On the VM, you will see a terminal icon in the middle of the VM screen on the right. Click on it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/589479031148fb985fd6b899d99baf98_MD5.jpg)

A terminal window will pop-up, time to move to the TASK-7 directory. To do this we will use the `cd` command, which stands for change directory. We will using this command in combination with Tab completion. With Tab complete, you only have to press Tab after starting to type, and if it only has one entry that matches, it will auto complete it. So let’s type out the command `cd Desktop/Exercise-Files/TASK-7`, then press enter to run the command. Follow up with the `ls` command to see the contents of the directory.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/5f00286dc4b17d69bd6a839b017732ac_MD5.jpg)

Go to folder **TASK-7/101**.  
Investigate the **sample.pcap** file with **103.zeek script**. Investigate the **terminal output**. 

**What is the number of the detected new connections?**

Move into directory 101 with `cd 101/`, the press enter. Then use `ls` to look at the contents of the directory.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/d1060b43a7010c27e843b75fdd24f792_MD5.jpg)

So as we have done before we want to run Zeek against the sample.pcap file. To do this we use the command `zeek -C -r sample.pcap 103.zeek`, and press enter to run it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/683d81b595580a14a3220b368909b4f5_MD5.jpg)

First thing we notice is that there is a lot of output to try and count. So let’s have the terminal do the counting for us.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/6706a972cf1d51b77a543e4b4a5d579a_MD5.jpg)

We can do this by using some commands that we have used before and piping. The full command is `` zeek -C -r sample.pcap 103.zeek | grep "New Connections Found!" | uniq -c` ``then press enter to run. The output will give you the count of the total number of new connections found, and thus the answer to the question. Type it into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/4e12a2aa80645b92a2f1a4a24fa72afd_MD5.jpg)

Answer: 87

Go to folder **TASK-7/201**.  
Investigate the **ftp.pcap** file with **ftp-admin.sig** signature and **201.zeek** script. Investigate the **signatures.log** file. 

**What is the number of signature hits?**

We have to move back the forward again, first use the command `cd ..`, then move forward with the command `cd 201/`. Finally use `ls`, to see the contents of the directory.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/c1c27aaa32b40a81621acfe031aca39f_MD5.jpg)

Let’s run Zeek against the ftp.pcap file. We will use the command `zeek -C -r ftp.pcap 201.zeek -s ftp-admin.sig`, the press enter to run.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/7736ea22136799d215f38fa65f2476d6_MD5.jpg)

After it is done running we will use the `ls` command to see the contents of the directory.

![](https://miro.medium.com/v2/resize:fit:818/1*fisIfhHKbWgJjYdhfyJfrg.png)

Now we can parse the signature file and find out how many times it was hit. So using zeek-cut, piping, and uniq -c. The command is `cat signatures.log | zeek-cut sig_id | uniq -c`, then press enter. You will have the count in the output, and thus the answer to the question. Type it into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/d09543111e1ab4d7525df7626fdc03fb_MD5.jpg)

Answer: 1401

**Investigate the signatures.log file. What is the total number of “administrator” username detections?**

We need to figure out what column this we need to cut and inspect. To do this we will use the command `cat signatures.log | less`, then press enter.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/0be23c42b31dadb748e712d2ed4c5513_MD5.jpg)

When the log file is open in less, use the right arrow to scroll to the right. Do this to you reach the last column.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/9e6d9dddb4cfd91bc05910784d4c3f5b_MD5.jpg)

So the column we want is the third from the last, so now that we know what column, we want to look at the column names. You might have to scroll to the left one press, I do.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/cef22b47b14a3034b6b5aac20dda7367_MD5.jpg)

Count the column names till you reach the third one, we now have the name of the column to run through zeek-cut. Then press `q` to exit less.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/2ec934a848fd93813c44e73b2f8818c2_MD5.jpg)

Time to run some zeek-cut and piping, the command we want to run is `cat signatures.log | zeek-cut sub_msg | sort | uniq -c`, then press enter to run. You will have the count for the amount of times User administrator was hit in the output, and thus the answer to the question. Type it into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/2d130477fea561f5d65582a33dd07ce6_MD5.jpg)

Answer: 731

**Investigate the ftp.pcap file with all local scripts, and investigate the loaded_scripts.log file. What is the total number of loaded scripts?**

Time to run zeek with local, the command we want to run is `zeek -C -r ftp.pcap local`, the press enter. Then use `ls` to see the contents of the directory.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/b63756761c3b58b1bdeef66b178a10a7_MD5.jpg)

We need to figure out what how we need to filter and count the log file. To do this we can pipe the loaded_scripts.log file through less, with command `cat loaded_scripts.log | less`, then press enter to run.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/3c5c9cb380a45038b95e3ea9dd2115f4_MD5.jpg)

So we can see that the loaded scripts seem to have the same path, this gives us a good filter we can use. Press `q` to exit less.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/2e9369c92685c438f655074654b91b17_MD5.jpg)

Time to use grep and wc -l. The command we want to use is `cat loaded_scripts.log | grep "/opt/*" | wc -l`, then press enter to run. You will have the count for the amount loaded scripts in the output, and thus the answer to the question. Type it into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/c79ab4e515e710a503ddf57401182332_MD5.jpg)

Answer: 498

Go to folder **TASK-7/202**.  
Investigate the **ftp-brute.pcap** file with **“/opt/zeek/share/zeek/policy/protocols/ftp/detect-bruteforcing.zeek”** script. Investigate the **notice.log** file. 

**What is the total number of brute-force detections?**

To start we need to move over to the proper directory, we can do this will the command `cd ..`, to move back. Then move forward with `cd 202/`. We finish off with the `ls` command to see the contents of the directory.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/98638bd6b14796c19f32e785d142fc91_MD5.jpg)

TryHackMe gives us all we need for the command in the question. The command then being `zeek -C -r ftp-brute.pcap /opt/zeek/share/zeek/policy/protocols/ftp/detect-bruteforcing.zeek`, then press enter to run the command. Then `ls` to see the changes to the contents of the directory.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/bee9dc9cce29cb187289d4048a16058b_MD5.jpg)

Time to pipe some zeek-cut! The command I ran was `cat notice.log | zeek-cut uid`, then press enter to run. The out was only 1 dash (-), but when I typed that into the TryHackMe answer field it said that answer was not correct.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/7a57fdf29a6fe5046e3fa341c7531c54_MD5.jpg)

So I then ran `cat notice.log | less`, then pressed enter, to see what I could be doing wrong. When the log file loads into less, press the right arrow once.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/cc9977b4f765691d4c7ee86aa72d4ac7_MD5.jpg)

As you can see from my results below, the results are 1. So not sure. So for the answer I tried the next number in the sequence and got it right. I also made a post in the TryHackMe discord about it. If you get a different result I’d love to know!!

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/3a5a68c2f1ed9f1739bcc70ed701d133_MD5.jpg)

Answer: 2

# Task 8 Zeek Scripts | Frameworks

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/b72c13b1ee504ed29c13a620e8ae1d04_MD5.jpg)

## Scripts 203 | Load Frameworks

Zeek has 15+ frameworks that help analysts to discover the different events of interest. In this task, we will cover the common frameworks and functions. You can find and read more on the prebuilt scripts and frameworks by visiting Zeek’s online book [here](https://docs.zeek.org/en/master/frameworks/index.html).

### File Framework | Hashes

Not all framework functionalities are intended to be used in CLI mode. The majority of them are used in scripting. You can easily see the usage of frameworks in scripts by calling a specific framework as `load @ $PATH/base/frameworks/framework-name`. Now, let's use a prebuilt function of the file framework and have MD5, SHA1 and SHA256 hashes of the detected files. We will call the "File Analysis" framework's "hash-all-files" script to accomplish this. Before loading the scripts, let's look at how it works.

```
ubuntu@ubuntu$ cat hash-demo.zeek   
# Enable MD5, SHA1 and SHA256 hashing for all files.  
@load /opt/zeek/share/zeek/policy/frameworks/files/hash-all-files.zeek
```

The above output shows how frameworks are loaded. In earlier tasks, we mentioned that Zeek highly relies on scripts, and the frameworks depend on scripts. Let’s have a closer look at the file hash framework and see the script behind it.

```
ubuntu@ubuntu$ cat /opt/zeek/share/zeek/policy/frameworks/files/hash-all-files.zeek   
# Enable MD5, SHA1 and SHA256 hashing for all files.  
  
@load base/files/hash  
event file_new(f: fa_file)  
 {  
 Files::add_analyzer(f, Files::ANALYZER_MD5);  
 Files::add_analyzer(f, Files::ANALYZER_SHA1);  
 Files::add_analyzer(f, Files::ANALYZER_SHA256);  
 }
```

Now let’s execute the script and investigate the log file.

```
ubuntu@ubuntu$ zeek -C -r case1.pcap hash-demo.zeek  
ubuntu@ubuntu$ zeek -C -r case1.pcap /opt/zeek/share/zeek/policy/frameworks/files/hash-all-files.zeek   

ubuntu@ubuntu$ cat files.log | zeek-cut md5 sha1 sha256  
cd5a4d3fdd5bffc16bf959ef75cf37bc 33bf88d5b82df3723d5863c7d23445e345828904 6137f8db2192e638e13610f75e73b9247c05f4706f0afd1fdb132d86de6b4012  
b5243ec1df7d1d5304189e7db2744128 a66bd2557016377dfb95a87c21180e52b23d2e4e f808229aa516ba134889f81cd699b8d246d46d796b55e13bee87435889a054fb  
cc28e40b46237ab6d5282199ef78c464 0d5c820002cf93384016bd4a2628dcc5101211f4 749e161661290e8a2d190b1a66469744127bc25bf46e5d0c6f2e835f4b92db18
```

Look at the above terminal outputs. Both of the scripts provided the same result. Here the preference is up to the user. Both of the usage formats are true. Prebuilt frameworks are commonly used in scriptings with the “@load” method. Specific scripts are used as practical scripts for particular use cases.

### File Framework | Extract Files

The file framework can extract the files transferred. Let’s see this feature in action!

```
ubuntu@ubuntu$ zeek -C -r case1.pcap /opt/zeek/share/zeek/policy/frameworks/files/extract-all-files.zeek  

ubuntu@ubuntu$ ls  
101.zeek  102.zeek  103.zeek  case1.pcap  clear-logs.sh  conn.log  dhcp.log  dns.log  extract_files  files.log  ftp.pcap  http.log  packet_filter.log  pe.log
```

We successfully extracted files from the pcap. A new folder called “extract_files” is automatically created, and all detected files are located in it. First, we will list the contents of the folder, and then we will use the `file` command to determine the file type of the extracted files.

```
ubuntu@ubuntu$ ls extract_files | nl  
     1 extract-1561667874.743959-HTTP-Fpgan59p6uvNzLFja  
     2 extract-1561667889.703239-HTTP-FB5o2Hcauv7vpQ8y3  
     3 extract-1561667899.060086-HTTP-FOghls3WpIjKpvXaEl  

ubuntu@ubuntu$ cd extract_files  

ubuntu@ubuntu$ file *| nl  
     1 extract-1561667874.743959-HTTP-Fpgan59p6uvNzLFja:  ASCII text, with no line terminators  
     2 extract-1561667889.703239-HTTP-FB5o2Hcauv7vpQ8y3:  Composite Document File V2 Document, Little Endian, Os: Windows, Version 6.3, Code page: 1252, Template: Normal.dotm, Last Saved By: Administrator, Revision Number: 2, Name of Creating Application: Microsoft Office Word, Create Time/Date: Thu Jun 27 18:24:00 2019, Last Saved Time/Date: Thu Jun 27 18:24:00 2019, Number of Pages: 1, Number of Words: 0, Number of Characters: 1, Security: 0  
     3 extract-1561667899.060086-HTTP-FOghls3WpIjKpvXaEl: PE32 executable (GUI) Intel 80386, for MS Windows
```

Zeek extracted three files. The “file” command shows us one .txt file, one .doc/.docx file and one .exe file. Zeek renames extracted files. The name format consists of four values that come from conn.log and files.log files; default “extract” keyword, timestamp value (ts), protocol (source), and connection id (conn_uids). Let’s look at the files.log to understand possible anomalies better and verify the findings. Look at the below output; files.log provides the same results with additional details. Let’s focus on the .exe and correlate this finding by searching its connection id (conn_uids).

The given terminal output shows us that there are three files extracted from the traffic capture. Let’s look at the file.log and correlate the findings with the rest of the log files.

```
ubuntu@ubuntu$ cat files.log | zeek-cut fuid conn_uids tx_hosts rx_hosts mime_type extracted | nl  
     1 Fpgan59p6uvNzLFja CaeNgL1QzYGxxZPwpk 23.63.254.163 10.6.27.102 text/plain extract-1561667874.743959-HTTP-Fpgan59p6uvNzLFja  
     2 FB5o2Hcauv7vpQ8y3 CCwdoX1SU0fF3BGBCe 107.180.50.162 10.6.27.102 application/msword extract-1561667889.703239-HTTP-FB5o2Hcauv7vpQ8y3  
     3 FOghls3WpIjKpvXaEl CZruIO2cqspVhLuAO9 107.180.50.162 10.6.27.102 application/x-dosexec extract-1561667899.060086-HTTP-FOghls3WpIjKpvXaEl  

ubuntu@ubuntu$ grep -rin CZruIO2cqspVhLuAO9 * | column -t | nl | less -S  
#NOTE: The full output is not shown here!. Redo the same actions in the attached VM!  
     1 conn.log:43:1561667898.852600   CZruIO2cqspVhLuAO9  10.6.27.102     49162        107.180.50.162      80    tcp  http          
     2 files.log:11:1561667899.060086  FOghls3WpIjKpvXaEl  107.180.50.162  10.6.27.102  CZruIO2cqspVhLuAO9  HTTP  0    EXTRACT,PE    
     3 http.log:11:1561667898.911759   CZruIO2cqspVhLuAO9  10.6.27.102     49162        107.180.50.162      80    1    GET         
```

The “grep” tool helps us investigate the particular value across all available logs. The above terminal output shows us that the connection id linked with .exe appears in conn.log, files.log, and http.log files. Given example demonstrates how to filter some fields and correlate the findings with the rest of the logs. We’ve listed the source and destination addresses, file and connection id numbers, MIME types, and file names. Up to now, provided outputs and findings show us that record number three is a .exe file, and other log files provide additional information.

### Notice Framework | Intelligence

The intelligence framework can work with data feeds to process and correlate events and identify anomalies. The intelligence framework requires a feed to match and create alerts from the network traffic. Let’s demonstrate a single user-generated threat intel file and let Zeek use it as the primary intelligence source.

Intelligence source location: `/opt/zeek/intel/zeek_intel.txt`

There are two critical points you should never forget. First, the source file has to be tab-delimited. Second, you can manually update the source and adding extra lines doesn’t require any re-deployment. However, if you delete a line from the file, you will need to re-deploy the Zeek instance.

Let’s add the suspicious URL gathered from the case1.pcap file as a source intel and see this feature in action! Before executing the script, let’s look at the intelligence file and the script contents.

Investigate intel file and script

```
ubuntu@ubuntu$ cat /opt/zeek/intel/zeek_intel.txt   
#fields indicator indicator_type meta.source meta.desc  
smart-fax.com Intel::DOMAIN zeek-intel-test Zeek-Intelligence-Framework-Test  

ubuntu@ubuntu$ cat intelligence-demo.zeek   
# Load intelligence framework!  
@load policy/frameworks/intel/seen  
@load policy/frameworks/intel/do_notice  
redef Intel::read_files += { "/opt/zeek/intel/zeek_intel.txt" }; 
```

The above output shows the contents of the intel file and script contents. There is one intelligence input, and it is focused on a domain name, so when this domain name appears in the network traffic, Zeek will create the “intel.log” file and provide the available details.

```
ubuntu@ubuntu$ zeek -C -r case1.pcap intelligence-demo.zeek   

ubuntu@ubuntu$ cat intel.log | zeek-cut uid id.orig_h id.resp_h seen.indicator matched  
CZ1jLe2nHENdGQX377 10.6.27.102 10.6.27.1 smart-fax.com Intel::DOMAIN   
C044Ot1OxBt8qCk7f2 10.6.27.102 107.180.50.162 smart-fax.com Intel::DOMAIN 
```

The above output shows that Zeek detected the listed domain and created the intel.log file. This is one of the easiest ways of using the intelligence framework. You can read more on the intelligence framework [here](https://docs.zeek.org/en/master/frameworks/intel.html) and [here](https://docs.zeek.org/en/current/scripts/base/frameworks/intel/main.zeek.html#type-Intel::Type).

### Answer the questions below

Each exercise has a folder. Ensure you are in the right directory to find the pcap file and accompanying files. **Desktop/Exercise-Files/TASK-8**

So we will back out of two directories, then move forward into the TASK-8 directory. To do this start with the command `cd ..`, do this twice. Then `cd TASK-8/`, and finish up with `ls` to list the contents of the directory.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/afc7dede10d54a4eccbec36c52cacf3b_MD5.jpg)

**Investigate the case1.pcap file with intelligence-demo.zeek script. Investigate the intel.log file. Look at the second finding, where was the intel info found?**

Start by running zeek with the command `zeek -C -r case1.pcap intelligence-demo.zeek`, and press enter. Then use `ls` to view the contents of the directory.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/bed64b1137da1046c66673d7bac04885_MD5.jpg)

Using the command `cat intel.log`, and pressing enter to output it to the terminal, we can look through the output and see one of the fields is called seen.where. The question wants to know where the intel was from, so this seems like a good start. Let’s move onto zeek-cut.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/221fc87f2a05a73fe9e8f38a58437d98_MD5.jpg)

Time to use zeek-cut!! The command being `cat intel.log | zeek-cut seen.where`, then press enter to run. You will have two results in the output, the question is asking for the second one. So the answer can be found after the double colon. Once you find it, type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/6bab3dd159fa24f775a068b19bd610ed_MD5.jpg)

Answer: IN_HOST_HEADER

**Investigate the http.log file. What is the name of the downloaded .exe file?**

This one can easly be found by using grep. The command being `cat http.log | grep ".exe"`, then press enter. You will only have one possible executable file found and the .exe will be in red, and thus the answer to the question. Once you find it, type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/9bc374753bb39dab5b3d6d7b08ca014d_MD5.jpg)

Answer: knr.exe

**Investigate the case1.pcap file with hash-demo.zeek script. Investigate the files.log file. What is the MD5 hash of the downloaded .exe file?**

So we have to run Zeek against the case1.pcap file, this time with the hash-demo.zeek framework. The command being `zeek -C -r case1.pcap hash-demo.zeek`, press enter to run. Use `ls` to check the contents of the directory.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/c2ab8b295de96aadcbe861d184c8db35_MD5.jpg)

Let’s pipe the files.log file through less to figure out the column we want.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/e5768c459566d30c5a987c93ba14f799_MD5.jpg)

When the log file is open in less, use the right arrow to scroll to the right.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/88e9521c0c7ef26c9e3606c847d2a4d3_MD5.jpg)

Do this twice till you see file descriptions, these are what you are looking for. After looking over the field the one we want is mime_type. So time for some zeek-cutting, press `q` to exit less.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/2ab5648b5eda985a574c0ced7306141f_MD5.jpg)

Back in the terminal, we use the command `cat files.log | zeek-cut mime_type md5`, the press enter to run. We will have three results, only one give us info that it is an executable, that is the x-dosexec, so the md5 next to this is the answer. Highlight the hash.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/2c662ccd5684424febf7a9004c46ac88_MD5.jpg)

After you have highlight the answer, right click on it. When the drop-down menu appears click on Copy.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/eab335106dce69733698044f1136319e_MD5.jpg)

In the middle of the VM is a tab, click on it.

![](https://miro.medium.com/v2/resize:fit:95/1*4VBRcZ1yFNT0vcpiCjlXag.png)

Click the clipboard icon on the slide-out tab.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/775063c4d06fcc68eb3e8bb19412af43_MD5.jpg)

The Clipboard Window will appear in the middle of the VM with the hash on it. Highlight the hash and copy with the keyboard shortcut ctrl + c, then paste (ctrl + v) into the TryHackMe answer field, and click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/ed07dd017ba3c49daf081b1625b6a170_MD5.jpg)

Answer: cc28e40b46237ab6d5282199ef78c464

**Investigate the case1.pcap file with file-extract-demo.zeek script. Investigate the “extract_files” folder. Review the contents of the text file. What is written in the file?**

Close out the Clipboard window by clicking the clipboard icon again, and the slide-out tab.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/26f74f2c8e375374c79dacdd82de8671_MD5.jpg)

Start by running zeek with the command `zeek -C -r case1.pcap file-extract-demo.zeek`, and press enter. Then use `ls` to view the contents of the directory.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/f5d4825ed8156ac79491d582f88931e2_MD5.jpg)

Let’s move into the directory with `cd extract_files/`, then we can check the contents of the extract_files directory with `ls`, and press enter.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/51d76fae0daaa7ee4c2d40d1801fc6e9_MD5.jpg)

To figure out which file is the text file we will use the command `file * | nl`, this will first run the file command, which outputs to the terminal information about what the file is. Next the * , is a wildcard, which means it will run the file command on everything in the current directory. Lastly we pipe that into nl, which will put each result onto a new line. After running the command we can see that the first file is the one we want to look at.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/b46681e6f640f57665521abc39f0358b_MD5.jpg)

So all we need to do is cat the file and we should get our answer. So using the command `cat extract-1561667874.743959-HTTP-Fpgan59p6uvNzLFja`, and pressing enter, the answer will be output to the terminal. You don’t have to type it all out, don’t forget about tab complete, start typing the file name and press tab. Since this one has others similar to it, just add a digit to it after the similarity and it will complete the rest. Now you should have your answer, type it into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/93f2f189ebd0e578db56d397b2f73c6f_MD5.jpg)

Answer: Microsoft NCSI

# Task 9 Zeek Scripts | Packages

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/a49455c0241febc7794c1d536fe0edd8_MD5.jpg)

## Scripts 204 | Package Manager

Zeek Package Manager helps users install third-party scripts and plugins to extend Zeek functionalities with ease. The package manager is installed with Zeek and available with the `zkg` command. Users can install, load, remove, update and create packages with the "zkg" tool. You can read more on and view available packages [here](https://packages.zeek.org/) and [here](https://github.com/zeek/packages). Please note that you need root privileges to use the "zkg" tool.

**Basic usage of zkg;**

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/7d1d1220a84c68169e9952fdef814595_MD5.jpg)

There are multiple ways of using packages. The first approach is using them as frameworks and calling specific package path/directory per usage. The second and most common approach is calling packages from a script with the “@load” method. The third and final approach to using packages is calling their package names; note that this method works only for packages installed with the “zkg” install method.

### Packages | Cleartext Submission of Password

Let’s install a package first and then demonstrate the usage in different approaches.  
**Note:** The package is installed in the given VM.

```
ubuntu@ubuntu$ zkg install zeek/cybera/zeek-sniffpass  
The following packages will be INSTALLED:  
  zeek/cybera/zeek-sniffpass (master)  
Proceed? [Y/n] Y  
Installing "zeek/cybera/zeek-sniffpass"  
Installed "zeek/cybera/zeek-sniffpass" (master)  
Loaded "zeek/cybera/zeek-sniffpass"  

ubuntu@ubuntu$ zkg list  
zeek/cybera/zeek-sniffpass (installed: master) - Sniffpass will alert on cleartext passwords discovered in HTTP POST requests
```

The above output shows how to install and list the installed packages. Now we successfully installed a package. As the description mentions on the above terminal, this package creates alerts for cleartext passwords found in HTTP traffic. Let’s use this package in three different ways!

```
### Calling with script  
ubuntu@ubuntu$ zeek -Cr http.pcap sniff-demo.zeek   
  
### View script contents  
ubuntu@ubuntu$ cat sniff-demo.zeek   
@load /opt/zeek/share/zeek/site/zeek-sniffpass  
  
### Calling from path  
ubuntu@ubuntu$ zeek -Cr http.pcap /opt/zeek/share/zeek/site/zeek-sniffpass  
  
### Calling with package name  
ubuntu@ubuntu$ zeek -Cr http.pcap zeek-sniffpass
``` 

The above output demonstrates how to execute/load packages against a pcap. You can use the best one for your case. The “zeek-sniffpass” package provides additional information in the notice.log file. Now let’s review the logs and discover the obtained data using the specific package.

```
ubuntu@ubuntu$ cat notice.log | zeek-cut id.orig_h id.resp_h proto note msg  
10.10.57.178 44.228.249.3 tcp SNIFFPASS::HTTP_POST_Password_Seen Password found for user BroZeek  
10.10.57.178 44.228.249.3 tcp SNIFFPASS::HTTP_POST_Password_Seen Password found for user ZeekBro
```

The above output shows that the package found cleartext password submissions, provided notice, and grabbed the usernames. Remember, in **TASK-5** we created a signature to do the same action. Now we can do the same activity without using a signature file. This is a simple demonstration of the benefit and flexibility of the Zeek scripts.

### Packages | Geolocation Data

Let’s use another helpful package called “geoip-conn”. This package provides geolocation information for the IP addresses in the conn.log file. It depends on “GeoLite2-City.mmdb” database created by MaxMind. This package provides location information for only matched IP addresses from the internal database.

```
ubuntu@ubuntu$ zeek -Cr case1.pcap geoip-conn  

ubuntu@ubuntu$ cat conn.log | zeek-cut uid id.orig_h id.resp_h geo.orig.country_code geo.orig.region geo.orig.city geo.orig.latitude geo.orig.longitude geo.resp.country_code geo.resp.region geo.resp.city                                                    
Cbk46G2zXi2i73FOU6 10.6.27.102 23.63.254.163 - - - - - US CA Los Angeles
```

Up to now, we’ve covered what the Zeek packages are and how to use them. There are much more packages and scripts available for Zeek in the wild. You can try ready or third party packages and scripts or learn Zeek scripting language and create new ones.

### Answer the questions below

Each exercise has a folder. Ensure you are in the right directory to find the pcap file and accompanying files. **Desktop/Exercise-Files/TASK-9**

So we will back out of two directories, then move forward into the TASK-9 directory. To do this start with the command `cd ..`, do this twice. Then `cd TASK-9/`, and finish up with `ls` to list the contents of the directory.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/722cb21057a65f5424de9b5dc45bb07f_MD5.jpg)

**Investigate the http.pcap file with the zeek-sniffpass module. Investigate the notice.log file. Which username has more module hits?**

First move into the cleartext-pass directory with `cd cleartext-pass`, then press enter.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/75f517f119617a0c270a9061dba2e6b5_MD5.jpg)

So we have to run Zeek against the http.pcap file, this time with the zeek-sniffpass module. The command being `zeek -C -r http.pcap zeek-sniffpass`, press enter to run. Use `ls` to check the contents of the directory.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/11b4cd0d33aedee75f2e915a70ca0ad6_MD5.jpg)

Use the command `notice.log | less`, and press enter to run.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/35df1bc4604595a35a308aa96c91e9e1_MD5.jpg)

Once in less, use the right arrow to move to the right till you reach the column with Password found.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/744f6ba64c064b1ff05b4aa3405ea299_MD5.jpg)

When you reach this column, you will see Password found for user, followed by a user name. The name that occurs the most here is the answer to the question. Once you figure it out, type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/b9edb426f0d6ba260c5dac383096f876_MD5.jpg)

Answer: BroZeek

**Investigate the case2.pcap file with geoip-conn module. Investigate the conn.log file. What is the name of the identified City?**

Press `q` to exit out of less. Now we have to move back then forward into the geoip-conn directory. This can be done with the command `cd ..`, followed up with `cd geoip-conn/` to move into said directory. Finally `ls` to list the contents of the current directory.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/360e0ef85d739eb92d08b65b74a2cac8_MD5.jpg)

So we have to run Zeek again against the case2.pcap file, this time with the hash-demo.zeek framework. The command being `zeek -C -r case2.pcap geoip-conn`, press enter to run. Use `ls` to check the contents of the directory.

![](https://miro.medium.com/v2/resize:fit:830/1*dtCXO3_VvWSBRIFLCResDQ.png)

Running `cat conn.log`, we can scroll up to see to see the fields we can use. After looking the field that looks the most promising is geo.resp.city . Time for some zeek-cut!!!

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/43e3a931fc781512977d0e83ae8bea93_MD5.jpg)

Using zeek-cut, piping, grep, and uniq, let’s get this answer. The command we want to use is `cat conn.log | zeek-cut geo.resp.city | grep -v "-" | uniq`, then press enter. The output will only have one result, the answer. Once you see it, type it into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/3767359571a8efd4d957efd1b1d67d9e_MD5.jpg)

Answer: Chicago

**Which IP address is associated with the identified City?**

Running `cat conn.log`, we can scroll up to see to see the fields we can use. After looking the field that looks the most promising is id.resp_h . Time for some zeek-cut!!!

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/2ec0dce43be32306804b33413534f575_MD5.jpg)

Again using zeek-cut, piping, grep, and uniq, let’s get this answer. The command we want to use is `cat conn.log | zeek-cut id.resp_h geo.resp.city | grep -v "-" | uniq`, then press enter. The output will only have one result and to the left of the previous answer. Once you see it, type it into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/a51cdbffb896b31a8b02472a4f241aa6_MD5.jpg)

Answer: 23.77.86.54

**Investigate the case2.pcap file with sumstats-counttable.zeek script. How many types of status codes are there in the given traffic capture?**

So we have to run Zeek again against the case2.pcap file, this time with the sumstats-countable.zeek script. The command being `zeek -C -r case2.pcap sumstats-counttable.zeek`, press enter to run. The status codes will be output to the terminal, count the different status codes to get the answer. Once you have figured it out, type it into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/06%20zeek/46cfc6496af6cf4c9574c819c2940b38_MD5.jpg)

Answer: 4

# Task 10 Conclusion

**Congratulations!** You just finished the Zeek room. In this room, we covered Zeek, what it is, how it operates, and how to use it to investigate threats.