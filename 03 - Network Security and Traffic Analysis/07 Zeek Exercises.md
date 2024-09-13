https://www.youtube.com/watch?v=bi0_iPZzp60
https://www.youtube.com/watch?v=wnPxbZhgGV4

https://medium.com/@haircutfish/tryhackme-zeek-exercises-task-1-introduction-task-2-anomalous-dns-3a0baa1df1e8
https://medium.com/@haircutfish/tryhackme-zeek-exercises-task-3-phishing-task-4-log4j-task-5-conclusion-de684862d8e6

Put your Zeek skills into practice and analyze network traffic.

# Task 1 Introduction

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/4f7a3c52b12a040858a415a80c14c4ed_MD5.jpg)

The room invites you a challenge to investigate a series of traffic data and stop malicious activity under different scenarios. Let’s start working with Zeek to analyze the captured traffic.

We recommend completing the [**Zeek**](https://tryhackme.com/room/zeekbro) room first, which will teach you how to use the tool in depth.

A VM is attached to this room. You don’t need SSH or RDP; the room provides a “Split View” feature. Exercise files are located in the folder on the desktop. Log cleaner script **“clear-logs.sh”** is available in each exercise folder.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/20375d44b79d99da1a10848a9a86e9a0_MD5.jpg)
# Task 2 Anomalous DNS

**An alert triggered:** “Anomalous DNS Activity”.

The case was assigned to you. Inspect the PCAP and retrieve the artifacts to confirm this alert is a true positive.

### Answer the questions below

First, move into the anomalous-dns directory with the `cd` command. So the command we are doing is `cd anomalous-dns/`, then press enter to move into the directory. Then use `ls` to see the contents of the directory.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/45412aa7881027f49fc337af1699ed9e_MD5.jpg)

**Investigate the dns-tunneling.pcap file. Investigate the dns.log file. What is the number of DNS records linked to the IPv6 address?**

So we want to use run Zeek against the pcap file. To do this we will use the command `zeek -r dns-tunneling.pcap`, then press enter to run Zeek. Using `ls`, will show the content and log files in the current directory.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/773acbb262d9bb7b37a4bb251ae6495f_MD5.jpg)

Now let’s cat the dns log file and pipe it through less to see if we can figure out the name of the field we want to see it. Also, the question here wasn’t very clear so at first I was searching the IP addresses for an IPv6 address, and found one. But what they are asking for here is, a certain DNS record associated with the IPv6 address, and what is the number of occurrences of this DNS record are. So knowing this and looking at the hint that TryHackMe gives, we are looking for the quad A record (AAAA). Know all this let’s run the command `cat dns.log | less`, then press enter to run. When you get in the dns log file through less press the right arrow key till reaching the quad A record.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/7d4059a3c6c00e5865dbfcf8319906d8_MD5.jpg)

After looking at the fields and counting, I determined that the name of the field we are looking for is qtype_name. Press `q` to exit out of less.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/af025f6b758bebe41f3731751039c20c_MD5.jpg)

Knowing the field we need to zeek-cut, time to do a little Command-Line Kung-Fu! The command being `cat dns.log | zeek-cut qtype_name | grep "AAAA" | uniq -c`, then press enter to run. After we zeek-cut the field out, we then pipe that into grep which we then pull out only quad A results. Then take the results from grep and pipe that into uniq and get rid of the duplicates and count the number of times it occurred. After this command runs we are left with the answer in the output, type it into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/02665ab3f51956bb1957ed041c60b43f_MD5.jpg)

Answer: 320

**Investigate the conn.log file. What is the longest connection duration?**

Now let’s cat the conn log file and pipe it through less to see if we can figure out the name of the field we want to see it. So the command we want to use is `cat conn.log | less`, and press enter to run.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/2ae5fcb4af13687d3af3c3f83ccfbf43_MD5.jpg)

At a quick glance at the different fields, we see that one of the field names is duration. This seems to be the field we want to use, time to use some zeek-cut.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/f5278f445c94911ccb5b6db13da68061_MD5.jpg)

Time to use zeek-cut, sort, and tail with some pipes. The command that we want to use is `cat conn.log | zeek-cut duration | sort -n | tail -1`, and press enter to run the code. We take the field and run it through zeek-cut, and pipe the results through sort. Sort has the dash/tick n for sorting numerically, then we pipe the results of sort through tail. Tail gives the last 10 results unless told otherwise, which we are telling it to with the dash/tick 1. After running the command, you are left with the result in the output of the terminal, type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/38ef489dcf399fc4f6d7c60e2fe88b3e_MD5.jpg)

Answer: 9.420791

**Investigate the dns.log file. Filter all unique DNS queries. What is the number of unique domain queries?**

To start we will pipe the DNS log file into less to find the field we want to look at, to do this use the command `cat dns.log | less`, press enter to run.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/63970f5f1c860e844f0c5f9278d25e61_MD5.jpg)

At a quick glance at the different fields, we see that one of the field names is query. This seems to be the field we want to use, time to use some zeek-cut.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/2b6a5323da907b0ee6b42dc84659dbb8_MD5.jpg)

Let’s use zeek-cut along with some new commands to find the answer. After trying multiple combinations, and finally looking at the hint the full command I used was `cat dns.log | zeek-cut query | rev | cut -d '.' -f 1-2 | rev | sort | uniq`, and press enter to run. We take and zeek cut the query field out, then pipe the results through to rev. Rev then reverses the string of characters, which then get’s piped to cut. Cut will then work like zeek-cut and with the parameters of -d for the delimiter and we chose the period, the -f stands for field, and 1–2 is for the first and second field. Now the results of cut are piped back into rev to reverse the string of characters once more, aka they are now in the proper order. The results from rev are piped into sort, to sort them alphabetically. Finally, the results from sort are piped into uniq to remove any duplicates. After the command has run, you are left with a single output of each unique domain query. Count them to get your answer, once you have counted them type it into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/3d3f121097557b1554c3f85dba698629_MD5.jpg)

Answer: 6

**There are a massive amount of DNS queries sent to the same domain. This is abnormal. Let’s find out which hosts are involved in this activity. Investigate the conn.log file. What is the IP address of the source host?**

To start we will pipe the conn log file into less to find the field we want to look at, to do this use the command `cat conn.log | less`, press enter to run.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/2ca517adb5d07f6d1c9d6a8bd5e3996f_MD5.jpg)

At a quick glance at the different fields, we see that two of the field names are id.orig_h and id.resp_h. This seems to be the field we want to use, time to use some zeek-cut.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/8b269f7dbf08dae55df1cc926f9caf4f_MD5.jpg)

Time to use zeek-cut, sort, and uniq with some pipes. The command that we want to use is `cat conn.log | zeek-cut id.orig_h id.resp_h | sort -n | uniq -c`, then press enter. We take the field and run it through zeek-cut, and pipe the results through sort. Sort has the dash/tick n for sorting numerically. Finally, the results from sort are piped into uniq to remove any duplicates. After you run the command you are left with the results, one of those results is over two thousand times. The answer is the source IP address from this row. Once you find it type it into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/520cd8989f0d56039c1d51f09116f9f0_MD5.jpg)

Answer: 10.20.57.3

# Task 3 Phishing

**An alert triggered:** “Phishing Attempt”.

The case was assigned to you. Inspect the PCAP and retrieve the artifacts to confirm this alert is a true positive.

### Answer the questions below

First, we need to move into the correct directory, to do this we need to use the command `cd phishing/`, then press enter. Using `ls` will list out the directories contents.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/f012e050f7041f241956b984f421201b_MD5.jpg)

Next, let’s run Zeek against the phishing pcap file. To do this we use the command `zeek -r phishing.pcap`, and press enter. Then use `ls` to see the contents of the current directory.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/8a8cbed3c50f921422e3fa2c1cba6e87_MD5.jpg)

**Investigate the logs. What is the suspicious source address? Enter your answer in defanged format.**

After doing some investigating myself, I came to the realization that they want to know what the infected local machine is. So I went to the dhcp.log file and looked at it with `cat dhcp.log | less`, pressing enter to open it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/cf6f0601b05600b29a08dc0a51bcf553_MD5.jpg)

At a quick glance at the different fields, we see that one of the field names is client_addr. This seems to be the field we want to use, time to use some zeek-cut.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/90a17e7476b9d690aeb386989d56071a_MD5.jpg)

To keep with using the command line, I asked ChatGPT what is the command line script to defang an IP address. It gave me a bin/bash script to do this, I then asked it for one that doesn’t require bin/bash. ChatGPT gave me this script `echo "IP address" | sed -e 's/\./[.]/g'`.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/a9bb906db6f34a1fb696a2c8461257bd_MD5.jpg)

So with our newly learned code from ChatGPT, and the command line kung-fu we already know let us get the answer. So the command we use is `cat dhcp.log | zeek-cut client_addr | uniq | sed -e 's/\./[.]/g'`, and press enter to run. We take the field and run it through zeek-cut, and pipe the results through uniq. Uniq is used to remove any duplicates, then we pipe the results into sed to defang the IP address. After running the command we are left with a defanged IP address in the output of the terminal, and the answer to the question. Type the answer into the TryHackMe answer field, and click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/b3afebce03ef46b096ee8e52e7228830_MD5.jpg)

Answer: 10[.]6[.]27[.]102

**Investigate the http.log file. Which domain address were the malicious files downloaded from? Enter your answer in defanged format.**

Now let’s cat the HTTP log file and pipe it through less to see if we can figure out the name of the field we need to use.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/324ea7966ee8721a3318e626574518f2_MD5.jpg)

Once less opens the HTTP log file, press the right arrow key once.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/c74a9cb1f5414379a6b6c0db61445ff0_MD5.jpg)

We can see the name of the field we are looking for is host, and if we remember the malicious file from task 2. We can see it here, along with the domain that it was downloaded from. Time to use some zeek-cut, so press `q` to exit less.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/25643715bcccb855543d3438ef9abf2e_MD5.jpg)

With the name of the field, and some command line kung-fu let's get the answer. The command we are going to run is `cat http.log | zeek-cut host | grep "smart-fax" | uniq | sed -e 's/\./[.]/g'`, press enter to run the command. We take the field and run it through zeek-cut, and pipe the results through grep. Using grep we pull out only the host that matches our string, we then pipe those results into uniq. With uniq we get rid of the duplicates, and we then pipe those results into sed. Finally with sed to defang the domain. After running the command we are left with a defanged domain in the output of the terminal, and the answer to the question. Type the answer into the TryHackMe answer field, and click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/9c21e762924135e8bb5aeaf7c9d29f14_MD5.jpg)

Answer: smart-fax[.]com

**Investigate the malicious document in VirusTotal. What kind of file is associated with the malicious document?**

To start off, we need to run Zeek again, this time with the script hash-demo.zeek. The command we are going to run is `zeek -C -r phishing.pcap hash-demo.zeek`, and press enter to run. After Zeek is done, us the command `ls` to show the contents of the current directory.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/85b121c6d0a7e63cb5b31e73829e63c6_MD5.jpg)

Now let’s cat the files log file and pipe it through less to see if we can figure out the name of the field we need to use

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/a82e51deec6a50d27bea70029383c656_MD5.jpg)

Once less opens the files log file, press the right arrow key once.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/b7a7ac2d7dd2eb8469e037e5968298f6_MD5.jpg)

From the Zeek room, we know that we want to look at the mime_type field. We can see this by the fact that the application/msword is in this field.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/8d23194134295cb8c9fabb989c2afb47_MD5.jpg)

Next, we need to look at the hash field, use the right arrow key to move to the right till you reached the hashes. Once there, you will see the name of the md5 hash field. Now we have all the info we need for now, press `q` to exit less.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/c17e10233264840a5354139500c76b27_MD5.jpg)

So to get the hash that we need we can use some command line kung-fu. The command we are using is `cat files.log | zeek-cut mime_type md5 | grep "word"` , then press enter to run. You will have the hash will be in the output of the terminal.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/6c45d44970815aa39c5ce8c0d99bb856_MD5.jpg)

Highlight the hash, right-click on the highlighted hash, then click Copy on the drop-down menu.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/a3caddd07eb0c079e033f0bdee890592_MD5.jpg)

Open a browser, go to the [VirusTotal](https://www.virustotal.com) website (I provided the link to the site). Once the site loads, click the SEARCH tab in the middle of the screen.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/0126a7a7aa3eaa7fddf5afc16552a54e_MD5.jpg)

A search field will be in the middle of the page, using the keyboard shortcut ctrl + v to paste the hash in search field and press enter to search the hash.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/ca97437d813bfbac57409115f04698e8_MD5.jpg)

Once the DETECTION page loads, click the RELATIONS tab.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/7b276e620ae4f279747551fe1410e0ae_MD5.jpg)

Once the RELATIONS page loads, scroll down till you see Bundled Files section.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/cf16100a802917bc50d1b382350e2250_MD5.jpg)

Once you reach the Bundled Files section, you will see a column labeled File type. The three-letter file abbreviation is the answer, type the answer into the TryHackMe answer field, and click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/c8d92412b06a975ad3bfb75700dafcbc_MD5.jpg)

Answer: VBA

**Investigate the extracted malicious .exe file. What is the given file name in Virustotal?**

Head back to the terminal and leave VirusTotal open. Since we know the field to look at from the previous question, let’s use zeek-cut and grep to get hash for the exe file. The command being `cat files.log | zeek-cut mime_type md5 | grep "exe"`, press enter to run the command.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/b5df583942548301102bdf19b1c76988_MD5.jpg)

Highlight the hash, right-click on the highlighted hash, then click Copy on the drop-down menu.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/cb8fb536ed898cdf50de8d944e5272b6_MD5.jpg)

Back at VirusTotal highlight the hash at the top of the page, and press the delete key to remove it from the search field.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/8afbca4da27e3248b88ef294252dfc61_MD5.jpg)

Use the keyboard shortcut ctrl + v to paste the new hash into the search field, then press enter to search it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/af1e73c638982f80af6c0e594f934fff_MD5.jpg)

Once the DETECTION tab loads, you can see this is malicious. At the top is a box that has some general information about the file. Inside this box, under the hash, you will see the name of the file, and thus the answer to the question. Highlight copy (ctrl + c) and paste (ctrl + v) or type, the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/c3bffa99b7cff8f1e4b6b46b952998bd_MD5.jpg)

Answer: PleaseWaitWindow.exe

**Investigate the malicious .exe file in VirusTotal. What is the contacted domain name? Enter your answer in defanged format.**

Go back to VirusTotal, you already have the exe file hash searched in VirusTotal so we just need to do a little looking for the answer to this question. Once back on VirusTotal, click the RELATIONS tab.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/340330695564024c2664f34592549661_MD5.jpg)

The first section is Contacted Domains, there is one that has a detection. You don’t need the full domain for the answer, just every after dunlop.. You can type the answer in and defange it yourself or use the command `echo hopto.org | sed -e 's/\./[.]/g'`, and press enter to run. Highlight copy (ctrl + c) and paste (ctrl + v) from the VM or type, the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/ef43fe94f5f1975ae9bf00709d909d07_MD5.jpg)

Answer:hopto[.]org

**Investigate the http.log file. What is the request name of the downloaded malicious .exe file?**

Head back to your terminal in the VM, use the command `cat http.log | grep "exe"`, you will see the name of the malicious file. Type the answer into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/82ad9ba74cacb81ed9eccbd0eaff96d7_MD5.jpg)

Answer: knr.exe

# Task 4 Log4J

**An alert triggered:** “Log4J Exploitation Attempt”.

The case was assigned to you. Inspect the PCAP and retrieve the artefacts to confirm this alert is a true positive.

### Answer the questions below

First we need to move from the phishing directory to the log4j directory. Use the command `cd ..`, to back out of the current directory. Then using the command `cd log4j/`, to move forward into the log4j directory. Finally, use the command `ls` to list the content of the current directory.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/cde489660daf52cf5e26511e37834d91_MD5.jpg)

**Investigate the log4shell.pcapng file with detection-log4j.zeek script. Investigate the signature.log file. What is the number of signature hits?**

Start by using the command `zeek -C -r log4shell.pcapng detection-log4j.zeek`, press enter to run. Then use the command `ls`to see the contents of the current directory.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/b5a68d8c124276947eaa674d027ed2df_MD5.jpg)

Now let’s cat the signatures log file and pipe it through less to see if we can find the answer.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/83177ed61b1cb70f773009797730ecd0_MD5.jpg)

Once less opens the signatures log file, press the right arrow key once.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/30e1612122cedb5b64e650a0e95b0ef9_MD5.jpg)

If you count the number of Signatures here in the note field you will get your answer. But I will show you the command line way of finding it. Press `q` to exit less.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/530954127d3824535e361f769cd1318c_MD5.jpg)

Back in the terminal, we want to use the command `cat signatures.log | zeek-cut note | uniq -c`, press enter after you were done typing the command. After you have run the command you will have the answer in the output of the terminal, type it into the TryHackMe answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/038cdd29216d5943cf966b4265f1c243_MD5.jpg)

Answer: 3

**Investigate the http.log file. Which tool is used for scanning?**

Now let’s cat the http log file and pipe it through less to see if we can find the answer.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/1f8779151e6f53815739714933e8b4bf_MD5.jpg)

Once less opens the http log file, press the right arrow key once.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/161e5ce002c4c3cba62d34e200bcc3f5_MD5.jpg)

As we look through the user_agent field we can see some interesting information, so the field we are looking for is user_agent. Time to use some zeek-cut, so press `q` to exit less

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/1e2adb158e1a2e01c632b0cbf497cb31_MD5.jpg)

Knowing the field we want to look at let’s run zeek-cut, sort, and uniq. The command being `cat http.log | zeek-cut user_agent | sort | uniq`, after you have finished typing out the command press enter. We use zeek-cut to “cut” that field out to look at, taking the results for zeek-cut we pipe it through sort. With sort, the results are sorted alphabetically, those results are then piped through uniq. Finally uniq will remove any dupilcates. After the command is finished running, look through the output you should be able to notice a famous network mapping program (wink wink). Once you find it, type the answer into the TryHackMe answer field, and click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/020d141696ea290c558278bbd04a90e9_MD5.jpg)

Answer: Nmap

**Investigate the http.log file. What is the extension of the exploit file?**

Now let’s cat the http log file and pipe it through less to see if we can find the answer.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/1f8779151e6f53815739714933e8b4bf_MD5.jpg)

Once less opens the http log file, press the right arrow key once.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/161e5ce002c4c3cba62d34e200bcc3f5_MD5.jpg)

As we look through the user_agent field we can see some interesting information, so the field we are looking for is uri. Time to use some zeek-cut, so press `q` to exit less

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/293d05033af0503cea03e5865492d61c_MD5.jpg)

Knowing the field we want to look at let’s run zeek-cut, sort, and uniq. The command being `cat http.log | zeek-cut uri | sort | uniq`, after you have finished typing out the command press enter. We use zeek-cut to “cut” that field out to look at, taking the results for zeek-cut we pipe it through sort. With sort, the results are sorted alphabetically, those results are then piped through uniq. Finally uniq will remove any dupilcates. After the command is finished running, look through the output you should be able to see only one file extension, this is the answer. Once you find it, type the answer into the TryHackMe answer field, and click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/3a6f5207bd5910d8a782b4e4ef224b93_MD5.jpg)

Answer: .class

**Investigate the log4j.log file. Decode the base64 commands. What is the name of the created file?**

Now let’s cat the log4j log file and pipe it through less to see if we can find the answer. Once the log4j file opens in less, looking through the fields along with the field contents we can see some of the base64 we need to decode. Time to use some command line kung-fu to help slim down the results.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/ea3576254ea1e07d6c1c498f682c107b_MD5.jpg)

Time for the command line kung-fu, the command we want to run is `cat log4j.log | zeek-cut uri | sort -nr | uniq`, after you have done typing the command out press enter to run it. You will see three base64 codes in the output. Next we will be decoding them.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/ea10bff752a1737ea905c19af0e4c0cc_MD5.jpg)

To decode all three the take the same steps to reach. First step is to highlight the base64 code, then right-click on it. On the drop-down menu click copy.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/7e0e6aa142a8e9ec8a85d7e205a98918_MD5.jpg)

Then type `echo` into the terminal, using the paste shortcut for linux terminal, ctrl + shift + v, paste the base64 code into the terminal. Then pipe it to `base64 -d`, this command will take a base64 code and decode it. So the command is `echo {base64 code} | base64 -d`, press enter to run the code.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/15da05926a78e8d00ef76478e6a78d5e_MD5.jpg)

Repeat these steps for the other two base64 codes. Now that you have them all decoded, you should see the name of the file created at the end of the first line. Touch is used to create, and with the name on the end this says that this is the name of the file. Once you have found it, type the answer into the TryHackMe answer field, and click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/07%20Zeek%20Exercises/ea12b3245e4328da0e22ef335622ff44_MD5.jpg)

Answer: pwned

# Task 5 Conclusion

**Congratulations!** You just finished the Zeek exercises.

If you like this content, make sure you visit the following rooms later on THM;

- [**Snort**](https://tryhackme.com/room/snort)
- [**Snort Challenges 1**](https://tryhackme.com/room/snortchallenges1)
- [**Snort Challenges 2**](https://tryhackme.com/room/snortchallenges2)
- [**Wireshark**](https://tryhackme.com/room/wireshark)
- [**NetworkMiner**](https://tryhackme.com/room/networkminer)

Note that there are challenge rooms available for the discussed content. Use the search option to find them! Happy hacking!