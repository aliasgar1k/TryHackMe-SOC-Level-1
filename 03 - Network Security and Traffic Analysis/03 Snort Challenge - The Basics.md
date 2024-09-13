https://www.youtube.com/watch?v=aGIs-xQiqMI

https://medium.com/@haircutfish/tryhackme-snort-challenge-the-basics-task-1-introduction-task-2-writing-ids-rules-http-b8ec9348452
https://medium.com/@haircutfish/tryhackme-snort-challenge-the-basics-task-4-writing-ids-rules-png-task-5-writing-ids-rules-16bc16c31e51
https://medium.com/@haircutfish/tryhackme-snort-challenge-the-basics-task-6-troubleshooting-rule-syntax-errors-a23e72ff8bf1
https://medium.com/@haircutfish/tryhackme-snort-challenge-the-basics-task-7-using-external-rules-ms17-010-6586803c360f
https://medium.com/@haircutfish/tryhackme-snort-challenge-the-basics-task-8-using-external-rules-log4j-task-9-conclusion-30eb99b7454d

Put your snort skills into practice and write snort rules to analyze live capture network traffic.

# Task 1 Introduction

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/ad0ba4ea5d8cab47c83da1863ba917b4_MD5.jpg)

The room invites you a challenge to investigate a series of traffic data and stop malicious activity under two different scenarios. Let’s start working with Snort to analyze live and captured traffic.

We recommend completing the [Snort](https://tryhackme.com/room/snort) room first, which will teach you how to use the tool in depth.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/137e7198b63448e97b875c6aff012b26_MD5.jpg)

Exercise files for each task are located on the desktop as follows;

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/04a1bf5fb0ac998381085234d44e9771_MD5.jpg)

# Task 2 Writing IDS Rules (HTTP)

Let’s create IDS Rules for HTTP traffic!

###  Answer the questions below

Navigate to the task folder.

Use the given pcap file.

Write rules to detect “**all TCP port 80 traffic**” packets in the given pcap file.

So we want to open a text editor, so use the command `sudo gedit local.rules`, then press enter to open it.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/ddeaf587874d97a4adb9158072db1638_MD5.jpg)

So from going through the previous room, we learned that we will start with alert. Then from what THM wants us to write, it is a tcp protocol with port 80. Then we create a message that is descriptive, followed by the sid and the rev. So our rule should be `alert tcp any 80 <> any any (msg:”TCP port 80 found”; sid:100001; rev:1;)`, we need to create the rule again with the port in the destination side as well, so it would look like this, `alert tcp any any <> any 80(msg:”TCP port 80 found”; sid:100002; rev:1;)`

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/fddcfa0ec5b3856c62f200ddab67757f_MD5.jpg)

Save (ctrl + s) and X out of the text editor window, and your back in the terminal.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/1336342b57e205a5ae9c5ef7d6525a21_MD5.jpg)

**What is the number of detected packets?**

Note: You must answer this question correctly before answering the rest of the questions in this task.

Time to run our rule through, snort against the pcap file. We will set it up as we did in the previous room, the command will be `sudo snort -c local.rules -A full -l . -r mx-3.pcap`. We get the name of the pcap file from running the `ls` command earlier. So after typing the command in, press enter to run it.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/f82f4153530db1111a077e1e568997fe_MD5.jpg)

After snort is done running, we can use `ls` again, and see that now we have an alert and log file.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/016639fed1e925844937d57392f131fc_MD5.jpg)

Let’s look at the log file, to do this we can use the snort command we learned in the previous room, `sudo snort -r snort.log.1671720080`. The name of your log file may be different, that is ok, just make sure it is named properly. Then press enter to run the command.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/5e4a7e9293bdea2b6d348c9dc0fb900f_MD5.jpg)

When snort is done outputting the log file, you will see Total, if you look to the right in the Total row you will see a number. This number is the answer to the question. Type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/f00d9e3bd71cbcc00dc03aaeee1e53ac_MD5.jpg)

Answer: 164

_Edit: Thanks_ [_Oatuvalentin_](https://medium.com/@oatuvalentin)_, I fixed the answer. It must have changed._

Investigate the log file.

**What is the destination address of packet 63?**

Time to pick and choose packets to investigate, to do this once again we go back to what we learned in the previous room. We use the command from the previous question, but end it with -n 63, this will show us the first 63 packets. So the command is `sudo snort -r snort.log.1671720080 -n 63`, then press enter to run it.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/efc1906f5acd626f6c8ee406ba17942b_MD5.jpg)

When it is done running, we want to scroll up to the last packet being displayed.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/b922242b7115619d1fbbda316b52b254_MD5.jpg)

Once we reach the packet, you can find the destination IP as it the second IP address in the second row. Once you find it, type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/64ab2174628984bfb544f707ab077d8e_MD5.jpg)

Answer: 145.254.160.237

Investigate the log file.

**What is the ACK number of packet 64?**

So head back to your terminal, and press the up arrow to bring back the previous command. Then delete the number 63 and type in the number 64.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/14ae80e487609df1380c207a368be374_MD5.jpg)

Now that we have the correct number in, press enter for snort to read the first 64 packets from the log file.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/bdf29053171329813a104111e91d008d_MD5.jpg)

As before, when it is done running, we want to scroll up to the last packet being displayed.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/9dda80e92d0faf37b443e1b1c313b5b6_MD5.jpg)

Once we reach the packet, you can find the Ack in the last row around the middle of the packet. Once you find it, type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/c96818e3e21db3df467f822012daf523_MD5.jpg)

Answer: 0x38AFFFF3

Investigate the log file.

**What is the SEQ number of packet 62?**

Go back to the terminal and if you look two packets up you are at 62. The Seq number is right before the Ack in the last row, and the Seq number will look familiar. Once you find it, type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/b6bd85e9bccd57595c5ed673bb6dee77_MD5.jpg)

Answer: 0x38AFFFF3

Investigate the log file.

**What is the TTL of packet 65?**

So head back to your terminal, and press the up arrow to bring back the previous command. Then delete the number 64 and type in the number 65.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/b77c2fd6545c38d9f097200b52340f70_MD5.jpg)

Now that we have the correct number in, press enter for snort to read the first 65 packets from the log file.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/83f8978f6b24bf2969f7fd77bbee4fc9_MD5.jpg)

As before, when it is done running, we want to scroll up to the last packet being displayed.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/c555d65e176606e84a5bd48914be7193_MD5.jpg)

Once we reach the packet, you can find the TTL: in the middle row, the number after the colon is the answer. Once you find it, type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/ba1c07984c86fc0d18f0759aeae36f58_MD5.jpg)

Answer: 128

Investigate the log file.

**What is the source IP of packet 65?**

Heading back to packet 65, look to the second row and look for the first IP address. This is the source IP address, and the answer to this question. Once you find it, type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/fe2db0d7f0f16c390e12ecf2d73c9343_MD5.jpg)

Answer: 145.254.160.237

Investigate the log file.

**What is the source port of packet 65?**

Heading back, one last time, to packet 65, look at the end of the first IP address for the number after the colon. This is the port number, and the answer to this question. Once you find it, type this answer into the TryHackMe answer field, then click submit.

Answer: 3372

# Task 3 Writing IDS Rules (FTP)

Let’s create IDS Rules for FTP traffic!

### Answer the questions below

Navigate to the task folder.

Use the given pcap file.

Write rules to detect “**all TCP port 21**” traffic in the given pcap.

I set it up similar to the previous task, catching traffic on both the source and the destination side. Then the message, I differentiated which side it is on. So the rules are written like this, `alert tcp any 21 <> any any (msg:"src:FTP found"; sid:100001; rev:1;)` & `alert tcp any any <> any 21 (msg:"des:FTP found"; sid:100002; rev:1;)`. Once you have them written out, it’s time to save.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/a206446dace8d2911e1577cf6c4db847_MD5.jpg)

**What is the number of detected packets?**

Time to run our rule against the ftp pcap that THM gave us. Just like in the previous task, the command is the same except the file at the end. The command is `sudo snort -c local.rules -A full -l . -r ftp-png-gif.pcap`, after typing this in, press enter and let Snort do it’s work.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/3ff4543f088d6a5b6a4d2f56826390de_MD5.jpg)

When Snort is done running, we can use the `ls`command to view the contents of the current directory. As we can see, we have our alert and log file now.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/11ab0009ebac62c3ef604ed227706d05_MD5.jpg)

Let’s take a look at the log file with the command, `sudo snort -r snort.log.1671731339`, and press enter for snort to read and output it to the terminal.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/c4da89df2561378c7ad5d1cd8224e6d9_MD5.jpg)

When snort is done outputting the log file, you will see Total, if you look to the right in the Total row you will see a number. This number is the answer to the question. Type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/4d42c653ed509c81277fd398ab71a19f_MD5.jpg)

Answer: 307

Investigate the log file.

**What is the FTP service name?**

Head back to the terminal, since we don’t want to search through 500+, let’s start with 10, and let’s add a little information to them as well. We can do this with the `-X` parameter, so the command is `sudo snort -r snort.log.1671731339 -X -n 10`. Press enter to run this command.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/d13c5463ce20da12b5721e5524509896_MD5.jpg)

Scroll back to the top, and as you can see, we have more information. Scroll down through the 10 packets, looking for FTP service, as the question is asking.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/a425616bbfd37cd20c289801af678830_MD5.jpg)

After scrolling down through you should reach about packet 7 and 8, you should see it. Once you find it, type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/be1938f01960afc3721580f8bbb7d536_MD5.jpg)

Answer: Microsoft FTP service

Write a rule to **detect failed FTP login attempts** in the given pcap.

Let’s write the rules to catch failed FTP login attempts on our system. Start off, we can type the first part of the first alert `alert tcp any 21 <> any any`. Then when it comes to the msg: section I am going to change to `msg:"Detected Failed FTP Login";`. The sid: area is going to be `sid:100003`, and rev is going to stay the same.But before the sid: section we are going to add a content: section, and that will be `content:"530 User";` . So the full rule should look like this, `alert tcp any 21 <> any any (msg:"Detectected Failed FTP Login"; content:"530 User"; sid:100003; rev:1;)`

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/e7b29bdc14794de809e64059f4e42d20_MD5.jpg)

The reason I went the route I did above is because I couldn’t figure out why “Failed” didn’t work so I looked at the hint and this is why. But doing a quick research I don’t know where it came from so I have to do more research on the topic

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/b49adabf48a0d21be2f3a97fc17fcd23_MD5.jpg)

**What is the number of detected packets?**

Time to run our rule against the ftp pcap that THM gave us. Just like in the previous task, the command is the same except the file at the end. The command is `sudo snort -c local.rules -A full -l . -r ftp-png-gif.pcap`, after typing this in, press enter and let Snort do it’s work.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/4ddac3a21c5ad593767509a064ab0369_MD5.jpg)

When Snort is done running, we can use the `ls`command to view the contents of the current directory. As we can see, we have our alert and log file now.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/490cd2322c5f64319be60977cc403f80_MD5.jpg)

Let’s take a look at the log file with the command, `sudo snort -r snort.log.1671736484`, and press enter for snort to read and output it to the terminal.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/837807208a3e967e1995e02efff97979_MD5.jpg)

When snort is done outputting the log file, you will see Total, if you look to the right in the Total row you will see a number. This number is the answer to the question. Type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/3113bdfeb2d885eb8f3deeb05fbafd75_MD5.jpg)

Answer: 41

Write a rule to **detect successful FTP logins** in the given pcap.

Let’s write the rules to catch successful FTP login attempts. I am not going to lie, I checked the hint right away on this one as I was sure it was going to have a number I didn’t know about, and it did.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/6239ba9d7b21eee754ed854f355c6254_MD5.jpg)

So our rule is going to be just like the last one we created, so let’s highlight, copy (ctrl + c), and paste (ctrl + v) under the last rule we created.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/09706310bd5f0aa89e45d5f1a0d1b7d3_MD5.jpg)

Time for rule surgery, first remove the # in the front, next change the msg: from Failed to Successful. Then content: from 530 User to 230 User, and sid from 100003 to 100004. So let’s stitch it together, `alert tcp any 21 <> any any (msg:"Detected Successful FTP Login"; content:"230 User"; sid:100004; rev:1;)`. Once you have it all fixed, time to save.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/d00630a259ac355a8b3e5f3b0aebfa34_MD5.jpg)

**What is the number of detected packets?**

Time to run our rule against the ftp pcap that THM gave us. Just like in the previous task, the command is the same except the file at the end. The command is `sudo snort -c local.rules -A full -l . -r ftp-png-gif.pcap`, after typing this in, press enter and let Snort do it’s work.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/922f4a819cbad082bf449408b47ff819_MD5.jpg)

When Snort is done running, we can use the `ls`command to view the contents of the current directory. As we can see, we have our alert and log file now.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/e7c4b73af803e25260c3be1a1b2dfc2d_MD5.jpg)

Let’s take a look at the log file with the command, `sudo snort -r snort.log.1671738489`, and press enter for snort to read and output it to the terminal.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/df65352e3d2b75725d5d8d4991fd4296_MD5.jpg)

When snort is done outputting the log file, you will see Total, if you look to the right in the Total row you will see a number. This number is the answer to the question. Type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/9b2ef2b42817bfec1c027877134bacac_MD5.jpg)

Answer: 1

Write a rule to **detect failed FTP login attempts with a valid username but a bad password or no password.**

Let’s write the rule to detect the failed FTP login attemps but with bad or no passwords. I have found a [wiki](https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes) that has the server codes that we can use to help us. Click the link to be taken to the [wiki](https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes), once there use the browser find function ctrl + f, and type password, you will have two responses.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/4066eceb763251cc5679b5bfcc613481_MD5.jpg)

Look at the first result, I think we might have a winner.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/e4f8a3e50d28849efcf5ef272577a5d1_MD5.jpg)

So back in the text editor, like before it’s time for surgery. Highlight copy (ctrl + c) the previous rule and paste (ctrl + v) under said rule.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/acc6b39aa2c0735735f23c492ca2fe41_MD5.jpg)

First remove the # in the front, next change the msg: from Successful to FTP Failed Login-Bad or No Password. Then content: from 230 User to 331 Password, and sid from 100004 to 100005. So let’s stitch it together, `alert tcp any 21 <> any any (msg:"FTP Failed Login-Bad or No Password"; content:"331 Password"; sid:100005; rev:1;)`. Once you have it all fixed, time to save.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/d182f3ee38f2c7ad988721ea0c37932b_MD5.jpg)

**What is the number of detected packets?**

Time to run our rule against the ftp pcap that THM gave us. Just like in the previous task, the command is the same except the file at the end. The command is `sudo snort -c local.rules -A full -l . -r ftp-png-gif.pcap`, after typing this in, press enter and let Snort do it’s work.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/7d726f053b7abf89bce5901e24d0121b_MD5.jpg)

When Snort is done running, we can use the `ls`command to view the contents of the current directory. As we can see, we have our alert and log file now.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/2ac934c965c4d46da8cf7d5c4ae74ae8_MD5.jpg)

Let’s take a look at the log file with the command, `sudo snort -r snort.log.1671739842`, and press enter for snort to read and output it to the terminal.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/4a2682f9cda6cd727ad55e8654f12954_MD5.jpg)

When snort is done outputting the log file, you will see Total, if you look to the right in the Total row you will see a number. This number is the answer to the question. Type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/219cdb67eb64310f6294aef7b19adbc4_MD5.jpg)

Answer: 42

Write a rule to **detect failed FTP login attempts with “Administrator” username but a bad password or no password.**

So this time we don’t need to change much just add to what we have there. We will change up the msg to reflex what what we are looking for, add fast_pattern, and add another content section with “Administrator”. So it should look like this, `alert tcp any 21 <> any any (msg:"FTP Failed Admin Login-Bad or No Password"; content:"331 Password"; fast_pattern; content:"Administrator"; sid:100006; rev:1;)`.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/297fd427633dd2bfa5e03f2529f029ef_MD5.jpg)

Save (ctrl + s) and X out of the text editor window, and your back in the terminal.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/6495398257c51f88970cb8d69d3bda93_MD5.jpg)

**What is the number of detected packets?**

Time to run our rule against the ftp pcap that THM gave us. Just like in the previous task, the command is the same except the file at the end. The command is `sudo snort -c local.rules -A full -l . -r ftp-png-gif.pcap`, after typing this in, press enter and let Snort do it’s work.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/7d726f053b7abf89bce5901e24d0121b_MD5.jpg)

When Snort is done running, we can use the `ls`command to view the contents of the current directory. As we can see, we have our alert and log file now.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/1a93fec5b6877d402bf4bff81f43edb8_MD5.jpg)

Let’s take a look at the log file with the command, `sudo snort -r snort.log.1671740806`, and press enter for snort to read and output it to the terminal.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/d2cf9b42069ec1e98366ddeb7b34d4c7_MD5.jpg)

When snort is done outputting the log file, you will see Total, if you look to the right in the Total row you will see a number. This number is the answer to the question. Type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/219cdb67eb64310f6294aef7b19adbc4_MD5.jpg)

Answer: 7

# Task 4 Writing IDS Rules (PNG)

Let’s create IDS Rules for PNG files in the traffic!

### Answer the questions below

Navigate to the task folder.

Use command `cd Desktop/Exercise-Files/TASK-4\ \(PNG\)/`, then press enter to run the command. You are now in the correct directory, using the command `ls` will list the contents of the directory so we know what the name of the pcap and rules file is.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/9d8959829ad45fb1400c21ee9c83b6b4_MD5.jpg)

Use the given pcap file.

Write a rule to **detect the PNG file** in the given pcap.

Before we write our rule we need to go get a number, to start we need to go to [wiki](https://en.wikipedia.org/wiki/List_of_file_signatures) that hold the list of file signatures. Click on the link for the [wiki](https://en.wikipedia.org/wiki/List_of_file_signatures), and once there we are going to use the find (ctrl + f) feature of our browser to find png. When the search bar opens, type png and you will have 4 results.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/1d82ebbea871e88fba988614929bf3dc_MD5.jpg)

Go to the second or third result and you will see the PNG magic number we need.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/1e298d900fa0261f327c1cd794d239cb_MD5.jpg)

Start by opening the text editor with `sudo gedit local.rules`, and press enter.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/1f1e31b2ea94e1158f01667ab72c4ce0_MD5.jpg)

We can see that they already have a rule inside the rule file, so we will leave it alone for the time being. But we will borrow from it, highlight and copy (ctrl + c) the rule on line 8, press enter to start a new line and paste (ctrl + v) the rule on line 9.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/7a03b0863194acffce26db990d2e66f9_MD5.jpg)

Now let’s change some things up on the new rule. First thing to change is the protocol to tcp from icmp. The second thing to change would be the msg:, we want to change it to “PNG file detected”. Then the sid we can increment it one 1. Finally we need to add a content: section, this is where we are going to put that magic number from earlier into. You can copy (ctrl + c) and paste (ctrl + v) or type the hex value in, but the command should look like this, `alert tcp any any <> any any (msg:"PNG file Detected"; content:"|89 50 4A 47 0D 0A 1A 0A|"; sid:100002; rev:1;)`, once we have this typed out we can save it. We use the pipes between to tell snort that this is a binary or a hex value inside here.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/6f8bc5613bb1ae4dcaee7f4c8f25bed0_MD5.jpg)

Save (ctrl + s) and X out of the text editor window, and your back in the terminal.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/fb3223a9dc06fd23f0030503e71c0d3b_MD5.jpg)

Time to run our rule through, snort against the pcap file. We will set it up as we did in the previous room, the command will be `sudo snort -c local.rules -A full -l . -r ftp-png-gif.pcap`. We get the name of the pcap file from running the `ls` command earlier. So after typing the command in, press enter to run it.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/af990984033f95bb5fc6761fa6acaff6_MD5.jpg)

After snort is done running, we can use `ls` again, and see that now we have an alert and log file.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/17340559e33b91b855bee85fe1ed2abf_MD5.jpg)

**Investigate the logs and identify the software name embedded in the packet.**

Let’s look at the log file, to do this we can use the snort command we learned in the previous room, `sudo snort -r snort.log.1671814047 -X`. The name of your log file may be different, that is ok, just make sure it is named properly. Then press enter to run the command.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/076b9bbfb89894194f4829507e3a5d25_MD5.jpg)

There is only one result, scroll up till you get almost to the top. Look to the text next to the hex output. A program name should standout, this is the answer. Once you find it, type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/78efe07d940677660266a1e5e27afa04_MD5.jpg)

Answer: Adobe ImageReady

Clear the previous log and alarm files.

Let’s remove the log file first, to do this we can use the command `sudo rm snort.log.1671814047`, then press enter. If it is ready for you to add another command, then you entered it correctly.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/41ea25fb456ce61ec38df8d9ffcd3b2f_MD5.jpg)

For the alarm file, we can use `gedit`. The command will be `sudo gedit alert`, then press enter to open the alert file in gedit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/17e529fb14e8ea8c1513f74f4b41ecf3_MD5.jpg)

Click anywhere inside the alert file, then use the keyboard shortcut to select all, ctrl + a . The text editor should fill up blue, meaning that all the text is selected.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/e2156f2ead06d5c3b764f7e5531d4218_MD5.jpg)

Press the Deleted button on the keyboard, everything will be gone.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/8b2005b181b6d35e4644fdcf28de1441_MD5.jpg)

Save (ctrl + s) and X out of the text editor window, and your back in the terminal.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/7a6ee81cd8c495d65d06c6d75146bd32_MD5.jpg)

Deactivate/comment on the old rule.

Open the rule file with the command, `sudo gedit local.rules`.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/8c53d81a698430777215b63663e3fdb7_MD5.jpg)

To Deactivate/comment out the rule, just put a # symbol at the beginning of the line.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/e0ea99182a0f30c97d9dc981006266e3_MD5.jpg)

Write a rule to **detect the GIF file** in the given pcap.

Before we write our rule, head back to the [List of File Signatures Wiki](https://en.wikipedia.org/wiki/List_of_file_signatures) page. Once there, we are going to use the browser find (ctrl + f) feature. In the search bar type GIF, and you will get 4 result all of which are going to be in the same row.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/24da1625ac55b99c88c261bec9389527_MD5.jpg)

I will say, after some trail and error, I came up with this being the only code that would yield results. So now we have our number.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/fc5971d503d1278b08a3d1470e57f349_MD5.jpg)

Time to write a rule to detect GIF files, to do so it is going to be much like the previous rule. I am going to type out the rule then explain it, `alert tcp any any <> any any (msg:"GIF File Detected"; content:"GIF89a"; sid:100003; rev:1;)`. So before the parentheses we are keeping the same, so we go to msg: to start our changes. In the msg: section we change it to “GIF File Detected”. The content: section we will go back to the [wiki](https://en.wikipedia.org/wiki/List_of_file_signatures), to get the GIF code and place that in here. Then the sid: section with once again be incremented by one, and the rev will be left along.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/426fe8af5502b44deb1f7306b315c6c8_MD5.jpg)

> **UPDATE:** I had a reader named Naftoli, told me that the there was an issue with the above rule and GIF code. This reader mentioned a website called [MIME types (IANA media types)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types#mime_sniffing:~:text=they%20are%20correct.-,Magic%20numbers.,-The%20syntax%20of), that has a more accurate Hex Signature for GIF files. Looking in the MIME sniffing portion, you will see the section on “Other methods of conveying document type”. Looking at the Magic Number bullet point will show the hex vaule for both GIF (47 49 46 38 39) and PNG (89 50 4E 47). Which could give you a better detection for GIF files. Since it is looking for GIF in hex instead of GIF plus additional characters. The rule for finding GIF using the hex value is `alert tcp any any <> any any (msg:"GIF File Detected"; content:"|47 49 46 38 39|"; sid:100003; rev:1;)` .

Save (ctrl + s) and X out of the text editor window, and your back in the terminal.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/7a6ee81cd8c495d65d06c6d75146bd32_MD5.jpg)

Time to run our rule through, snort against the pcap file. We will set it up as we did in the previous room, the command will be `sudo snort -c local.rules -A full -l . -r ftp-png-gif.pcap`. We get the name of the pcap file from running the `ls` command earlier. So after typing the command in, press enter to run it.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/af990984033f95bb5fc6761fa6acaff6_MD5.jpg)

After snort is done running, we can use `ls` again, and see that now we have an alert and log file.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/cc8c462791420f281d8500a3f06f60a0_MD5.jpg)

**Investigate the logs and identify the image format embedded in the packet.**

Let’s look at the log file, to do this we can use the snort command we learned in the previous room, `sudo snort -r snort.log.1671817766 -X`. The name of your log file may be different, that is ok, just make sure it is named properly. Then press enter to run the command.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/34d1d5d5240a1cc61a1acc2c73a88be6_MD5.jpg)

Scroll up, looking at the text next to the hex output. Something should stand out to be in everyone, that is also something that you put in your rule. Once you figure it out/find it, type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/0409a660266a94781f9712d4222b1e0a_MD5.jpg)

Answer: GIF89A

# Task 5 Writing IDS Rules (Torrent Metafile)

Let’s create IDS Rules for torrent metafiles in the traffic!

### Answer the questions below

Navigate to the task folder.

Let’s move back and then forward again from the Task 4 directory to the Task 5 directory. To do this use the command `cd ..`, this backs you out of your current directory. The next command is `cd TASK-T\ \(TorrentMetafile\)/`, this will move you forward into the Task 5 directory. Finish up with, `ls` to view the contents of the current directory.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/d35b51bfd00214db866af2998979bed6_MD5.jpg)

Use the given pcap file.

Write a rule to **detect the torrent metafile** in the given pcap.

Time to write a rule to detect Torrent Metafiles, let’s go simple with this one. First open the text editor with `sudo gedit local.rules`.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/fe79d5d21d1e926904a2411f3258d5ad_MD5.jpg)

Writing out the command it is `alert tcp any any <> any any (msg:"Torrent MetaFile Detected"; content:"torrent"; sid:100001; rev:1;)`. Let’s break it down, we start it off like we have been `alert tcp any any <> any any`. Then we get to the msg: section, we make it `msg:"Torrent MetaFile Detected"`. The content: section we want to search for any instance of torrent. Then sid: 10001, and rev:1 as always. Once you have it all typed out, you are ready to save your rule.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/b8536dcd1310692d16aca0643ad6c5b4_MD5.jpg)

Save (ctrl + s) and X out of the text editor window, and your back in the terminal.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/b1bfeef766e5a4ac8b84416c8a8a6ec4_MD5.jpg)

**What is the number of detected packets?**

Time to run our rule through, snort against the pcap file. We will set it up as we did in the previous room, the command will be `sudo snort -c local.rules -A full -l . -r torrent.pcap`. We get the name of the pcap file from running the `ls` command earlier. So after typing the command in, press enter to run it.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/4411d2fbf362f592ac1fbecfbfb40462_MD5.jpg)

After snort is done running, we can use `ls` again, and see that now we have an alert and log file.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/3e64cfd330cdef8e3d43b0119588df88_MD5.jpg)

> **UPDATE:** The same reader, Naftoli, from before also pointed out the I dropped the ball and forgot to include the reading of the snort log file. So I am placeing the write-up portion below this update, sorry I don’t have a screen shot for this. Thank you so much Naftoli!!!

Let’s look at the log file, to do this we can use the snort command we learned in the previous room, `sudo snort -r snort.log.1671819514 -X`. The name of your log file may be different, that is ok, just make sure it is named properly. Then press enter to run the command.

When snort is done outputting the log file, you will see Total, if you look to the right in the Total row you will see a number. This number is the answer to the question. Type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/b09a5c145fd5aa90ab5194fb573c6676_MD5.jpg)

Answer: 2

Investigate the log/alarm files.

Go back to the log where you just got the answer from in the previous question. You will just need to scroll up to the packet section.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/faad80687e1936fe3d81481c91e137a7_MD5.jpg)

**What is the name of the torrent application?**

Now that you are up in the Packet section, look in the text next to the hex values, this is where you are going to find the answer. It is in both packets, and can be found just under halfway down through the text. Once you find it, type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/8eb8c823b0adf6ebe80825933247b4e1_MD5.jpg)

Answer: bittorrent

Investigate the log/alarm files.

Stay where you are!!!!

**What is the MIME (Multipurpose Internet Mail Extensions) type of the torrent metafile?**

This answer is easier to find once you have found the previous answer. It has the previous answer in it, but it starts before the previous answer. Once you find it, type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/674bccf4130dd4e6a761a148dc685a27_MD5.jpg)

Answer: application/x-bittorrent

Investigate the log/alarm files.

Stay where you are!!!!

**What is the hostname of the torrent metafile?**

Going back for the last time, look for Host:, the answer can be found right after this. Once you find it, type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/882fe72de4d39c39fd3e7e795b718887_MD5.jpg)

Answer: tracker2.torrentbox.com

# Task 6 Troubleshooting Rule Syntax Errors

Let’s troubleshoot rule syntax errors!

First, let’s navigate to the correct folder, use the following command `cd Desktop/Exercise-Files/TASK-6\ \(Troubleshooting\)/`. Then using the command `ls` to see the contents of the directory. You are now ready to proceed.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/445a82d8e05d7a3b07666b87b13e9e81_MD5.jpg)

###  Answer the questions below

In this section, you need to fix the syntax errors in the given rule files.

You can test each ruleset with the following command structure;

`sudo snort -c local-X.rules -r mx-1.pcap -A console`

Fix the syntax error in **local-1.rules** file and make it work smoothly.

Open the local-1.rules in the text editor with `sudo gedit local-1.rules`.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/b576afac12a0c4f0157898b16282bce7_MD5.jpg)

At first glance, the last any doesn’t have a space between it and the parenthesis. So we need to add one in there, once we do, it is time to save.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/16fce14af73047c6fa1f3061a2835104_MD5.jpg)

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/8295a16c1448338871d948533499cac5_MD5.jpg)

**What is the number of the detected packets?**

Now let’s run the fixed syntaxed rule against the pcap file and see what we get in return. So type the command `sudo snort -c local-1.rules -r mx-1.pcap -A console` into the terminal, then press enter to run it.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/46c33802970e381b2a3ccc3b8ee573a6_MD5.jpg)

When the Snort is done, look in the Action Stats section, this is the last section of the scan. Look in for Alerts, the number to the right is the answer to the question, Once you find it, type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/2e025284e9bb063141e74d7e4417bcdd_MD5.jpg)

Answer: 16

Fix the syntax error in **local-2.rules** file and make it work smoothly.

Open the local-2.rules in the text editor with `sudo gedit local-2.rules`.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/3026ee212c05cfd00effbea083e3a3ac_MD5.jpg)

Looking at this rule, I see two problems with it. The first one is before the directional arrow, the rule is missing an any. The second is a space gap between msg: and “Troubleshooting 2”. So make the changes, and you're ready to save.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/f2deb7f20b592288c8893c4d0011c770_MD5.jpg)

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/a6993d68e3ff45eb20e98b2db54baa4f_MD5.jpg)

**What is the number of the detected packets?**

Now let’s run the fixed syntaxed rule against the pcap file and see what we get in return. So type the command `sudo snort -c local-2.rules -r mx-1.pcap -A console` into the terminal, then press enter to run it.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/2b081545559333e36e31cfd129286824_MD5.jpg)

When the Snort is done, look in the Action Stats section, this is the last section of the scan. Look in for Alerts, the number to the right is the answer to the question, Once you find it, type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/860ed1b5fe8600fba23e0458a491460d_MD5.jpg)

Answer: 68

Fix the syntax error in **local-3.rules** file and make it work smoothly.

Open the local-3.rules in the text editor with `sudo gedit local-3.rules`.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/25a7a9da93aec8ef119cfb988decbfc7_MD5.jpg)

This time we have two rules to look at. I see that we once again that we have a space gap in the msg: field. Also, the sid: field is not incremented, so we need to change these but removing the space between message and incrementing the sid: by one in the second rule.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/2c0bedbf3f94c11d777f704bf7062f7c_MD5.jpg)

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/cf7849c41b7f293e8982c0be461dafde_MD5.jpg)

Save (ctrl + s) and X out of the text editor window, and your back in the terminal.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/a48a3c815bb2ee465cf8fadc7234a724_MD5.jpg)

**What is the number of the detected packets?**

Now let’s run the fixed syntaxed rule against the pcap file and see what we get in return. So type the command `sudo snort -c local-3.rules -r mx-1.pcap -A console` into the terminal, then press enter to run it.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/ae87dea4eaa04714d5fd255d363e1cb3_MD5.jpg)

When the Snort is done, look in the Action Stats section, this is the last section of the scan. Look in for Alerts, the number to the right is the answer to the question, Once you find it, type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/460dda874687acebee60d1c7a2056d92_MD5.jpg)

Answer: 87

Fix the syntax error in **local-4.rules** file and make it work smoothly.

Open the local-4.rules in the text editor with `sudo gedit local-4.rules`.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/f28afe0bef98289f6eac7892bb9e34b3_MD5.jpg)

These rules look similar to the rules of the previous question. But after closer inspection, I see two issues. The first is, once again, the space gap in the msg: field (I don’t think it really matters but for me, I think it looks better for proper syntax), and the second is a colon instead of a semicolon to denote a new field after the msg: field. So let's make these changes.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/dea5cd16ffcb44829b64a2911a0138d5_MD5.jpg)

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/e7a38d68e35c09df736df67641b14a53_MD5.jpg)

Save (ctrl + s) and X out of the text editor window, and you're back in the terminal.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/a48a3c815bb2ee465cf8fadc7234a724_MD5.jpg)

**What is the number of the detected packets?**

Now let’s run the fixed syntaxed rule against the pcap file and see what we get in return. So type the command `sudo snort -c local-4.rules -r mx-1.pcap -A console` into the terminal, then press enter to run it.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/046495a79aef8e6441b34975109ea30b_MD5.jpg)

When the Snort is done, look in the Action Stats section, this is the last section of the scan. Look in for Alerts, the number to the right is the answer to the question, Once you find it, type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/f919f387d1072aae0cc04455685f90fc_MD5.jpg)

Answer: 90

Fix the syntax error in **local-5.rules** file and make it work smoothly.

Open the local-5.rules in the text editor with `sudo gedit local-5.rules`.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/0af816ea922591ce3810ad443c2f347c_MD5.jpg)

Ohh boy, we have three rules to look at this time. After looking it over, I found 4 different syntax errors. The first bad syntax is the directional arrows, you can’t have the arrows point in that direction, so you have to change it to point to the right. This indicates ICMP coming from source to destination. The second being, as it has always been, the space gap in the msg: field. The second being in the third rule, if you look at the sid field they put a semicolon where a colon should be. The final being on the last rule, they put a colon where a semicolon should be between the msg and sid field to denote the new field. Make the changes, and when you're done, you are ready to save.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/86f7b044e60319ce921b1c490c7c8d82_MD5.jpg)

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/06c92ff53be267f6f50d76a7fdca6fca_MD5.jpg)

Save (ctrl + s) and X out of the text editor window, and you’re back in the terminal.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/a48a3c815bb2ee465cf8fadc7234a724_MD5.jpg)

**What is the number of the detected packets?**

Now let’s run the fixed syntaxed rule against the pcap file and see what we get in return. So type the command `sudo snort -c local-5.rules -r mx-1.pcap -A console` into the terminal, then press enter to run it.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/4afaa6d9b561f303838f4716a0024517_MD5.jpg)

When the Snort is done, look in the Action Stats section, this is the last section of the scan. Look in for Alerts, the number to the right is the answer to the question, Once you find it, type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/06312cc9fe726720eaa804a278d29b04_MD5.jpg)

Answer: 155

Fix the logical error in **local-6.rules** file and make it work smoothly to create alerts.

Open the local-6.rules in the text editor with `sudo gedit local-6.rules`.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/5d1c6f720f4c68dcb937093bb263b2a9_MD5.jpg)

This time we have only one rule to look at, but within that rule we have three syntax errors. The first being, once again the space in the msg: field. The next syntax error is, the content field, the hex within reads out to lowercase. So we want to add a nocase field next to the content field so it will search for get despite case. Then finally the space gap in the sid field much like the gap in the msg field. Make all the changes, and get it ready to save.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/62d083aebcbb509107cdfda111da507e_MD5.jpg)

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/dbd34ca58bbcc63ed70a0f55927c89c7_MD5.jpg)

Save (ctrl + s) and X out of the text editor window, and you’re back in the terminal.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/a48a3c815bb2ee465cf8fadc7234a724_MD5.jpg)

**What is the number of the detected packets?**

Now let’s run the fixed syntaxed rule against the pcap file and see what we get in return. So type the command `sudo snort -c local-6.rules -r mx-1.pcap -A console` into the terminal, then press enter to run it.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/c7b85ee086e17093bfc6f7cfe1a01d2e_MD5.jpg)

When the Snort is done, look in the Action Stats section, this is the last section of the scan. Look in for Alerts, the number to the right is the answer to the question, Once you find it, type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/f2083e439fe19f74c760a3e791aaf72f_MD5.jpg)

Answer: 2

Fix the logical error in **local-7.rules** file and make it work smoothly to create alerts.

Open the local-7.rules in the text editor with `sudo gedit local-7.rules`.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/16fe851ff6fd2ce232e6bf990935bd95_MD5.jpg)

As we can see, we have a couple of issues here, the rule is missing the msg: field and has a space added in the sid: field. Before we can add a message we need to know what the message is going to be, to do this let's head to the website [CyberChef](https://cyberchef.org). Using the link, head to [CyberChef](https://cyberchef.org), once on the page, go to the left side of the page. Drag and drop From Hex into the Recipe section.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/68680a4b159f79398468984bd3c11442_MD5.jpg)

Then on the right side of the page is an Input field, type the Hex value into the Input field. Below it, the Output field will populate with the converted text.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/a1b65b9c743ea85372d9b9705bda2ce7_MD5.jpg)

So seeing this we are looking for HTML files, so we can make the msg: field “HTML file found”. We can then just remove the space that was added in the sid: field. Then we should be ready to save.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/d769a29d6ce1e890df7331daa1dced28_MD5.jpg)

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/44c69312120e04ab6de67a89f86f2c56_MD5.jpg)

Save (ctrl + s) and X out of the text editor window, and you’re back in the terminal.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/a48a3c815bb2ee465cf8fadc7234a724_MD5.jpg)

**What is the name of the required option:**

The answer for this is, the section that we had to go do research on in CyberChef. Once you figure it out, type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/e4931567716a5346ebc35d5f2a3111cd_MD5.jpg)

Answer: msg

# Task 7 Using External Rules (MS17–010)

Let’s use external rules to fight against the latest threats!

### Answer the questions below

Navigate to the task folder.

First, let’s navigate to the correct folder, use the following command `cd Desktop/Exercise-Files/TASK-7\ \(MS17-10\)/`. Then using the command `ls` to see the contents of the directory. You are now ready to proceed.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/a28d748e251a58dc91251fa2a22ca963_MD5.jpg)

Use the given pcap file.

Use the given rule file (**local.rules**) to investigate the ms1710 exploitation.

So TryHackMe already has a rule ready for us to use and wants us to use it. So using the local.rules file, we can use the command `sudo snort -c local.rules -A full -l . -r ms-17-010.pcap`, and press enter to run it.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/9d16875a05f056accf7c4b2b884e203f_MD5.jpg)

**What is the number of detected packets?**

When the Snort is done, look in the Action Stats section, this is the last section of the scan. Look in for Alerts, the number to the right is the answer to the question, Once you find it, type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/99e8d5ce959a2102048c8da0c54d4de9_MD5.jpg)

Answer: 25154

Clear the previous log and alarm files.

Run the command `ls` so we know what the names of the files

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/cb210148360f4e4f0416f427cc3a1c25_MD5.jpg)

Let’s remove the log file first, to do this we can use the command `sudo rm snort.log.1672250642`, then press enter. If it is ready for you to add another command, then you entered it correctly.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/e6720dbf4e251b35431a017a4e9f8d59_MD5.jpg)

For the alarm file, we can use `gedit`. The command will be `sudo gedit alert`, then press enter to open the alert file in gedit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/f132a636ccf3d2036c5e7cd3058b57ba_MD5.jpg)

Click anywhere inside the alert file, then use the keyboard shortcut to select all, ctrl + a . The text editor should fill up blue, meaning that all the text is selected.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/a2fae4d5d479edc0febef1db13bcdc19_MD5.jpg)

Press the Deleted button on the keyboard, everything will be gone.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/720f0a73da3fad0f1a2b6a985dc625b2_MD5.jpg)

Save (ctrl + s) and X out of the text editor window, and your back in the terminal.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/c955ccdf08bdfa267e699289368ab042_MD5.jpg)

Use **local-1.rules** empty file to write a new rule to detect payloads containing the “**\IPC$**” keyword.

Open local-1.rules in a text editor, with the command `sudo gedit local-1.rules`.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/fab3875d68f31a70dc95478b92ba0572_MD5.jpg)

So when writing this rule, we start by making it an `alert` so we will be notified if/when it happens. Next is the protocol, I went with `tcp` as it seems to be the protocol of choice for the most part. Then, since we don’t have an IP address or port on either side, we make both on the source and destination sides `any`. Next is the msg: section, this is where we make it descriptive to what we could see, so we know from a glance what why the alert was triggered. I made it `"\IPC$ Payload Detected"`. Then the content: section which is what will be used to search against and alerted if found. So I used what was given by TryHackMe and that was `"\IPC$"`. Finally the last two sections are the sid: and the rev:, the sid: section should be `100001` and the rev: should be `1`. Altogether, the command is `alert tcp any any <> any any (msg:"\IPC$ Payload Detected"; content:”\IPC$”; sid:100001; rev:1;)`. After you have that typed into the rule file, it’s time to save.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/d39b1cbb3b9262ea30b5b006c8f0aaf5_MD5.jpg)

Save (ctrl + s) and X out of the text editor window, and your back in the terminal.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/c955ccdf08bdfa267e699289368ab042_MD5.jpg)

Time to run our rule through snort with the command `sudo snort -c local-1.rules -A full -l . -r ms-17-010.pcap`. Press enter to run Snort, unfortunately we have an error!!! So we have to go about this another way.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/883d07bd9d035a060a628b146fb2e032_MD5.jpg)

Let’s head over to [CyberChef](https://cyberchef.org) (use the link I provided). Once at [CyberChef](https://cyberchef.org), go to the Operations column on the left. Drag and drop To Hex into the Recipe Column in the center.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/4d32cc1d030c283c5aa956a3fd8cefb4_MD5.jpg)

Move over to the Input section on the right, type in `\IPC$`, the Output section in the bottom should autopopulate with the hex value of the Input text.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/2304361270199db5e2cdcd811980a6b0_MD5.jpg)

Head back to the terminal and open the local-1.rules file again in gedit with `sudo gedit local-1.rules`.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/5265af02e48b8dd94c9a4eb52b7a6866_MD5.jpg)

Now replace what is currently in the content: section with the hex value, remembering to use quotes and pipes. It should look like this `"|5c 49 50 43 24|"`.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/de090578a9728dd8bf06eafa5c0beb43_MD5.jpg)

Save (ctrl + s) and X out of the text editor window, and your back in the terminal.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/c955ccdf08bdfa267e699289368ab042_MD5.jpg)

**What is the number of detected packets?**

Time to run our rule through snort again, with the command `sudo snort -c local-1.rules -A full -l . -r ms-17-010.pcap`. Press enter to run Snort, this time no error.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/7e2838ae626cce45e6c442cdf3fb31e1_MD5.jpg)

When the Snort is done, look in the Action Stats section, this is the last section of the scan. Look in for Alerts, the number to the right is the answer to the question, Once you find it, type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/b48208e19cae4d11ee72281eaa1621ef_MD5.jpg)

Answer: 12

Investigate the log/alarm files.

We can look at the file with the command `sudo snort -r snort.log.1672253726`, your log file name maybe be different. Press enter to have Snort output the results to the terminal.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/2df7c22fc6f89c74f72e309eed93333a_MD5.jpg)

**What is the requested path?**

Scroll up to the first packet, if you look to the text on the right side of the hex output, you will see an IP address. This is the answer along with the letters after it. Once you find it, type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/08bca5519d397dcb0214fdb18ab9de12_MD5.jpg)

Answer: \\192.168.116.138\IPC$

**What is the CVSS v2 score of the MS17–010 vulnerability?**

We won’t need the VM for this answer, but we will need a trusty friend by the name of Google. Head over to Google and search MS17–010 CVSS v2 score.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/61f3aaa7875d0d1a8e256079313defd3_MD5.jpg)

The first result back is from NIST, so let’s head on in and check it out. Click the link.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/5a8f745d31c3c7515bfe8b284465c566_MD5.jpg)

When the page loads we and kinda of see what we are looking for so scroll down a little bit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/5f0678012641707415d5f0e70565acbc_MD5.jpg)

Now that it’s in better view we can see that it is on version 3.x but we want version 2. So click the white box labeled CVSS Version 2.0.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/bf1b57fdcbb3103db874ea245c05cee2_MD5.jpg)

The number will change, and will be the answer you are looking for. Type the answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/5c3b61d1469f8d34b1362894d3e80f01_MD5.jpg)

Answer: 9.3

# Task 8 Using External Rules (Log4j)

Let’s use external rules to fight against the latest threats!

### Answer the questions below

Navigate to the task folder.

First, let’s navigate to the correct folder, use the following command `cd Desktop/Exercise-Files/TASK-8\ \(Log4j\)/`. Then using the command `ls` to see the contents of the directory. You are now ready to proceed.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/4b849cd2c8b3766028e56563d3fd982f_MD5.jpg)

Use the given pcap file.

Use the given rule file (**local.rules**) to investigate the log4j exploitation.

So TryHackMe already has a rule ready for us to use and wants us to use it. So using the local.rules file, we can use the command `sudo snort -c local.rules -A full -l . -r log4j.pcap`, and press enter to run it.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/56e2209c2900c93b121c292a65be5bf6_MD5.jpg)

**What is the number of detected packets?**

When the Snort is done, look in the Action Stats section, this is the last section of the scan. Look in for Alerts, the number to the right is the answer to the question, Once you find it, type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/e7645f4832e23e210984f27a43a96c67_MD5.jpg)

Answer: 26

Investigate the log/alarm files.

Using the command `cat alert`, will output the alerts onto the screen. From there I can see that all the alerts have the same thing in common, they start with FOX-SRT.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/975f54bf064d7706773f7d1a349fa71b_MD5.jpg)

**How many rules were triggered?.**

Using the same command as above with some added help from grep we can cut the output down a bit. The command is now `cat alert | grep "FOX-SRT"`. Counting these up, I only count 3 rules in total that were triggered, but this isn’t the answer. So looking over the output again, I found that the numbers on the left side of FOX-SRT are all the same except the last two digits. These last two digits coincide with the rule that was triggered, which could make this the sid numbers.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/1ccd383853925512142e25a4d2ca8ad4_MD5.jpg)

Knowing this now we can use the command `cat alert | grep "210037"`, and count the first instance of each number. After you have counted it up, type the answer in the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/31a748a20f418e0e37d11e4a1937d9b1_MD5.jpg)

Answer: 4

Investigate the log/alarm files.

You should already have what you need in the terminal.

**What are the first six digits of the triggered rule sids?**

Back in the terminal, the answer is the six digits that we searched with grep. Type these digits into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/0359f82245dee02d75114db2dbf49518_MD5.jpg)

Answer: 210037

Clear the previous log and alarm files.

Run the command `ls` so we know what the names of the files

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/b3e2a1fbbf886819d8888bfc20950e78_MD5.jpg)

Let’s remove the log file first, to do this we can use the command `sudo rm snort.log.1672321771`, then press enter. If it is ready for you to add another command, then you entered it correctly.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/5d2f0ffe980a27ede2b376c0d0fed493_MD5.jpg)

For the alarm file, we can use `gedit`. The command will be `sudo gedit alert`, then press enter to open the alert file in gedit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/ccbc944fa86a3ab3989067f93afa455a_MD5.jpg)

Click anywhere inside the alert file, then use the keyboard shortcut to select all, ctrl + a . The text editor should fill up blue, meaning that all the text is selected.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/e88709f0f68ba396d49bcb6df7ea8dc3_MD5.jpg)

Press the Deleted button on the keyboard, everything will be gone.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/12e821d29a27f606a962c43871b026eb_MD5.jpg)

Save (ctrl + s) and X out of the text editor window, and your back in the terminal.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/1eba142250a1dfa79000538df0f43ec7_MD5.jpg)

Use **local-1.rules** empty file to write a new rule to detect packet payloads **between 770 and 855 bytes**.

To refresh our minds, we can look back on Task 9 of the Snort room, if we scroll down to the **Non-Payload Detection Rule Options.** Look in the table for Dsize, it will show you how to use it with an example.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/d77d8054b19e48dfff0237d2655f3f34_MD5.jpg)

Now that we know how to detect payload data sizes, let’s open up the text editor and create our rule, with the command `sudo gedit local-1.rules`.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/ad58f542d9fc695976ac0ef938b7dfff_MD5.jpg)

So when writing this rule, we start by making it an `alert` so we will be notified if/when it happens. Next is the protocol, I went with `tcp` as it seems to be the protocol of choice for the most part. Then, since we don’t have an IP address or port on either side, we make both on the source and destination sides `any`. Next is the msg: section, this is where we make it descriptive to what we could see, so we know from a glance what why the alert was triggered. The next section is the dsize: section, here we want to specifiy `770<>855`, since this is what TryHackMe told us to detect. Finally the last two sections are the sid: and the rev:, the sid: section should be `100001` and the rev: should be `1`. Altogether, the command is `alert tcp any any <> any any (msg:"Log4j detected-Byte size"; dsize:770<>855; sid:100001; rev:1;)`. After you have that typed into the rule file, it’s time to save.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/9afc1c2ea57f9f9d08a4ec1d849e5515_MD5.jpg)

Save (ctrl + s) and X out of the text editor window, and your back in the terminal.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/1eba142250a1dfa79000538df0f43ec7_MD5.jpg)

**What is the number of detected packets?**

Time to run our rule through snort with the command `sudo snort -c local-1.rules -A full -l . -r log4j.pcap`. Press enter to run Snort, unfortunately we have an error!!! So we have to go about this another way.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/7162d81cfd9dd0969f0e79b3c5a2140e_MD5.jpg)

When the Snort is done, look in the Action Stats section, this is the last section of the scan. Look in for Alerts, the number to the right is the answer to the question, Once you find it, type this answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/0549a873db6f62de2efa3696c1c37c43_MD5.jpg)

Answer: 41

Investigate the log/alarm files.

Using Snort and grep we are going to use the command `sudo snort -r snort.log1672329139 -X` , this will display in the output all the content of the packet down to the hex values.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/c6e61527328da5322a80f71ab1578e00_MD5.jpg)

**What is the name of the used encoding algorithm?**

Start to scroll up through the outputs, looking for anything that would indicate what the encoding algorithm could be. Lucky we don’t have to go far up, packet number 40 has our answer in it. Look at the text on the right, look for the word Command/, the answer is after this. Once you find it type the answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/de8ae752d3a85cb2be17c6b85c589e20_MD5.jpg)

Answer: Base64

Investigate the log/alarm files.

You should already have what you need in the terminal.

**What is the IP ID of the corresponding packet?**

Look at the top of Packet 40, the third line down about halfway in. You will see ID:, the numbers after this are the answer. Once you find it type the answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/2f56c5696c22913af94024063827a7d8_MD5.jpg)

Answer: 62808

Investigate the log/alarm files.

You should already have what you need in the terminal.

Decode the encoded command.

Go back and highlight the encoded section, you will have the hex value highlighted as well.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/b021bf601bc2ea490480d9e2fea079c0_MD5.jpg)

Right-click on the highlighted part, then in the drop-down menu click Copy. Now look to the left side of the VM for a little gray tab, click on it.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/42ecbbbaf54da9a019bb12d02e1cf850_MD5.jpg)

Click the clipboard icon in the middle of the panel.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/7ace5a61b211a713b940212f9b7a66db_MD5.jpg)

Now the Clipboard function of the VM is open, and code we copied from the terminal is already in here. We just need to remove the hex value parts of it and combine the base64 portion.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/956babe34fca1cb89d0f4c4b8c3bc3dc_MD5.jpg)

After you have taken all the hex values, spaces, and new lines out. You are left with the base64 code, we are almost ready to decode this. First, highlight the base64 code, this time we can use the keyboard shortcut to copy, ctrl + c . Time to head over to [CyberChef](https://cyberchef.org).

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/89afa3296e698c627b1e7996a7b62a3d_MD5.jpg)

**What is the attacker’s command?**

Once at [CyberChef](https://cyberchef.org) (use the link I provided), on the left side of the screen is Operations. Drag and drop From Base64 to the Recipe column in the middle of the page.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/503b4fb3da58264e3e7e008828ea5628_MD5.jpg)

Now move over to the Input section on the right of the webpage, and paste (ctrl + v) the base64 code into it. In the Output section will be the decoded command, and the answer to the question. Type the answer in the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/1a1aa07009eb3cd2167bef69a01135b9_MD5.webp)

**Not the Answer: I am not putting the answer in here, as medium doesn’t like it and crashes every time I put it in here.**

**What is the CVSS v2 score of the Log4j vulnerability?**

We won’t need the VM for this answer, but we will need a trusty friend by the name of Google. Head over to Google and search CVSS v2 score log4j vulnerability.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/2f8a5c716ea237dadefac9f0e93fd79f_MD5.jpg)

So we can see that the NIST site comes up again, like in the previous task. Click on and let’s check it out.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/2276381aa050dc7b50d5f80039bd7c66_MD5.jpg)

When the page loads we and kinda of see what we are looking for so scroll down a little bit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/0a4ff44f2e56a8b7e9027b34d6e7ed9c_MD5.jpg)

Now that it’s in better view we can see that it is on version 3.x but we want version 2. So click the white box labeled CVSS Version 2.0.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/807ad72efeb47e169d9296368daabc12_MD5.jpg)

The number will change, and will be the answer you are looking for. Type the answer into the TryHackMe answer field, then click submit.

![](_resources/03%20Snort%20Challenge%20-%20The%20Basics/3658e7fefe022ad205a2a35c770e1add_MD5.jpg)

Answer: 9.3

# Task 9 Conclusion

Congratulations! Are you brave enough to stop a live attack in the [Snort2 Challenge 2](https://tryhackme.com/room/snortchallenges2) room?