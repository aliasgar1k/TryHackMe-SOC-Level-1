https://www.youtube.com/watch?v=fZjUmfuozoM
https://medium.com/@haircutfish/snort-challenge-live-attacks-room-f65858077692

Put your snort skills into practice and defend against a live attack

# Task 1 Introduction

The room invites you to a challenge where you will investigate a series of traffic data and stop malicious activity under two different scenarios. Let’s start working with Snort to analyse live and captured traffic.

Before joining this room, we suggest completing the [**‘Snort’**](https://tryhackme.com/room/snort2) room.

**Note:** There are two VMs attached to this challenge. Each task has dedicated VMs. You don’t need SSH or RDP, the room provides a **“Screen Split”** feature.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/137e7198b63448e97b875c6aff012b26_MD5.jpg)

# Task 2 Scenario 1 | Brute-Force

Use the attached VM to finish this task.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/b918d88b2718e8aa9c4e7e4b7eb516a9_MD5.jpg)

**[+] THE NARRATOR**

J&Y Enterprise is one of the top coffee retails in the world. They are known as tech-coffee shops and serve millions of coffee lover tech geeks and IT specialists every day.

They are famous for specific coffee recipes for the IT community and unique names for these products. Their top five recipe names are;

**WannaWhite**, **ZeroSleep**, **MacDown**, **BerryKeep** and **CryptoY**.

J&Y’s latest recipe, “**Shot4J**”, attracted great attention at the global coffee festival. J&Y officials promised that the product will hit the stores in the coming months.

The super-secret of this recipe is hidden in a digital safe. Attackers are after this recipe, and J&Y enterprises are having difficulties protecting their digital assets.

Last week, they received multiple attacks and decided to work with you to help them improve their security level and protect their recipe secrets.

This is your assistant **J.A.V.A. (Just Another Virtual Assistant).** She is an AI-driven virtual assistant and will help you notice possible anomalies. Hey, wait, something is happening…

**[+] J.A.V.A.**

Welcome, sir. I am sorry for the interruption. It is an emergency. Somebody is knocking on the door!

**[+] YOU**

Knocking on the door? What do you mean by “knocking on the door”?

**[+] J.A.V.A.**

We have a brute-force attack, sir.

**[+] THE NARRATOR**

This is not a comic book! Would you mind going and checking what’s going on! Please…

**[+] J.A.V.A**.

**Sir, you need to observe the traffic with Snort and identify the anomaly first. Then you can create a rule to stop the brute-force attack. GOOD LUCK!**

### Answer the questions below

First of all, start Snort in sniffer mode and try to figure out the attack source, service and port.

If we remember back from the Snort room how to run in sniffer mode, we want to use the `-v` for Verbose.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/eaf2f3caccb634068126429c2e22313d_MD5.jpg)

So knowing what tack we want to use, let’s start to run Snort in sniffer mode. We will use the command `sudo snort -v -l .`, we use the `-l` to log and the `.` to log it in our current directory.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/e774dbad877e2a55e5752ef7fd7a13ca_MD5.jpg)

Let that run for 10–15 seconds, then press the keyboard ctrl + c to stop Snort. Let snort finish, when it is done, the terminal will be waiting to accept another command.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/7a72897b41cf8422a3ad28979621e127_MD5.jpg)

To be able to make our rule we first need to look at the log file to see what we have captured. Since we know that Snort names it’s log files snort.log{set of numbers}, we can use Tab complete. With Tab complete, you only have to press Tab after starting to type, and if it only has one entry that matches, it will auto complete it. Using Tab complete, use the command `sudo snort -r snort.log.1672414629 -X`, then press enter to run.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/758e37bdd00c68ddfd14e01c173c3927_MD5.jpg)

After Snort is done reading the file, and outputting it to the screen. We need to scroll up to the last packet.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/02552338e4f6c69497727cf1a02a5d0f_MD5.jpg)

After inspecting the packets, I kept seeing port 22 coming up. Not just in the Destination side either but in the source.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/d016720f9f5212ae9b90f88f95758d52_MD5.jpg)

So using grep, I ran the same command and added grep to the end of it. That command being `sudo snort -r snort.log.1672414629 -X | grep :22`, see way I can see if it is a thread I should follow.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/4ab4ca6f4b3ff248944537d09db9693a_MD5.jpg)

Sure enough, it does come up quite a lot.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/73ca7a2c388dea440d30baa3d587a030_MD5.jpg)

So, knowing that SSH runs on port 22, I then used grep to search for ssh in the packets with the command `sudo snort -r snort.log.1672414629 -X | grep "ssh"`.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/1b67bf630f1a4b8a6a6f94893a5edb44_MD5.jpg)

When Snort is done, scroll up to the top of the output. I am sure you will see as you scroll up that we have found some ssh results. When you make it to the top, start to scroll down through, and not too far down you will find a hit.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/5d7c4113249619e9ea38273ac09b56e3_MD5.jpg)

So let’s narrow it down and take a look at that packet. To do this I used the command `sudo snort -r snort.log.1672414629 -X -n 30`, this will only output the first 30 packets to the terminal.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/3e99faa9066c8ee798920478391678df_MD5.jpg)

When Snort is done, scroll up, you should spot the packet right away. It stands out amongst the others.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/8c97c01544f879e87d026cf7fe3e74a8_MD5.jpg)

Looking at the top of the packet, we can see the source is matches what we saw before. So we should have enough information to write our rule.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/64c56f96aca444e205da501dd28e386b_MD5.jpg)

Then, write an IPS rule and run Snort in IPS mode to stop the brute-force attack. Once you stop the attack properly, you will have the flag on the desktop!

Here are a few points to remember:

- Create the rule and test it with “-A console” mode.
- Use **“-A full”** mode and the **default log path** to stop the attack.
- Write the correct rule and run the Snort in IPS “-A full” mode.
- **Block the traffic at least for a minute** and then the flag file will appear on your desktop.

First, we need to open the local.rules file in a text editor. Using the command `sudo gedit /etc/snort/rules/local.rules`, and press enter

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/ae365ac7950219b907763ac54908d9e6_MD5.jpg)

Looking back at Task 9 of the Snort room, and we can see what Action must be taken.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/9ffa27bbf01fae453a338214f1792cfb_MD5.jpg)

Time to write our rule, to start it off we won’t be writing alert as we usually have. No, this time we will write `drop`. Then from the packet we know it’s a `tcp`protocol. The next section is source IP address, we will put `any 22`, as we want to specify the port. Followed by the `<>` directional arrows. For the destination IP address, we are going to put `any any`. The reasoning behind using any on both parts is what if the attacker changes IP addresses, you are now ahead of the game. Now the second half of the rule, for the msg: section I put `"SSH Connection attempted"`. To finish off the rule since we only have one, the sid: should be `100001`, and the rev: will stay at `1`. It should look as such so far `drop tcp any 22 <> any any (msg:"SSH Connection attempted"; sid:100001; rev:1;)`.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/19244b722fca3900c6ff00cbf8a33a72_MD5.jpg)

Save (ctrl + s) and X out of the text editor window, and your back in the terminal.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/9ca5cd373c055b7514c7d69f78860634_MD5.jpg)

stop the attack and get the flag (which will appear on your Desktop)

Almost time to run our rule against the live traffic, but first we need to know how we are to run the Snort. If we look back at Task 7 of the Snort room, we can see how we need to run the rule.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/ee8384d4ecc230731b9dd5c9184982cf_MD5.jpg)

After seeing the command we have to use to run the rule, the only change that needs to be made is instead of console on the end we put full. so the command it `sudo snort -c /ect/snort/snort.conf -q -Q --daq afpacket -i eth0:eth1 -A full`, the press enter and let it run till you see the flag.txt file pop-up on the desktop.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/bc2cb40a3157a3a1563e15d1b3e5bbd3_MD5.jpg)

Once the flag.txt file appears, you can stop snort with ctrl +c. Then double-click on the flag.txt icon to open it.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/6ba2c57b4f4e1c8a8842c1270d6b0d24_MD5.jpg)

After opening it you will be greeted with the flag.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/8fec85ea4af8a1f3ac87e77ee688013c_MD5.jpg)

Highlight and copy (ctrl + c) the flag. Then click the tab in the middle of the VM.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/dc5aafb2785d601853f581152216ae4e_MD5.jpg)

Click the Clipboard icon on the pop-out bar.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/a718f943d8f2b225b658fbb5fe4a5dd1_MD5.jpg)

The Clipboard window will pop-up, highlight and copy (ctrl + c) the flag. It will now be on your PC’s clipboard. Paste the flag in the answer TryHackMe answer field, then click submit.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/e36830179b0da185f00c4abfd74383ea_MD5.jpg)

Answer: THM{81b7fef657f8aaa6e4e200d616738254}

**What is the name of the service under attack?**

This can be found back from when we searched for what we know runs on port 22. When you figure it out, then type the answer in the TryHackMe answer field, then click submit.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/53e5b4a09140c07e9899674d4016d985_MD5.jpg)

Answer: SSH

**What is the used protocol/port in the attack?**

For the protocol, if you look at the Packet that we got a lot of our information from, in the last line on the left you can find the answer. For the port, at the end of the second line is the port number, it is also the same port that the above service runs on. Once you find it\figure it out type the answer into the TryHackMe answer field, then click submit.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/c489f1d1213bf411c0b8a86019c99030_MD5.jpg)

Answer: TCP/22

# Task 3 Scenario 2 | Reverse-Shell

Use the attached VM to finish this task.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/b918d88b2718e8aa9c4e7e4b7eb516a9_MD5.jpg)

**[+] THE NARRATOR**

Good Job! Glad to have you in the team!

**[+] J.A.V.A.**

Congratulations sir. It is inspiring watching you work.

**[+] You**

Thanks team. J.A.V.A. can you do a quick scan for me? We haven’t investigated the outbound traffic yet.

**[+] J.A.V.A.**

Yes, sir. Outbound traffic investigation has begun.

**[+] THE NARRATOR**

The outbound traffic? Why?

**[+] YOU**

We have stopped some inbound access attempts, so we didn’t let the bad guys get in. How about the bad guys who are already inside? Also, no need to mention the insider risks, huh? The dwell time is still around 1–3 months, and I am quite new here, so it is worth checking the outgoing traffic as well.

**[+] J.A.V.A.**

Sir, persistent outbound traffic is detected. Possibly a reverse shell…

**[+] YOU**

You got it!

**[+] J.A.V.A.**

Sir, you need to observe the traffic with Snort and identify the anomaly first. Then you can create a rule to stop the reverse shell. GOOD LUCK!

# Answer the questions below

## First of all, start Snort in sniffer mode and try to figure out the attack source, service and port.

If we remember back from the Snort room how to run in sniffer mode, we want to use the `-v` for Verbose.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/eaf2f3caccb634068126429c2e22313d_MD5.jpg)

So knowing what tack we want to use, let’s start to run Snort in sniffer mode. We will use the command `sudo snort -v -l .`, we use the `-l` to log and the `.` to log it in our current directory.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/53ae0f7bf352f39484e83cd6d8ebc39e_MD5.jpg)

Let that run for 10–15 seconds, then press the keyboard ctrl + c to stop Snort. Let snort finish, when it is done, the terminal will be waiting to accept another command.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/73c58d7875dd3e416caf7cedfd97dce5_MD5.jpg)

To be able to make our rule we first need to look at the log file to see what we have captured. Since we know that Snort names it’s log files snort.log{set of numbers}, we can use Tab complete. With Tab complete, you only have to press Tab after starting to type, and if it only has one entry that matches, it will auto complete it. Using Tab complete, use the command `sudo snort -r snort.log.1672697486 -X`, then press enter to run.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/cd8c78ccf6343e86d19b440f9b0c9c65_MD5.jpg)

After Snort is done reading the file, and outputting it to the screen. We need to scroll up to the last packet.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/1c6c00e38bd34ab589afae98edc61f5e_MD5.jpg)

As we can see from inspecting some of the packets, the port in the source and destination of some of the packets is 4444. This could indcate the possibilty of a reverse shell.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/255cba82ffa5beb0d32b86d7cdb3e29f_MD5.jpg)

Time to use grep to search the log file for port 4444, and see if we get any results. The command we are going to use is `sudo snort -r snort.log.1672697486 -X | grep ":4444"`, then press enter to run Snort.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/cda3a1c410df8f369a65ec96137e27f0_MD5.jpg)

Look at the results shows us that we are looking in the right direction.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/9cad886409a2dbcee25d5d0f9386ea7c_MD5.jpg)

Let’s run snort again only getting 10 results back from the 5,000+ we have. To do this we use the command `sudo snort -r snort.log.1672697486 -X -n 10`, press enter to run Snort.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/22e8f717d950893e58d9cdd126ff4e4d_MD5.jpg)

We should have enough information now to write a rule for snort!

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/ffd99da1dbd2fd8aea7d19909608157d_MD5.jpg)

## Then, write an IPS rule and run Snort in IPS mode to stop the brute-force attack. Once you stop the attack properly, you will have the flag on the desktop!

Here are a few points to remember:

- Create the rule and test it with “-A console” mode.
- Use **“-A full”** mode and the **default log path** to stop the attack.
- Write the correct rule and run the Snort in IPS “-A full” mode.
- **Block the traffic at least for a minute** and then the flag file will appear on your desktop.

First, we need to open the local.rules file in a text editor. Using the command `sudo gedit /etc/snort/rules/local.rules`, and press enter

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/ae365ac7950219b907763ac54908d9e6_MD5.jpg)

Looking back at Task 9 of the Snort room, and we can see what Action must be taken.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/9ffa27bbf01fae453a338214f1792cfb_MD5.jpg)

Time to write our rule, to start it off we won’t be writing alert as we usually have. No, this time we will write `drop`. Then from the packet we know it’s a `tcp`protocol. The next section is source IP address, we will put `any 4444`, as we want to specify the port. Followed by the `<>` directional arrows. For the destination IP address, we are going to put `any any`. The reasoning behind using any on both parts is what if the attacker changes IP addresses, you are now ahead of the game. Now the second half of the rule, for the msg: section I put `"Reverse Shell Detected"`. To finish off the rule since we only have one, the sid: should be `100001`, and the rev: will stay at `1`. It should look as such so far `drop tcp any 4444 <> any any (msg:"Reverse Shell Detected"; sid:100001; rev:1;)`.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/acc85c828e8497ba29ccafa8dc7ff919_MD5.jpg)

Save (ctrl + s) and X out of the text editor window, and your back in the terminal.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/89536cac3435c7e20c478b1520395464_MD5.jpg)

## Stop the attack and get the flag (which will appear on your Desktop)

Almost time to run our rule against the live traffic, but first we need to know how we are to run the Snort. If we look back at Task 7 of the Snort room, we can see how we need to run the rule.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/ee8384d4ecc230731b9dd5c9184982cf_MD5.jpg)

After seeing the command we have to use to run the rule, the only change that needs to be made is instead of console on the end we put full. so the command it `sudo snort -c /ect/snort/snort.conf -q -Q --daq afpacket -i eth0:eth1 -A full`, the press enter and let it run till you see the flag.txt file pop-up on the desktop.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/bc2cb40a3157a3a1563e15d1b3e5bbd3_MD5.jpg)

Once the flag.txt file appears, you can stop snort with ctrl +c. Then double-click on the flag.txt icon to open it.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/6ba2c57b4f4e1c8a8842c1270d6b0d24_MD5.jpg)

After opening it you will be greeted with the flag.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/8fec85ea4af8a1f3ac87e77ee688013c_MD5.jpg)

Highlight and copy (ctrl + c) the flag. Then click the tab in the middle of the VM.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/dc5aafb2785d601853f581152216ae4e_MD5.jpg)

Click the Clipboard icon on the pop-out bar.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/a718f943d8f2b225b658fbb5fe4a5dd1_MD5.jpg)

The Clipboard window will pop-up, highlight and copy (ctrl + c) the flag. It will now be on your PC’s clipboard. Paste the flag in the answer TryHackMe answer field, then click submit.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/e36830179b0da185f00c4abfd74383ea_MD5.jpg)

**Answer: THM{0ead8c494861079b1b74ec2380d2cd24}**

## What is the used protocol/port in the attack?

For the protocol, if you look at the Packet that we got a lot of our information from, in the last line on the left you can find the answer. For the port, at the end of the first IP address you will see the port number. Once you find it\figure it out type the answer into the TryHackMe answer field, then click submit.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/7ea39c9ffc7b10977770ad0cb9132ae9_MD5.jpg)

**Answer: TCP/4444**

## Which tool is highly associated with this specific port number?

If you aren’t sure what tool this is, head over to our friend Google. Using part of the question in the search, search for tool is highly associated with port 4444.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/8f2a87fc97529a4f064bd57840afc340_MD5.jpg)

The first result shows use what tool is closely associated with port 4444. Once you find it, highlight copy (ctrl + c) and paste (ctrl + v) or type, the answer into the TryHackMe answer field, then click submit.

![](_resources/04%20Snort%20Challenge%20-%20Live%20Attacks/c5f99fa5e033f874296f7e4f527d5ce0_MD5.jpg)

**Answer: Metasploit**