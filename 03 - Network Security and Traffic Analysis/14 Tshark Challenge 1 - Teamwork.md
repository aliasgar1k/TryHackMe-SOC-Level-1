https://www.youtube.com/watch?v=aR-Y7ZW3G3o
https://www.youtube.com/watch?v=RcUcmMmg3KU
https://www.youtube.com/watch?v=E0Q9hGRUc0o

https://rafiadw.medium.com/tshark-challenge-i-teamwork-e166ac0c4305
https://faresbltagy.gitbook.io/footprintinglabs/tryhackme-soc-1/tshark/tshark-challenge-i-teamwork
https://suad198.medium.com/tshark-challenge-i-teamwork-tryhackme-10cc695fa2b8
https://writeupsifelix.gitbook.io/writeups/tshark-challenge-i-teamwork-thm
# Task 1 Introduction

This room presents you with a challenge to investigate some traffic data as a part of the SOC team. Let's start working with TShark to analyse the captured traffic. We recommend completing the [TShark: The Basics](https://tryhackme.com/room/tsharkthebasics) and [TShark: CLI Wireshark Features](https://tryhackme.com/room/tsharkcliwiresharkfeatures) rooms first, which will teach you how to use the tool in depth.

Start the VM by pressing the green Start Machine button attached to this task. The machine will start in split view, so you don't need SSH or RDP. In case the machine does not appear, you can click the blue Show Split View button located at the top of this room.

**NOTE:** Exercise files contain real examples. **DO NOT** interact with them outside of the given VM. Direct interaction with samples and their contents (files, domains, and IP addresses) outside the given VM can pose security threats to your machine.

# Task 2 Case: Teamwork!

An alert has been triggered: "The threat research team discovered a suspicious domain that could be a potential threat to the organisation."

The case was assigned to you. Inspect the provided teamwork.pcap located in `~/Desktop/exercise-files` and create artefacts for detection tooling.

Your tools: TShark, [VirusTotal](https://www.virustotal.com/gui/home/upload).

Investigate the contacted domains. 
Investigate the domains by using VirusTotal. 
According to VirusTotal, there is a domain marked as malicious/suspicious.

### Answer the questions below

**What is the full URL of the malicious/suspicious domain address?**

```
tshark -r teamwork.pcap -T fields -e dns.qry.name | awk NF | sort | uniq | sort -nr
```

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/14%20Tshark%20Challenge%201%20-%20Teamwork/04c1249445a5edd8f87a337b259d6567_MD5.jpg)

Answer: `hxxp[://]www[.]paypal[.]com4uswebappsresetaccountrecovery[.]timeseaways[.]com/`

**When was the URL of the malicious/suspicious domain address first submitted to VirusTotal?**

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/14%20Tshark%20Challenge%201%20-%20Teamwork/989e133b5e83153ef40c618fe6cacece_MD5.jpg)

Answer: `2017-04-17 22:52:53 UTC`

**Which known service was the domain trying to impersonate?**

Answer: PayPal

**What is the IP address of the malicious domain?**

```
tshark -r teamwork.pcap -T fields -e dns.qry.name -e dns.a | sort -u
```

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/14%20Tshark%20Challenge%201%20-%20Teamwork/c073c054b505dd4360ea4770f90fa236_MD5.jpg)

Answer: `184[.]154[.]127[.]226`

**What is the email address that was used?**

```
tshark -r teamwork.pcap -Y 'http.request.method == "POST"' -T fields -e http.host -e http.request.uri -e urlencoded-form.key -e urlencoded-form.value
```

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/14%20Tshark%20Challenge%201%20-%20Teamwork/d671012cdbd9ef1cc07afbba2c6d8c67_MD5.jpg)

Answer: `johnny5alive[at]gmail[.]com`

