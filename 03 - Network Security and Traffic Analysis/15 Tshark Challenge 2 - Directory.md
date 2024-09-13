
https://www.youtube.com/watch?v=TMFnCcbqDHw
https://www.youtube.com/watch?v=RkbjwF4N4jU


https://faresbltagy.gitbook.io/footprintinglabs/tryhackme-soc-1/tshark/tshark-challenge-ii-directory
https://github.com/Tara2805/THM_TShark-Challenge-II/blob/main/README.md
https://medium.com/@dilaraunsal9/tshark-challenge-ii-directory-d8d137b5bec9
https://medium.com/@unn00n/tshark-challenge-ii-directory-thm-writeup-4b2216e18619

# Task 1 Introduction

This room presents you with a challenge to investigate some traffic data as a part of the SOC team. Let's start working with TShark to analyse the captured traffic. We recommend completing the [TShark: The Basics](https://tryhackme.com/room/tsharkthebasics) and [TShark: CLI Wireshark Features](https://tryhackme.com/room/tsharkcliwiresharkfeatures) rooms first, which will teach you how to use the tool in depth.

Start the VM by pressing the green Start Machine button in this task. The machine will start in split view, so you don't need SSH or RDP. In case the machine does not appear, you can click the blue Show Split View button located at the top of this room.

NOTE: Exercise files contain real examples. DO NOT interact with them outside of the given VM. Direct interaction with samples and their contents (files, domains, and IP addresses) outside the given VM can pose security threats to your machine.

# Task 2 Case: Directory Curiosity!

An alert has been triggered: "A user came across a poor file index, and their curiosity led to problems".

The case was assigned to you. Inspect the provided directory-curiosity.pcap located in `~/Desktop/exercise-files` and retrieve the artefacts to confirm that this alert is a true positive.

Your tools: TShark, [VirusTotal](https://www.virustotal.com/).

### Answer the questions below

**What is the name of the malicious/suspicious domain?**

```
tshark -r directory-curiosity.pcap -Y "dns.qry.type == 1"
```

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/15%20Tshark%20Challenge%202%20-%20Directory/d9a9abe23297c6d04d7ed6e9720aceb1_MD5.jpg)

Answer: `jx2-bavuong[.]com`

**What is the total number of HTTP requests sent to the malicious domain?**

```
tshark -r directory-curiosity.pcap -Y 'http.request.full_uri contains "jx2-bavuong.com"' -T fields -e http.request.full_uri | wc -l
```

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/15%20Tshark%20Challenge%202%20-%20Directory/21fc0d90cb74c84c13309670c1ee92dd_MD5.jpg)

Answer: 14

**What is the IP address associated with the malicious domain?**

```
tshark -r directory-curiosity.pcap -Y 'dns.qry.name =="jx2-bavuong.com" ' -T fields -e dns.qry.name -e dns.a
```

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/15%20Tshark%20Challenge%202%20-%20Directory/1ad0da28c00ca878bdf4f049b17ed016_MD5.jpg)

Answer: `141[.]164[.]41[.]174`

**What is the server info of the suspicious domain?**

```
tshark -r directory-curiosity.pcap -Y 'http contains "jx2-bavuong.com"' -T fields -e http.server | sort | uniq
```

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/15%20Tshark%20Challenge%202%20-%20Directory/6d92dd78ccd6572bfc7043e990edc8e8_MD5.jpg)

Answer: `Apache/2.2.11 (Win32) DAV/2 mod_ssl/2.2.11 OpenSSL/0.9.8i PHP/5.2.9`

**Follow the "first TCP stream" in "ASCII". What is the number of listed files?**

```
tshark -r directory-curiosity.pcap  -z follow,tcp,ascii,0 -q
```

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/15%20Tshark%20Challenge%202%20-%20Directory/81ff3cacd85925ed43b00d17429a6112_MD5.jpg)

Answer: 3

**What is the filename of the first file?**

Answer: `123.php`

**What is the name of the downloaded executable file?**

```
tshark -r directory-curiosity.pcap -Y 'http.request.full_uri contains "jx2-bavuong.com"' -T fields -e http.request.full_uri
```

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/15%20Tshark%20Challenge%202%20-%20Directory/1cf56fe7ceba32c6a1b861f44d6e91bd_MD5.jpg)

Answer: `vlauto[.]exe`

**What is the SHA256 value of the malicious file?**

```
tshark -r directory-curiosity.pcap --export-objects http,./extracted-files
```

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/15%20Tshark%20Challenge%202%20-%20Directory/d535b91ec65cce542ce61a6820a081a6_MD5.jpg)

Answer: `b4851333efaf399889456f78eac0fd532e9d8791b23a86a19402c1164aed20de`

**Search the SHA256 value of the file on VirtusTotal. What is the "PEiD packer" value?**

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/15%20Tshark%20Challenge%202%20-%20Directory/bacf5a8cc17dee1c88e598aa4ed1825d_MD5.jpg)

Answer: `.NET executable`

**What does the "Lastline Sandbox" flag this as?**

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/15%20Tshark%20Challenge%202%20-%20Directory/e938cb257e14a87e817adb76e5fc3109_MD5.jpg)

Answer: `MALWARE TROJAN`

