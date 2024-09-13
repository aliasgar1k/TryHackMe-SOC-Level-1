https://medium.com/@kirk.dy.johnson/tryhackme-soc-level-1-friday-overtime-a32e9df8347e
https://medium.com/@CarsonS/tryhackme-friday-overtime-writeup-e5484527bbb1
https://www.youtube.com/watch?v=KASQhm-cioU
# Challenge Scenario 

Hello Busy Weekend. . .

It’s a Friday evening at PandaProbe Intelligence when a notification appears on your CTI platform. While most are already looking forward to the weekend, you realise you must pull overtime because SwiftSpend Finance has opened a new ticket, raising concerns about potential malware threats. The finance company, known for its meticulous security measures, stumbled upon something suspicious and wanted immediate expert analysis.

As the only remaining CTI Analyst on shift at PandaProbe Intelligence, you quickly took charge of the situation, realising the gravity of a potential breach at a financial institution. The ticket contained multiple file attachments, presumed to be malware samples.

With a deep breath, a focused mind, and the longing desire to go home, you began the process of:

1. Downloading the malware samples provided in the ticket, ensuring they were contained in a secure environment.
2. Running the samples through preliminary automated malware analysis tools to get a quick overview.
3. Deep diving into a manual analysis, understanding the malware’s behaviour, and identifying its communication patterns.
4. Correlating findings with global threat intelligence databases to identify known signatures or behaviours.
5. Compiling a comprehensive report with mitigation and recovery steps, ensuring SwiftSpend Finance could swiftly address potential threats.

## Answer the following:

**Who shared the malware sample?**

Once you connect to lab, login with credentials provided if it doesn’t do it automatically. Within the message/email, the answer is in the first sentence.

![](02%20-%20Cyber%20Threat%20Intelligence/_resources/06%20Friday%20Overtime/e6568639ab4c54e79ed44c5db445885c_MD5.jpg)
Answer: Oliver Bennett

**What is the SHA1 hash of the file “pRsm.dll” inside samples.zip?**

There are different ways to do it but I will explain mine. Download the attachment in the VM, open a terminal on the Desktop, navigate to your Downloads folder, cd /home/ericatracy/Downloads/ , then unzip samples.zip with unzip samples.zip, input the password found in the email: Panda321! and now you have the unzipped file. I used the command: sha1sum pRsm.dll

![](02%20-%20Cyber%20Threat%20Intelligence/_resources/06%20Friday%20Overtime/10fad73363c5915f2966c106dd700a78_MD5.jpg)

![](02%20-%20Cyber%20Threat%20Intelligence/_resources/06%20Friday%20Overtime/f503d8cbc9b25b5cbd1762bde9e7b53d_MD5.jpg)
Answer: 9d1ecbbe8637fed0d89fca1af35ea821277ad2e8

**Which malware framework utilizes these DLLs as add-on modules?**

Finding the answer to this question is essential to finish the lab. I used trusted google and searched, “ what malware framework utilizes “pRsm.dll”. The top link/story from WeLiveSecurity is what I used to answer most of the following questions. In the introduction it mentions MgBot malware, which is the answer.

![](02%20-%20Cyber%20Threat%20Intelligence/_resources/06%20Friday%20Overtime/696fa054b6d81beac7f6899d9b546495_MD5.jpg)

![](02%20-%20Cyber%20Threat%20Intelligence/_resources/06%20Friday%20Overtime/4e5bcecb48546ef75ecf9358dbb38b5c_MD5.jpg)
Answer: MgBot

**Which MITRE ATT&CK Technique is linked to using pRsm.dll in this malware framework?**

I used the handy control+f in the article and input pRsm.dll, the third result gives the answer.

![](02%20-%20Cyber%20Threat%20Intelligence/_resources/06%20Friday%20Overtime/4f1526f6ed5b3a390be142bdbffdac85_MD5.jpg)
Answer: T1123

**What is the CyberChef defanged URL of the malicious download location first seen on 2020–11–02?**

Similarly, within the article I used control+f with 11‑02 and found the URL. With the URL, head over to cyberchef (type it in to search bar its free and very useful), paste the URL in the top, in the left search bar, look for defang URL, and the output is the answer.

![](02%20-%20Cyber%20Threat%20Intelligence/_resources/06%20Friday%20Overtime/307ca46677ee2d4a2b65eb4a138459ce_MD5.jpg)

![](02%20-%20Cyber%20Threat%20Intelligence/_resources/06%20Friday%20Overtime/d4d2eaa9891af6084ed4838a4b5a65a6_MD5.jpg)
Answer: hxxp[://]update[.]browser[.]qq[.]com/qmbs/QQ/QQUrlMgr_QQ88_4296[.]exe

**What is the CyberChef defanged IP address of the C&C server first detected on 2020–09–14 using these modules?**

You guessed it. Another control+f with 09–14 reveals the IP of the malicious C2 server. (TryHackMe wants the defanged version, this is very easy to do on your own for example the IP 8.8.8.8 defanged would be 8[.]8[.]8[.]8, brackets around the dots.)

![](02%20-%20Cyber%20Threat%20Intelligence/_resources/06%20Friday%20Overtime/cc8b71030aa68b479b90a31180483c88_MD5.jpg)
Answer: 122[.]10[.]90[.]12

**What is the SHA1 hash of the spyagent family spyware hosted on the same IP targeting Android devices on November 16, 2022?**

This we can’t use our control+f to save us, I know, it’s ok. With the IP address we found in the previous question 122[.]10[.]90[.]12, go to VirusTotal on the web (another very useful tool I’m sure you’re aware of) go over to search and input the IP. Under the relations tab you will see the date and device asked about in the question. Click on the hash (starts with 9) and you will be re-directed to that page. There click on details and you’ll see the SHA-1 hash.

![](02%20-%20Cyber%20Threat%20Intelligence/_resources/06%20Friday%20Overtime/e45c67c1e04521e3fd7f69950bb96587_MD5.jpg)

![](02%20-%20Cyber%20Threat%20Intelligence/_resources/06%20Friday%20Overtime/c0fdc6b2f7e306c40484c7d090259a89_MD5.jpg)

![](02%20-%20Cyber%20Threat%20Intelligence/_resources/06%20Friday%20Overtime/d0af1a04805b2a5fedf57c1bd2146ac9_MD5.jpg)
Answer: 1c1fe906e822012f6235fcc53f601d006d15d7be