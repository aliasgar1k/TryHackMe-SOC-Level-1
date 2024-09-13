https://www.youtube.com/watch?v=-v5bEhQ_-0o
https://medium.com/@niceselol/tryhackme-summit-walkthrough-b14cd75fb910
https://tryhackme.com/room/summit

**Objective:**

After participating in one too many incident response activities, PicoSecure has decided to conduct a threat simulation and detection engineering engagement to bolster its malware detection capabilities. You have been assigned to work with an external penetration tester in an iterative purple-team scenario. The tester will be attempting to execute malware samples on a simulated internal user workstation. At the same time, you will need to configure PicoSecure’s security tools to detect and prevent the malware from executing.

Following the **Pyramid of Pain’s** ascending priority of indicators, your objective is to increase the simulated adversaries’ cost of operations and chase them away for good. Each level of the pyramid allows you to detect and prevent various indicators of attack.

Room Prerequisites

Completing the preceding rooms in the [Cyber Defence Frameworks module](https://tryhackme.com/module/cyber-defence-frameworks) will be beneficial before venturing into this challenge. Specifically, the following:

- **[The Pyramid of Pain](https://tryhackme.com/room/pyramidofpainax)**
- **[MITRE](https://tryhackme.com/room/mitre)**

Connection Details

Please click **Start Machine** to deploy the application, and navigate to **`https://<<TARGET-IP>>.p.thmlabs.com`** once the URL has been populated.

**NOTE** It may take a few minutes to deploy the machine entirely. If you receive a “Bad Gateway” response, wait a few minutes and refresh the page.

In this room, we have to stimulate configuring rules to detect and prevent malware attacks. As we enter the site, one of the emails sends us a malware sample and tells us to add a detection rule to block it.

Let’s first look around the website to see what we can do.

![](01%20-%20Cyber%20Defence%20Frameworks/_resources/07%20Summit%20(Practice%20Room)/2b7394521dd3226a3ae3ef3e1f4be4fa_MD5.jpg)

- **Malware Sandbox**: Automated analysis engine for malware and malicious behaviour detection
- **Manage Hashes**: Block threats based on file signatures
- **Firewall Rule Manager**: set firewall rules to Allow/Deny incoming and outgoing traffic based on source and destination Ip addresses
- **DNS Rule Manager**: configure DNS rules to Allow/Deny incoming and outgoing traffic based on domain or subdomain name
- **Sigma Rule Builder**: user-friendly interface for crafting or modifying Sigma rules

**Getting start:**

I first upload **sample1.exe** into the malware sandbox.

![](01%20-%20Cyber%20Defence%20Frameworks/_resources/07%20Summit%20(Practice%20Room)/05ff0f264602228972f6a426074ae868_MD5.jpg)

The mail sending us this malware sample mentions “Maybe there’s a unique way for you to distinguish this file and add a detection rule to block it.” Therefore, it’s quite obvious that we can block this malware based on the file signature.

![](01%20-%20Cyber%20Defence%20Frameworks/_resources/07%20Summit%20(Practice%20Room)/1cc95324270ddeeec76b7dcfd3186edf_MD5.jpg)

I put one of the hashes into the Hash blocklist and suddenly got another mail containing **sample2.exe** and the first flag.

![](01%20-%20Cyber%20Defence%20Frameworks/_resources/07%20Summit%20(Practice%20Room)/e095152b853938d06b6a25b725324a99_MD5.jpg)

**What is the first flag you receive after successfully detecting sample1.exe?**

- `THM{f3cbf08151a11a6a331db9c6cf5f4fe4}`

Although signature-based is an easy and simple method to block malicious files, it has certain weaknesses such as false positive/negative results, being limited to only known threats, and most importantly it can be easily evaded by altering the file content which will make a hash of the file completely different. For this reason, the attacker now makes it so that we can no longer use a hash blacklist to block his file.

![](01%20-%20Cyber%20Defence%20Frameworks/_resources/07%20Summit%20(Practice%20Room)/d1341a5c574142f41806e624863cb1e9_MD5.jpg)

By using a malware sandbox, I noticed the suspicious process **"sample2.exe"** reach out to IP **154.35.10.133**, so I blocked any traffic going out to that IP with a Firewall rule. Then got 1 more email from the tester.

![](01%20-%20Cyber%20Defence%20Frameworks/_resources/07%20Summit%20(Practice%20Room)/b9727f9901f7240719a1ee906fa9dd04_MD5.jpg)

![](01%20-%20Cyber%20Defence%20Frameworks/_resources/07%20Summit%20(Practice%20Room)/9a82fb13a4d0b166523f7d2c07a26e7b_MD5.jpg)

**What is the second flag you receive after successfully detecting sample2.exe?**

- `THM{2ff48a3421a938b388418be273f4806d}`

After we block his server Ip address, the attacker now uses a cloud service provider so that he can change his Ip over time. I also have to change the method to detect this changing threat in **sample3.exe**.

![](01%20-%20Cyber%20Defence%20Frameworks/_resources/07%20Summit%20(Practice%20Room)/5a7a849a763ce13b95032795f3653949_MD5.jpg)

Instead of relying solely on IP addresses, I tried blocking the malicious domain associated with the threat by adding **emudyn.bresonicz.info** to the DNS Filter.

![](01%20-%20Cyber%20Defence%20Frameworks/_resources/07%20Summit%20(Practice%20Room)/458fe4c414c4c7bde898349916e66bea_MD5.jpg)

![](01%20-%20Cyber%20Defence%20Frameworks/_resources/07%20Summit%20(Practice%20Room)/4b13b0f13f4d74304e27524d214fbf50_MD5.jpg)

**What is the third flag you receive after successfully detecting sample3.exe?**

- `THM{4eca9e2f61a19ecd5df34c788e7dce16}`

We cannot simply block hashes, IPs, or domains this time, but we’re not done yet.

![](01%20-%20Cyber%20Defence%20Frameworks/_resources/07%20Summit%20(Practice%20Room)/87f14342bd7ae337bf34f47a0f1ef6f5_MD5.jpg)

With the help of our best friend, malware sandbox, we can see the activity of **sample4.exe** making changes to Real-time Protection. I headed to the tool that we’ve never used: **Sigma Rule Builder** which has several rules we can set. I use **Sysmon Event Logs -> Registry Modifications** to set a rule detecting the change of settings and receive the next email.

![](01%20-%20Cyber%20Defence%20Frameworks/_resources/07%20Summit%20(Practice%20Room)/2f0ca566811f90d8e5644ab02130b09e_MD5.jpg)

![](01%20-%20Cyber%20Defence%20Frameworks/_resources/07%20Summit%20(Practice%20Room)/70c7dfeb028aa09df7be1fc7191f65d2_MD5.jpg)

**What is the fourth flag you receive after successfully detecting sample4.exe?**

- `THM{c956f455fc076aea829799c0876ee399}`

For **sample5.exe,** we focus on the log file since the threat further evolves to the point that the attacker can dynamically change various artifacts such as IP addresses and ports.

![](01%20-%20Cyber%20Defence%20Frameworks/_resources/07%20Summit%20(Practice%20Room)/d9206b6bb569615fe937452b7e5865a3_MD5.jpg)

We can easily spot the behavior of this malware on the log as we have suspicious outgoing traffic with a size of **97 bytes** every **30 minutes**.

![](01%20-%20Cyber%20Defence%20Frameworks/_resources/07%20Summit%20(Practice%20Room)/b5eff610a248dc011cf655588c255e2e_MD5.jpg)

I use Sigma Rule Builder -> Sysmon Event Logs -> Network Connections to detect network traffic patterns. R-host and R-port are set to Any because the attacker can easily change them anytime.

![](01%20-%20Cyber%20Defence%20Frameworks/_resources/07%20Summit%20(Practice%20Room)/f6646afbc1d8ee671f4c1cc83fea639a_MD5.jpg)

**What is the fifth flag you receive after successfully detecting sample5.exe?**

- `THM{46b21c4410e47dc5729ceadef0fc722e}`

![](01%20-%20Cyber%20Defence%20Frameworks/_resources/07%20Summit%20(Practice%20Room)/c44542027e371a25bee5f7ff10bbaa75_MD5.jpg)

In this last challenge, **sample6.exe**, we can see from the command history that the malware runs a series of command lines to gather information about the system as well as network configuration, then saves the results to a log file named **“exfiltr&.log”** in **“temp”** directory.

![](01%20-%20Cyber%20Defence%20Frameworks/_resources/07%20Summit%20(Practice%20Room)/5026e5e8309afa9bc8fe08d0debdfc5c_MD5.jpg)

I configured **Sigma Rule Builder/Sysmon Event Logs/File Creation and Modification** to detect the creation/modification of files in order to prevent the malware from gathering system information. And just like that, the attacker finally gave up and sent us the final flag.

![](01%20-%20Cyber%20Defence%20Frameworks/_resources/07%20Summit%20(Practice%20Room)/82ddccf1d9714660bb0e31c56e171eaa_MD5.jpg)

**What is the final flag you receive from Sphinx?**

- `THM{c8951b2ad24bbcbac60c16cf2c83d92c}`

