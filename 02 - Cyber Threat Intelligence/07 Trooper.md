https://medium.com/@0x4C1D/try-hack-me-trooper-walkthrough-d4ddecd7254a
https://medium.com/@DaoudaD/tryhackme-trooper-writeup-c4fd8a8f28b7
https://www.youtube.com/watch?v=gOdiFxHVBG4

A multinational technology company has been the target of several cyber attacks in the past few months. The attackers have been successful in stealing sensitive intellectual property and causing disruptions to the company’s operations. A [threat advisory report](https://assets.tryhackme.com/additional/trooper-cti/APT_X_USBFerry.pdf) about similar attacks has been shared, and as a CTI analyst, your task is to identify the Tactics, Techniques, and Procedures (TTPs) being used by the Threat group and gather as much information as possible about their identity and motive. For this task, you will utilize the [OpenCTI](https://tryhackme.com/room/opencti) platform as well as the MITRE ATT&CK navigator, linked to the details below.

# Assigned Tools

Start the virtual machine by clicking on the green “**Start Machine**” button on the upper right section of this task. Give it about **7 minutes** to fully load and use the credentials below to access the platforms via the AttackBox or VPN to conduct your investigations.

![](02%20-%20Cyber%20Threat%20Intelligence/_resources/07%20Trooper/acb6e8ddd33adbe7d97b5ed2f72e3eb3_MD5.jpeg)

**What kind of phishing campaign does APT X use as part of their TTPs ?**

The given report sample shows that APT X is known for using **spear-phishing emails as initial acces tactic .**



Answer: Spear-phishing emails

**What is the name of the malware used by APT X ?**

The report states that APT X’s latest activities center on targeting Taiwanese and the Philippine military’s physically isolated networks through a **USBferry attack** (the name derived from a sample found in a related research).

Answer: USBferry

**What is the malware’s STIX ID ?**

We’ll utilize our threat intelligence platform, OpenCTI, for this task. After accessing OpenCTI, we need to check for the USBferry malware.

![](02%20-%20Cyber%20Threat%20Intelligence/_resources/07%20Trooper/d30441fa67affd640741b6abf4d79104_MD5.jpg)

![](02%20-%20Cyber%20Threat%20Intelligence/_resources/07%20Trooper/ff27adfbe0a3383b44c2828196299bf2_MD5.jpg)

Answer: 5d0ea014–1ce9–5d5c-bcc7-f625a07907d0

**With the use of a USB, what technique did APT X use for initial access ?**

You can find this information using the MITRE ATT&CK Navigator. By examining the initial access tactics associated with this group, you can identify the techniques employed by the threat actor.

![](02%20-%20Cyber%20Threat%20Intelligence/_resources/07%20Trooper/34299eb83db1cf639e06a9ccc828c12f_MD5.jpg)

Answer: Replication through removable media

**What is the identity of APT X ?**

**APT X** is known by **Tropic Trooper** .

![](02%20-%20Cyber%20Threat%20Intelligence/_resources/07%20Trooper/5e02d8ec0016724542c4d57b9c29ca2a_MD5.jpg)

This can also be found using OpenCTI, by checking the reports related to USBferry.

![](02%20-%20Cyber%20Threat%20Intelligence/_resources/07%20Trooper/0408a09851d18bdf76835206bc26de4c_MD5.jpg)

Answer: Tropic Trooper

**On OpenCTI, how many Attack Pattern techniques are associated with the APT ?**

![](02%20-%20Cyber%20Threat%20Intelligence/_resources/07%20Trooper/bfcdbdba4fd5373a8833bdf2ff29595a_MD5.jpg)

**39 attack patterns** are associated with Tropic Trooper threat actor .

Answer: 39

**What is the name of the tool linked to the APT ?**

Using OPENCTI, we can find tools used by Tropic Trooper group, but checking the **arsenal menu** related to the threat actor in the right corner, then **tools**.

![](02%20-%20Cyber%20Threat%20Intelligence/_resources/07%20Trooper/517831b171b7cf17fad2ce839b0890aa_MD5.jpg)

Answer: BITSAdmin

**Load up the Navigator. What is the sub-technique used by the APT under Valid Accounts ?**

https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fgroups%2FG0081%2FG0081-enterprise-layer.json

Review the persistence tactic, then expand the “**Valid Accounts**” technique at the bottom.

![](02%20-%20Cyber%20Threat%20Intelligence/_resources/07%20Trooper/c4aee48955eebf75dabf510f85d76910_MD5.jpg)

Answer: Local Accounts

**Under what Tactics does the technique above fall ?**

https://attack.mitre.org/techniques/T1078/003/

The “**local accounts**” technique can be classified under four distinct tactics in the MITRE ATT&CK framework: Initial Access, Persistence, Defense Evasion, and Privilege Escalation. This classification highlights the versatility and impact of local accounts in a cybersecurity context.

**Initial Access**: Local accounts can be used by attackers to gain initial access to a system, particularly if they exploit weak or default credentials that provide entry points into a network or system.

**Persistence**: Once inside a system, attackers can create or manipulate local accounts to maintain access over time. By establishing local accounts with persistent access, they ensure that they can return to the system even if other access methods are discovered and removed.

**Defense Evasion**: Local accounts may help in evading detection by blending in with legitimate accounts or avoiding monitoring systems that focus on network or domain-level activities. Attackers might use local accounts to avoid triggering security alerts that are typically configured for network-based threats.

**Privilege Escalation**: Attackers might leverage local accounts to escalate privileges. For instance, if they manage to create or modify local administrator accounts, they can gain elevated privileges that allow them to perform actions with higher levels of access and control.

Answer: Initial Access, Persistence, Defense Evasion and Privilege Escalation

**What technique is the group known for using under the tactic Collection?**

The group is known for using an “**automated collection”** technique as part of their **collection** strategy.

![](02%20-%20Cyber%20Threat%20Intelligence/_resources/07%20Trooper/65d673bbace72307979dad691d6a08b3_MD5.jpg)

Answer : Automated Collection



