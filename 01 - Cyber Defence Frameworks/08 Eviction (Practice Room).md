https://www.youtube.com/watch?v=oPqoXCIppuA
https://www.youtube.com/watch?v=GvGo17FdvNI
https://medium.com/@saloni1111997/eviction-tryhackme-walkthrough-b21bb3d4d41e

This room is by [TryHackme](https://tryhackme.com/r/room/eviction) and is beginner-friendly.

![](_resources/08%20Eviction%20(Practice%20Room)/7819f97f0a96ee928a93cbcdb41925c3_MD5.webp)

**Overview :**

This room helps you navigate APT’s TTPs (Tactics, Techniques and Procedures), key concepts in cybersecurity and threat intelligence. This room is also helpful in understanding how to navigate the MITRE ATT&CK Navigator layer.

**Case Study**

Sunny is a SOC analyst at E-corp, which manufactures rare earth metals for government and non-government clients. She receives a classified intelligence report that informs her that an APT group (APT28) might be trying to attack organizations similar to E-corp. To act on this intelligence, she must use the MITRE ATT&CK Navigator to identify the TTPs used by the APT group, to ensure it has not already intruded into the network, and to stop it if it has.

Please visit [this](https://static-labs.tryhackme.cloud/sites/eviction/) link to check out the MITRE ATT&CK Navigator layer for the APT group and answer the questions below.

[https://static-labs.tryhackme.cloud/sites/eviction/](https://static-labs.tryhackme.cloud/sites/eviction/)

![](_resources/08%20Eviction%20(Practice%20Room)/d4c9def2f366dbc61acb64f75bcdb7a6_MD5.jpg)

**What is a technique used by the APT to both perform recon and gain initial access?**

Answer: spearphishing link

**Sunny identified that the APT might have moved forward from the recon phase. Which accounts might the APT compromise while developing resources?**

Answer: email account

**E-corp has found that the APT might have gained initial access using social engineering to make the user execute code for the threat actor. Sunny wants to identify if the APT was also successful in execution. What two techniques of user execution should Sunny look out for?**

Answer: malicious file and malicious link

**If the above technique was successful, which scripting interpreters should Sunny search for to identify successful execution?**

Answer: Powershell and Windows command shell

**While looking at the scripting interpreters identified in Q4, Sunny found some obfuscated scripts that changed the registry. Assuming these changes are for maintaining persistence, which registry keys should Sunny observe to track these changes?**

Answer: registry run key

**Sunny identified that the APT executes system binaries to evade defences. Which system binary’s execution should Sunny scrutinize for proxy execution?**

Answer: rundll32

**Sunny identified tcpdump on one of the compromised hosts. Assuming this was placed there by the threat actor, which technique might the APT be using here for discovery?**

Answer: network sniffing

**It looks like the APT achieved lateral movement by exploiting remote services. Which remote services should Sunny observe to identify APT activity traces?**

Answer: SMB/Windows admin Share

**It looked like the primary goal of the APT was to steal intellectual property from E-corp’s information repositories. Which information repository can be the likely target of the APT?**

Answer: SharePoint

**Although the APT had collected the data, it could not connect to the C2 for data exfiltration. To thwart any attempts to do that, what types of proxy might the APT use?**

Answer: external proxy and multihop proxy

Congratulations! You have helped Sunny successfully thwart the APT’s nefarious designs by stopping it from achieving its goal of stealing the IP of E-corp.