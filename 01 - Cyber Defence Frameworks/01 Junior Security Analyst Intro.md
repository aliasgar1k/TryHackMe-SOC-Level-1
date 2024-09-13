https://www.youtube.com/watch?v=9oOQLED6mRU
https://medium.com/@AbhijeetSingh4/cyber-defense-frameworks-65a1a06c99ab
https://medium.com/@jcm3/junior-security-analyst-intro-tryhackme-walkthrough-b66190a54976

# Task 1 A career as a Junior (Associate) Security Analyst

![](_resources/01%20Junior%20Security%20Analyst%20Intro/c731e402beb5c65a7ac3df11b2c9b88c_MD5.webp)

In the Junior Security Analyst role, you will be a Triage Specialist. You will spend a lot of time triaging or monitoring the event logs and alerts.

The responsibilities for a Junior Security Analyst or Tier 1 SOC Analyst include:

- Monitor and investigate the alerts (most of the time, it’s a 24x7 SOC operations environment)
- Configure and manage the security tools
- Develop and implement basic [IDS (Intrusion Detection System)](https://www.barracuda.com/glossary/intrusion-detection-system) signatures
- Participate in SOC working groups, meetings
- Create tickets and escalate the security incidents to the Tier 2 and Team Lead if needed

Required qualifications (most common):

- 0–2 years of experience with Security Operations
- Basic understanding of Networking ( OSI model (Open Systems Interconnection Model) or TCP/IP model (Transmission Control Protocol/Internet Protocol Model)), Operating Systems (Windows, Linux), Web applications. To further learn about OSI and TCP/IP models, please refer to the [Introductory Networking Room](https://tryhackme.com/room/introtonetworking).
- Scripting/programming skills are a plus

Desired certification:

- [CompTIA Security+](https://www.comptia.org/certifications/security)

As you progress and advance your skills as a Junior Security Analyst, you will eventually move up to Tier 2 and Tier 3.

An overview of the Security Operations Center (SOC) Three-Tier Model:

![](_resources/01%20Junior%20Security%20Analyst%20Intro/179e59228a29d20bc32253b2217a887e_MD5.jpg)

### Answer the questions below

![](_resources/01%20Junior%20Security%20Analyst%20Intro/144b28a7fe814c0937b3c9c48d791445_MD5.jpg)

# Task 2 Security Operations Center (SOC)

![](_resources/01%20Junior%20Security%20Analyst%20Intro/a5eb259bcd86536e2f9a7d200abcf891_MD5.jpg)

## **So, what exactly is a SOC?**

The core function of a SOC (Security Operations Center) is to investigate, monitor, prevent, and respond to threats in the cyber realm 24/7 or around the clock. Per [McAfee’s definition of a SOC](https://www.mcafee.com/enterprise/en-us/security-awareness/operations/what-is-soc.html), “Security operations teams are charged with monitoring and protecting many assets, such as intellectual property, personnel data, business systems, and brand integrity. As the implementation component of an organisation’s overall cyber security framework, security operations teams act as the central point of collaboration in coordinated efforts to monitor, assess, and defend against cyberattacks”. The number of people working in the SOC can vary depending on the organisation’s size.

## **What is included in the responsibilities of the SOC?**

![](_resources/01%20Junior%20Security%20Analyst%20Intro/21239ecde1b0cab57a5faf714c0aa4f5_MD5.jpg)

### **Preparation and Prevention**

As a Junior Security Analyst, you should stay informed of the current cyber security threats (Twitter and [Feedly](https://feedly.com/i/welcome) can be great resources to keep up with the news related to Cybersecurity). It’s crucial to detect and hunt threats, work on a [security roadmap](https://www.mcafee.com/enterprise/en-us/security-awareness/cybersecurity/creating-cybersecurity-strategy.html) to protect the organisation, and be ready for the worst-case scenario.

Prevention methods include gathering intelligence data on the latest threats, threat actors, and their [TTPs (Tactics, Techniques, and Procedures)](https://www.optiv.com/explore-optiv-insights/blog/tactics-techniques-and-procedures-ttps-within-cyber-threat-intelligence). It also includes the maintenance procedures like updating the firewall signatures, patching the vulnerabilities in the existing systems, block-listing and safe-listing applications, email addresses, and IPs.

To better understand the TTPs, you should look into one of the CISA’s (Cybersecurity & Infrastructure Security Agency) alerts on APT40 (Chinese Advanced Persistent Threat). Refer to the following link for more information, [https://us-cert.cisa.gov/ncas/alerts/aa21-200a](https://us-cert.cisa.gov/ncas/alerts/aa21-200a).

### **Monitoring and Investigation**

A SOC team proactively uses [SIEM (Security information and event management)](https://www.fireeye.com/products/helix/what-is-siem-and-how-does-it-work.html) and [EDR (Endpoint Detection and Response)](https://www.mcafee.com/enterprise/en-us/security-awareness/endpoint/what-is-endpoint-detection-and-response.html) tools to monitor suspicious and malicious network activities. Imagine being a firefighter and having a multi-alarm fire — one-alarm fires, two-alarm fires, three-alarm fires; the categories classify the seriousness of the fire, which is a threat in our case. As a Security Analyst, you will learn how to prioritise the alerts based on their level: Low, Medium, High, and Critical. Of course, it is an easy guess that you will need to start from the highest level (Critical) and work towards the bottom — Low-level alert. Having properly configured security monitoring tools in place will give you the best chance to mitigate the threat.

Junior Security Analysts play a crucial role in the investigation procedure. They perform triaging on the ongoing alerts by exploring and understanding how a certain attack works and preventing bad things from happening if they can. During the investigation, it’s important to raise the question “How? When, and why?”. Security Analysts find the answers by drilling down on the data logs and alerts in combination with using open-source tools, which we will have a chance to explore later in this path.

### **Response**

After the investigation, the SOC team coordinates and takes action on the compromised hosts, which involves isolating the hosts from the network, terminating the malicious processes, deleting files, and more.

### Answer the questions below 

![](_resources/01%20Junior%20Security%20Analyst%20Intro/6ac8ec314af70b6b11bc09597e61e83c_MD5.jpg)

# Task 3 A day In the life of a Junior (Associate) Security Analyst

![](_resources/01%20Junior%20Security%20Analyst%20Intro/2025feb27de86cd54d517067f134d2f7_MD5.jpg)

To understand the job responsibilities for a Junior (Associate) Security Analyst, let us first show you what a day in the life of the Junior Security Analyst looks like and why this is an exciting career journey.

To be in the frontline is not always easy and can be very challenging as you will be working with various log sources from different tools that we will walk you through in this path. You will get a chance to monitor the network traffic, including IPS (Intrusion Prevention System) and IDS (Intrusion Detection System) alerts, suspicious emails, extract the forensics data to analyze and detect the potential attacks, use open-source intelligence to help you make the appropriate decisions on the alerts.

One of the most exciting and rewarding things is when you are finished working on an incident and have managed to remediate the threat. Incident Response might take hours, days, or weeks; it all depends on the scale of the attack: did the attacker manage to exfiltrate the data? How much data does the attacker manage to exfiltrate? Did the attacker attempt to pivot into other hosts? There are many questions to ask and a lot of detection, containment, and remediation to do. We will walk you through some fundamental knowledge that every Junior (Associate) Security Analyst needs to know to become a successful Network Defender.

The first thing almost every Junior (Associate) Security Analyst does on their shift is to look at the tickets to see if any alerts got generated.

Are you ready to immerse yourself into the role of a Junior Security Analyst for a little bit?

### Answer the questions below 

![](_resources/01%20Junior%20Security%20Analyst%20Intro/7704c2a946cfb2261156b4ce55a7b553_MD5.jpg)