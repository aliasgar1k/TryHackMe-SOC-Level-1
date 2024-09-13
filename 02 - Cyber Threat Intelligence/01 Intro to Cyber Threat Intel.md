Introducing cyber threat intelligence and related topics, such as relevant standards and frameworks.

![](_resources/01%20Intro%20to%20Cyber%20Threat%20Intel/8ba585f697334d19b067a86fcabd52de_MD5.jpg)

# Task 1 Introduction

**Introduction**

This room will introduce you to cyber threat intelligence (CTI) and various frameworks used to share intelligence. As security analysts, CTI is vital for investigating and reporting against adversary attacks with organisational stakeholders and external communities.

**Learning Objectives**

- The basics of CTI and its various classifications.
- The lifecycle followed to deploy and use intelligence during threat investigations.
- Frameworks and standards used in distributing intelligence.

**Cyber Threat Intelligence Module**

This is the first room in a new Cyber Threat Intelligence module. The module will also contain:

- [Threat Intelligence Tools](https://tryhackme.com/room/threatinteltools)
- [YARA](https://tryhackme.com/room/yara)
- [OpenCTI](https://tryhackme.com/room/opencti)
- [MISP](https://tryhackme.com/room/misp)

# Task 2 Cyber Threat Intelligence

Cyber Threat Intelligence (CTI) can be defined as evidence-based knowledge about adversaries, including their indicators, tactics, motivations, and actionable advice against them. These can be utilised to protect critical assets and inform cybersecurity teams and management business decisions.

It would be typical to use the terms “data”, “information”, and “intelligence” interchangeably. However, let us distinguish between them to understand better how CTI comes into play.

![](_resources/01%20Intro%20to%20Cyber%20Threat%20Intel/8ba585f697334d19b067a86fcabd52de_MD5.jpg)

**Data:** Discrete indicators associated with an adversary such as IP addresses, URLs or hashes.

**Information:** A combination of multiple data points that answer questions such as “How many times have employees accessed tryhackme.com within the month?”

**Intelligence:** The correlation of data and information to extract patterns of actions based on contextual analysis.

The primary goal of CTI is to understand the relationship between your operational environment and your adversary and how to defend your environment against any attacks. You would seek this goal by developing your cyber threat context by trying to answer the following questions:

- Who’s attacking you?
- What are their motivations?
- What are their capabilities?
- What artefacts and indicators of compromise (IOCs) should you look out for?

With these questions, threat intelligence would be gathered from different sources under the following categories:

**Internal:**

- Corporate security events such as vulnerability assessments and incident response reports.
- Cyber awareness training reports.
- System logs and events.

**Community:**

- Open web forums.
- Dark web communities for cybercriminals.

**External**

- Threat intel feeds (Commercial & Open-source)
- Online marketplaces.
- Public sources include government data, publications, social media, financial and industrial assessments.

## Threat Intelligence Classifications:

Threat Intel is geared towards understanding the relationship between your operational environment and your adversary. With this in mind, we can break down threat intel into the following classifications:

![](_resources/01%20Intro%20to%20Cyber%20Threat%20Intel/555042a0fc888efaf4a4cece752ad7ab_MD5.jpg)

- **Strategic Intel:** High-level intel that looks into the organisation’s threat landscape and maps out the risk areas based on trends, patterns and emerging threats that may impact business decisions.
- **Technical Intel:** Looks into evidence and artefacts of attack used by an adversary. Incident Response teams can use this intel to create a baseline attack surface to analyse and develop defence mechanisms.
- **Tactical Intel:** Assesses adversaries’ tactics, techniques, and procedures (TTPs). This intel can strengthen security controls and address vulnerabilities through real-time investigations.
- **Operational Intel:** Looks into an adversary’s specific motives and intent to perform an attack. Security teams may use this intel to understand the critical assets available in the organisation (people, processes and technologies) that may be targeted.

### Answer the questions below

Since the answer can be found about, it won’t be posted here. Follow along so that if you aren’t sure of the answer you know where to find it.

**What does CTI stand for?**
![](_resources/01%20Intro%20to%20Cyber%20Threat%20Intel/0ee376ae4f7585bd2e1e69dbb61f719c_MD5.jpg)

**IP addresses, Hashes and other threat artefacts would be found under which Threat Intelligence classification?**
![](_resources/01%20Intro%20to%20Cyber%20Threat%20Intel/75802c80c01eb8890856866a8494be06_MD5.jpg)

# Task 3 CTI Lifecycle

Threat intel is obtained from a data-churning process that transforms raw data into contextualised and action-oriented insights geared towards triaging security incidents. The transformational process follows a six-phase cycle:

![](_resources/01%20Intro%20to%20Cyber%20Threat%20Intel/17a81f1f565fde9294d530b84b8cb405_MD5.jpg)

## Direction

Every threat intel program requires to have objectives and goals defined, involving identifying the following parameters:

- Information assets and business processes that require defending.
- Potential impact to be experienced on losing the assets or through process interruptions.
- Sources of data and intel to be used towards protection.
- Tools and resources that are required to defend the assets.

This phase also allows security analysts to pose questions related to investigating incidents.

## Collection

Once objectives have been defined, security analysts will gather the required data to address them. Analysts will do this by using commercial, private and open-source resources available. Due to the volume of data analysts usually face, it is recommended to automate this phase to provide time for triaging incidents.

## Processing

Raw logs, vulnerability information, malware and network traffic usually come in different formats and may be disconnected when used to investigate an incident. This phase ensures that the data is extracted, sorted, organised, correlated with appropriate tags and presented visually in a usable and understandable format to the analysts. SIEMs are valuable tools for achieving this and allow quick parsing of data.

## Analysis

Once the information aggregation is complete, security analysts must derive insights. Decisions to be made may involve:

- Investigating a potential threat through uncovering indicators and attack patterns.
- Defining an action plan to avert an attack and defend the infrastructure.
- Strengthening security controls or justifying investment for additional resources.

## Dissemination

Different organisational stakeholders will consume the intelligence in varying languages and formats. For example, C-suite members will require a concise report covering trends in adversary activities, financial implications and strategic recommendations. At the same time, analysts will more likely inform the technical team about the threat IOCs, adversary TTPs and tactical action plans.

## Feedback

The final phase covers the most crucial part, as analysts rely on the responses provided by stakeholders to improve the threat intelligence process and implementation of security controls. Feedback should be regular interaction between teams to keep the lifecycle working.

### Answer the questions below

**At which phase of the lifecycle is data made usable through sorting, organising, correlation and presentation?**
![](_resources/01%20Intro%20to%20Cyber%20Threat%20Intel/a63a16f8c55d86092376a15d5a5acc34_MD5.jpg)

**During which phase do security analysts get the chance to define the questions to investigate incidents?**
![](_resources/01%20Intro%20to%20Cyber%20Threat%20Intel/8c4c95782cfec44ee15d5f5501e96d8a_MD5.jpg)

# Task 4 CTI Standards & Frameworks

Standards and frameworks provide structures to rationalise the distribution and use of threat intel across industries. They also allow for common terminology, which helps in collaboration and communication. Here, we briefly look at some essential standards and frameworks commonly used.

## MITRE ATT&CK

The [ATT&CK framework](https://tryhackme.com/room/mitre) is a knowledge base of adversary behaviour, focusing on the indicators and tactics. Security analysts can use the information to be thorough while investigating and tracking adversarial behaviour.

![](_resources/01%20Intro%20to%20Cyber%20Threat%20Intel/b7983f67d4701c24a1671aeaecc3b078_MD5.jpg)

## TAXII

[The Trusted Automated eXchange of Indicator Information (TAXII)](https://oasis-open.github.io/cti-documentation/taxii/intro) defines protocols for securely exchanging threat intel to have near real-time detection, prevention and mitigation of threats. The protocol supports two sharing models:

- **Collection**: Threat intel is collected and hosted by a producer upon request by users using a request-response model.
- **Channel**: Threat intel is pushed to users from a central server through a publish-subscribe model.

## STIX

[Structured Threat Information Expression (STIX)](https://oasis-open.github.io/cti-documentation/stix/intro) is a language developed for the “specification, capture, characterisation and communication of standardised cyber threat information”. It provides defined relationships between sets of threat info such as observables, indicators, adversary TTPs, attack campaigns, and more.

## Cyber Kill Chain

Developed by Lockheed Martin, the Cyber Kill Chain breaks down adversary actions into steps. This breakdown helps analysts and defenders identify which stage-specific activities occurred when investigating an attack. The phases defined are shown in the image below.

![](_resources/01%20Intro%20to%20Cyber%20Threat%20Intel/882face2a4dc7fb0fe0c0ccd9cd54b08_MD5.jpg)

TechniquePurposeExamplesReconnaissanceObtain information about the victim and the tactics used for the attack.Harvesting emails, OSINT, and social media, network scansWeaponisationMalware is engineered based on the needs and intentions of the attack.Exploit with backdoor, malicious office documentDeliveryCovers how the malware would be delivered to the victim’s system.Email, weblinks, USBExploitationBreach the victim’s system vulnerabilities to execute code and create scheduled jobs to establish persistence.

EternalBlue, Zero-Logon, etc.InstallationInstall malware and other tools to gain access to the victim’s system.Password dumping, backdoors, remote access trojansCommand & ControlRemotely control the compromised system, deliver additional malware, move across valuable assets and elevate privileges.Empire, Cobalt Strike, etc.Actions on ObjectivesFulfil the intended goals for the attack: financial gain, corporate espionage, and data exfiltration.Data encryption, ransomware, public defacement

Over time, the kill chain has been expanded using other frameworks such as ATT&CK and formulated a new Unified Kill Chain.

## The Diamond Model

The diamond model looks at intrusion analysis and tracking attack groups over time. It focuses on four key areas, each representing a different point on the diamond. These are:

![](_resources/01%20Intro%20to%20Cyber%20Threat%20Intel/721035d1bc02b2655a131ad1f715f081_MD5.jpg)

- **Adversary:** The focus here is on the threat actor behind an attack and allows analysts to identify the motive behind the attack.
- **Victim:** The opposite end of adversary looks at an individual, group or organisation affected by an attack.
- **Infrastructure:** The adversaries’ tools, systems, and software to conduct their attack are the main focus. Additionally, the victim’s systems would be crucial to providing information about the compromise.
- **Capabilities:** The focus here is on the adversary’s approach to reaching its goal. This looks at the means of exploitation and the TTPs implemented across the attack timeline.

An example of the diamond model in play would involve an adversary targeting a victim using phishing attacks to obtain sensitive information and compromise their system, as displayed on the diagram. As a threat intelligence analyst, the model allows you to pivot along its properties to produce a complete picture of an attack and correlate indicators.

### Answer the questions below

**What sharing models are supported by TAXII?**
![](_resources/01%20Intro%20to%20Cyber%20Threat%20Intel/fe5aeda34531fbb06fdea92d6296f841_MD5.jpg)

**When an adversary has obtained access to a network and is extracting data, what phase of the kill chain are they on?**
![](_resources/01%20Intro%20to%20Cyber%20Threat%20Intel/59cc351d65c1c31d280bf78f50624477_MD5.jpg)

# Task 5 Practical Analysis

![](_resources/01%20Intro%20to%20Cyber%20Threat%20Intel/5b71e46d5a9d9a897f5d69631479b523_MD5.jpg)

As part of the dissemination phase of the lifecycle, CTI is also distributed to organisations using published threat reports. These reports come from technology and security companies that research emerging and actively used threat vectors. They are valuable for consolidating information presented to all suitable stakeholders. Some notable threat reports come from [Mandiant](https://www.mandiant.com/resources), [Recorded Future](https://www.recordedfuture.com/resources/global-issues) and [AT&TCybersecurity](https://cybersecurity.att.com/).

All the things we have discussed come together when mapping out an adversary based on threat intel. To better understand this, we will analyse a simplified engagement example. Click on the green “**View Site**” button in this task to open the Static Site Lab and navigate through the security monitoring tool on the right panel and fill in the threat details.

### Answer the questions below

Start off by opening the static site by clicking the green View Site Button. This will split the screen in half and on the right side of the screen will be the practical side with the information needed to answer the question.

![](_resources/01%20Intro%20to%20Cyber%20Threat%20Intel/1576cc60355b35cc6a33aecd49de7e11_MD5.jpg)

**What was the source email address?**
Looking down through Alert logs we can see that an email was received by John Doe. The email address that is at the end of this alert is the email address that question is asking for. Once you find it, highlight then copy (ctrl + c ) and paste (ctrl +v ) or type, the answer into TryHackMe Answer field, then click submit.

![](_resources/01%20Intro%20to%20Cyber%20Threat%20Intel/1f00b05769e174fa66f40701eae77e33_MD5.jpg)
**Answer: vipivillain@badbank.com**

**What was the name of the file downloaded?**
Look at the Alert above the one from the previous question, it will say File download inititiated. At the end of this alert is the name of the file, this is the answer to this quesiton. Once you find it, highlight then copy (ctrl + c ) and paste (ctrl +v ) or type, the answer into TryHackMe Answer field, then click submit.

![](_resources/01%20Intro%20to%20Cyber%20Threat%20Intel/299bc1f291c66bff73c209950c36dff4_MD5.jpg)
**Answer: flbpfuh.exe**

**After building the threat profile, what message do you receive?**
For this section you will scroll down, and have five different questions to answer. The answers to these questions can be found in the Alert Logs above. The way I am going to go through these is, the three at the top then the two at the bottom. I have them numbered to better find them below.

![](_resources/01%20Intro%20to%20Cyber%20Threat%20Intel/6b6f4aa36d43931ecefd28904092062f_MD5.jpg)

1. **What was the threat actor’s extraction IP address?**

![](_resources/01%20Intro%20to%20Cyber%20Threat%20Intel/48cffa02e1ff60f36e908f935b234543_MD5.jpg)

Looking at the Alert Logs we can see that we have Outbound and Internal traffic from a certain IP address that seem sus, this is the attackers IP address. Once you find it, highlight then copy (ctrl + c ) and paste (ctrl +v ) or type, the answer into answer field and click the blue Check Answer button.

![](_resources/01%20Intro%20to%20Cyber%20Threat%20Intel/d87e7b5a83a7376da25639911be58094_MD5.jpg)
**Answer:**

2. **What was the threat actor’s email address?**

![](_resources/01%20Intro%20to%20Cyber%20Threat%20Intel/b8772ce6021908f169b101f5ffab2d20_MD5.jpg)

We answer this question already with the first question of this task. Looking down through Alert logs we can see that an email was received by John Doe. The email address that is at the end of this alert is the email address that question is asking for. Once you find it, highlight then copy (ctrl + c ) and paste (ctrl +v ) or type, the answer into answer field and click the blue Check Answer button.

![](_resources/01%20Intro%20to%20Cyber%20Threat%20Intel/2a98de4d24b432cdcf8269760a42cfa9_MD5.jpg)
**Answer: vipivillain@badbank.com**

3. **What software tool was used in the extraction?**

![](_resources/01%20Intro%20to%20Cyber%20Threat%20Intel/cab948b9bcdfd59c4cd9a047402e52e4_MD5.jpg)

We answer this question already with the second question of this task. Look at the Alert above the one from the previous question, it will say File download inititiated. At the end of this alert is the name of the file, this is the answer to this quesiton. Once you find it, highlight then copy (ctrl + c ) and paste (ctrl +v ) or type, the answer into answer field and click the blue Check Answer button.

![](_resources/01%20Intro%20to%20Cyber%20Threat%20Intel/e9e1ee57f5f511eeffd77aaba8ef3159_MD5.jpg)
**Answer: flbpfuh.exe**

4. **What user account was logged in by the threat actor?**

![](_resources/01%20Intro%20to%20Cyber%20Threat%20Intel/c87e915b854cb8883ca5a615ee9e3367_MD5.jpg)

The Alert that this question is talking about is at the top of the Alert list. It states that an account was Logged on successfully. The account at the end of this Alert is the answer to this question. Once you find it, highlight then copy (ctrl + c ) and paste (ctrl +v ) or type, the answer into answer field and click the blue Check Answer button.

![](_resources/01%20Intro%20to%20Cyber%20Threat%20Intel/92ab222573ee4b1034027895c2a30a34_MD5.jpg)
**Answer: Administrator**

5. **Who was the targeted victim?**

![](_resources/01%20Intro%20to%20Cyber%20Threat%20Intel/9785aa2349ee20d6abfb473014728dbe_MD5.jpg)

On the Alert log we see a name come up a couple times, this person is the victim to the initite attack and the answer to this question. Once you find it, highlight then copy (ctrl + c ) and paste (ctrl +v ) or type, the answer into answer field and click the blue Check Answer button.

![](_resources/01%20Intro%20to%20Cyber%20Threat%20Intel/1b4ecba1f502d9ac188a8a9cf5d1b393_MD5.jpg)
**Answer: John Doe**

**The Flag!!!!!!**
Once you answer that last question, TryHackMe will give you the Flag.

![](_resources/01%20Intro%20to%20Cyber%20Threat%20Intel/5c7cb207ca0b2275b0c1fa4c6e30ce7a_MD5.jpg)

Once you find it, highlight then copy (ctrl + c ) and paste (ctrl +v ) or type, the answer into TryHackMe Answer field, then click submit.

**Answer: THM{NOW_I_CAN_CTI}**

🎉🎉Congrats!!! You have completed the Intro to Cyber Threat Intel🎉🎉