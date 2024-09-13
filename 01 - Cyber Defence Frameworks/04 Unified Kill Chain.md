https://www.youtube.com/watch?v=eI_EQn9b9wk
https://medium.com/@haircutfish/tryhackme-unified-kill-chain-room-d106917a9ba3
https://medium.com/@AbhijeetSingh4/unified-kill-chain-soc-lavel-1-tryhackme-walkthrough-12f7c512a92c

The Unified Kill Chain is a framework which establishes the phases of an attack, and a means of identifying and mitigating risk to IT assets.
# Task 1 Introduction

![](_resources/04%20Unified%20Kill%20Chain/53d3ff2ddadacbbdcb6fb744a8f94d78_MD5.jpg)

Understanding the behaviours, objectives and methodologies of a cyber threat is a vital step to establishing a strong cybersecurity defence (known as a cybersecurity posture).

In this room, you will be introduced to the UKC (Unified Kill Chain) framework that is used to help understand how cyber attacks occur.

**Learning Objectives:**

- Understanding why frameworks such as the UKC are important and helpful in establishing a good cybersecurity posture
- Using the UKC to understand an attacker’s motivation, methodologies and tactics
- Understanding the various phases of the UKC
- Discover that the UKC is a framework that is used to complement other frameworks such as MITRE.

# Task 2 What is a “Kill Chain”

![](_resources/04%20Unified%20Kill%20Chain/cbb037928206d1f14d314cb337d4ca78_MD5.jpg)

Originating from the military, a “Kill Chain” is a term used to explain the various stages of an attack. In the realm of cybersecurity, a “Kill Chain” is used to describe the methodology/path attackers such as hackers or APTs use to approach and intrude a target.

For example, an attacker scanning, exploiting a web vulnerability, and escalating privileges will be a “Kill Chain”. We will come to explain these stages in much further detail later in this room.

The objective is to understand an attacker’s “Kill Chain” so that defensive measures can be put in place to either pre-emptively protect a system or disrupt an attacker’s attempt.

### Answer the questions below

**Where does the term “Kill Chain” originate from?**

For this answer, you must fill in the blank!: The ********

Since the answers can be found above, I won’t be posting it. You can follow along to learn and discover where they are located.

The answer can be found in the first sentence of this task. Once you find it, highlight & copy (ctrl +c ) or type the answer into the TryHackMe answer field, then click submit.

![](_resources/04%20Unified%20Kill%20Chain/940db054fd82afcb0963523338a448f7_MD5.jpg)

# Task 3 What is “Threat Modelling”

Threat modelling, in a cybersecurity context, is a series of steps to ultimately improve the security of a system.

Threat modelling is about identifying risk and essentially boils down to:

1. Identifying what systems and applications need to be secured and what function they serve in the environment. For example, is the system critical to normal operations, and is a system holding sensitive information like payment info or addresses?
2. Assessing what vulnerabilities and weaknesses these systems and applications may have and how they could be potentially exploited
3. Creating a plan of action to secure these systems and applications from the vulnerabilities highlighted
4. Putting in policies to prevent these vulnerabilities from occurring again where possible (for example, implementing a software development life cycle (SDLC) for an application or training employees on phishing awareness).

![](_resources/04%20Unified%20Kill%20Chain/05563af6ee61cb8d0599c99f20d2f464_MD5.jpg)

Threat modelling is an important procedure in reducing the risk within a system or application, as it creates a high-level overview of an organisation’s IT assets (an asset in IT is a piece of software or hardware) and the procedures to resolve vulnerabilities.

The UKC can encourage threat modelling as the UKC framework helps identify potential attack surfaces and how these systems may be exploited.

STRIDE, DREAD and CVSS (to name a few) are all frameworks specifically used in threat modelling. If you are interested to learn more, check out the “[Principles of Security](https://tryhackme.com/room/principlesofsecurity)” room on TryHackMe.

### Answer the questions below

**What is the technical term for a piece of software or hardware in IT (Information Technology?)**

Since the answers can be found above, I won’t be posting it. You can follow along to learn and discover where they are located.

The answer can be found at the end of the sentence after the boiled down section. Once you find it, highlight & copy (ctrl +c ) or type the answer into the TryHackMe answer field, then click submit.

![](_resources/04%20Unified%20Kill%20Chain/be58f921c795c2dedb6d0c3781d5eec5_MD5.jpg)

# Task 4 Introducing the Unified Kill Chain

![](_resources/04%20Unified%20Kill%20Chain/53d3ff2ddadacbbdcb6fb744a8f94d78_MD5.jpg)

To continue from the previous task, the [Unified Kill Chain](https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf) published in 2017, aims to complement (**not compete**) with other cybersecurity kill chain frameworks such as Lockheed Martin’s and MITRE’s ATT&CK.

The UKC states that there are 18 phases to an attack: Everything from reconnaissance to data exfiltration and understanding an attacker’s motive. These phases have been grouped together in this room into a few areas of focus for brevity, which will be detailed in the remaining tasks.

Some large benefits of the UKC over traditional cybersecurity kill chain frameworks include the fact that it is modern and extremely detailed (**reminder**: it has 18 phases officially, whereas other frameworks may have a small handful)

![](_resources/04%20Unified%20Kill%20Chain/f98bf3e2b2ae14607b09811cb72083a9_MD5.jpg)

**Benefits of the Unified Kill Chain (UKC) FrameworkHow do Other Frameworks Compare?**Modern (released in 2017, updated in 2022).

Some frameworks, such as MITRE’s were released in 2013, when the cybersecurity landscape was very different.

The UKC is extremely detailed (18 phases).

Other frameworks often have a small handful of phases.

The UKC covers an entire attack — from reconnaissance, exploitation, post-exploitation and includes identifying an attacker’s motivation.

Other frameworks cover a limited amount of phases.

The UKC highlights a much more realistic attack scenario. Various stages will often re-occur. For example, after exploiting a machine, an attacker will begin reconnaissance to pivot another system.

Other frameworks do not account for the fact that an attacker will go back and forth between the various phases during an attack.

### Answer the questions below

Since the answers can be found above, I won’t be posting it. You can follow along to learn and discover where they are located.

**In what year was the Unified Kill Chain framework released?**

The answer can be found in the first sentence of this task. Once you find it, highlight & copy (ctrl +c ) or type the answer into the TryHackMe answer field, then click submit.

![](_resources/04%20Unified%20Kill%20Chain/296d253081cb60ebc10c47e01d1df7fa_MD5.jpg)

**According to the Unified Kill Chain, how many phases are there to an attack?**

Count the number of “links” to the Unified kill chain, or see what at the bottom of the chart and see what the number is. Once you find it, highlight & copy (ctrl +c ) or type the answer into the TryHackMe answer field, then click submit.

![](_resources/04%20Unified%20Kill%20Chain/93dd3db5c80064bdad22e2b254e7bcc0_MD5.jpg)

**What is the name of the attack phase where an attacker employs techniques to evade detection?**

Going back up to the chart, the answer can be found at number 7. Once you find it, highlight & copy (ctrl +c ) or type the answer into the TryHackMe answer field, then click submit.

![](_resources/04%20Unified%20Kill%20Chain/e0952ef5b345220b6aa30876077a55c4_MD5.jpg)

**What is the name of the attack phase where an attacker employs techniques to remove data from a network?**

Going back up to the chart, the answer can be found at number 16. Once you find it, highlight & copy (ctrl +c ) or type the answer into the TryHackMe answer field, then click submit.

![](_resources/04%20Unified%20Kill%20Chain/4793fb6482b832d1de38cc3aa0345f0b_MD5.jpg)

**What is the name of the attack phase where an attacker achieves their objectives?**

Going back up to the chart, the answer can be found at number 18. Once you find it, highlight & copy (ctrl +c ) or type the answer into the TryHackMe answer field, then click submit.

![](_resources/04%20Unified%20Kill%20Chain/eedbb96307488f7d1795386183749aea_MD5.jpg)

# Task 5 Phase: In (Initial Foothold)

![](_resources/04%20Unified%20Kill%20Chain/14f644ed306cc3ae9134c6c3029b036e_MD5.jpg)

The main focus of this series of phases is for an attacker to gain access to a system or networked environment.

An attacker will employ numerous tactics to investigate the system for potential vulnerabilities that can be exploited to gain a foothold in the system. For example, a common tactic is the use of reconnaissance against a system to discover potential attack vectors (such as applications and services).

![](_resources/04%20Unified%20Kill%20Chain/3e22deb8b886a7b265de80fe10d81718_MD5.jpg)

This series of phases also accommodates for an attacker creating a form of persistence (such as files or a process that allows the attacker to connect to the machine at any time). Finally, the UKC accounts for the fact that attackers will often use a combination of the tactics listed above.

We will explore the different phases of this section of the UKC in the headings below:

## Reconnaissance ([MITRE Tactic TA0043](https://attack.mitre.org/tactics/TA0001/))

This phase of the UKC describes techniques that an adversary employs to gather information relating to their target. This can be achieved through means of passive and active reconnaissance. The information gathered during this phase is used all throughout the later stages of the UKC (such as the initial foothold).

Information gathered from this phase can include:

- Discovering what systems and services are running on the target, this is beneficial information in the weaponisation and exploitation phases of this section.
- Finding contact lists or lists of employees that can be impersonated or used in either a social-engineering or phishing attack.
- Looking for potential credentials that may be of use in later stages, such as pivoting or initial access.
- Understanding the network topology and other networked systems can be used to pivot too.

## Weaponization ([MITRE Tactic TA0001](https://attack.mitre.org/tactics/TA0001/))

This phase of the UKC describes the adversary setting up the necessary infrastructure to perform the attack. For example, this could be setting up a command and control server, or a system capable of catching reverse shells and delivering payloads to the system.

## Social Engineering ([MITRE Tactic TA0001](https://attack.mitre.org/tactics/TA0001/))

This phase of the UKC describes techniques that an adversary can employ to manipulate employees to perform actions that will aid in the adversaries attack. For example, a social engineering attack could include:

- Getting a user to open a malicious attachment.
- Impersonating a web page and having the user enter their credentials.
- Calling or visiting the target and impersonating a user (for example, requesting a password reset) or being able to gain access to areas of a site that the attacker would not previously be capable of (for example, impersonating a utility engineer).

## Exploitation ([MITRE Tactic TA0002](https://attack.mitre.org/tactics/TA0002/))

This phase of the UKC describes how an attacker takes advantage of weaknesses or vulnerabilities present in a system. The UKC defines “Exploitation” as abuse of vulnerabilities to perform code execution. For example:

- Uploading and executing a reverse shell to a web application.
- Interfering with an automated script on the system to execute code.
- Abusing a web application vulnerability to execute code on the system it is running on.

## Persistence ([MITRE Tactic TA0003](https://attack.mitre.org/tactics/TA0002/))

This phase of the UKC is rather short and simple. Specifically, this phase of the UKC describes the techniques an adversary uses to maintain access to a system they have gained an initial foothold on. For example:

- Creating a service on the target system that will allow the attacker to regain access.
- Adding the target system to a Command & Control server where commands can be executed remotely at any time.
- Leaving other forms of backdoors that execute when a certain action occurs on the system (i.e. a reverse shell will execute when a system administrator logs in).

## Defence Evasion ([MITRE Tactic TA0005](https://attack.mitre.org/tactics/TA0005/))

The “Defence Evasion” section of the UKC is one of the more valuable phases of the UKC. This phase specifically is used to understand the techniques an adversary uses to evade defensive measures put in place in the system or network. For example, this could be:

- Web application firewalls.
- Network firewalls.
- Anti-virus systems on the target machine.
- Intrusion detection systems.

This phase is valuable when analysing an attack as it helps form a response and better yet — gives the defensive team information on how they can improve their defence systems in the future.

## Command & Control ([MITRE Tactic TA0011](https://attack.mitre.org/tactics/TA0011/))

The “Command & Control” phase of the UKC combines the efforts an adversary made during the “Weaponization” stage of the UKC to establish communications between the adversary and target system.

An adversary can establish command and control of a target system to achieve its action on objectives. For example, the adversary can:

- Execute commands.
- Steal data, credentials and other information.
- Use the controlled server to pivot to other systems on the network.

## Pivoting ([MITRE Tactic TA0008](https://attack.mitre.org/tactics/TA0008/))

“Pivoting” is the technique an adversary uses to reach other systems within a network that are not otherwise accessible (for example, they are not exposed to the internet). There are often many systems in a network that are not directly reachable and often contain valuable data or have weaker security.

For example, an adversary can gain access to a web server that is publically accessible to attack other systems that are within the same network (but are not accessible via the internet).

### Answer the questions below

**What is an example of a tactic to gain a foothold using emails?**

Above under the Social Engineering section you will find; Getting a user to open a malicious attachment. This is the hint of about the tatic being used in email. Click the blue link next to Social Engineering labeled, MITRE Tactic TA0001.

![](_resources/04%20Unified%20Kill%20Chain/06c38eae58fb5d152c18f5e12918ae79_MD5.jpg)

The MITRE ATT&CK page will load, you will see the Techniques table below the scroll down till reach T1566.

![](_resources/04%20Unified%20Kill%20Chain/3334d4c2b70266e5a3e02032253c05dc_MD5.jpg)

Once you reach this technique you will have your answer. Once you find it, highlight & copy (ctrl +c ) or type the answer into the TryHackMe answer field, then click submit.

![](_resources/04%20Unified%20Kill%20Chain/1d6daf09a3758091571ed7422eca4a11_MD5.jpg)

Answer: Phishing

**Impersonating an employee to request a password reset is a form of what?**

Since the answer can be found above, I won’t be posting it. You can follow along to learn and discover where they are located.

Scroll up till you find the section about manipulating employees, the name of this section is the answer to this question. Once you find it, highlight & copy (ctrl +c ) or type the answer into the TryHackMe answer field, then click submit.

![](_resources/04%20Unified%20Kill%20Chain/d8992182cd2bf313df9528029ee12a7b_MD5.jpg)

**An adversary setting up the Command & Control server infrastructure is what phase of the Unified Kill Chain?**

Since the answer can be found above, I won’t be posting it. You can follow along to learn and discover where they are located.

Scroll up to the Command & Control Section, in the first sentence you will find the answer. Once you find it, highlight & copy (ctrl +c ) or type the answer into the TryHackMe answer field, then click submit.

![](_resources/04%20Unified%20Kill%20Chain/95becc90d3eefdce05d1bf9ad51a1a42_MD5.jpg)

**Exploiting a vulnerability present on a system is what phase of the Unified Kill Chain?**

Since the answer can be found above, I won’t be posting it. You can follow along to learn and discover where they are located.

Scroll up to the Section with MITRE Tactic TA0002, in the first sentence you will find the answer, the highlighted part describes what the question is asking. Once you find it, highlight & copy (ctrl +c ) or type the answer into the TryHackMe answer field, then click submit.

![](_resources/04%20Unified%20Kill%20Chain/2992c86ef2a481898a7c8afd443c3ce3_MD5.jpg)

**Moving from one system to another is an example of?**

Since the answer can be found above, I won’t be posting it. You can follow along to learn and discover where they are located.

Scroll up to the Section with MITRE Tactic TA0008, in the first sentence you will find the answer, the highlighted part describes what the question is asking. Once you find it, highlight & copy (ctrl +c ) or type the answer into the TryHackMe answer field, then click submit.

![](_resources/04%20Unified%20Kill%20Chain/2d48d275db53c6b8b20d73f5aa4c2526_MD5.jpg)

**Leaving behind a malicious service that allows the adversary to log back into the target is what?**

Since the answer can be found above, I won’t be posting it. You can follow along to learn and discover where they are located.

Scroll up to the Section with MITRE Tactic TA0003, the last bullet point is where you can find the answer, the highlighted part describes what the question is asking. Once you find it, highlight & copy (ctrl +c ) or type the answer into the TryHackMe answer field, then click submit.

![](_resources/04%20Unified%20Kill%20Chain/3e2aa66e4dfdcbfd56c528a42f47834c_MD5.jpg)

# Task 6 Phase: Through (Network Propagation)

![](_resources/04%20Unified%20Kill%20Chain/03fffa040a8442d4ac63a1c72d65b16f_MD5.jpg)

This phase follows a successful foothold being established on the target network. An attacker would seek to gain additional access and privileges to systems and data to fulfil their goals. The attacker would set up a base on one of the systems to act as their pivot point and use it to gather information about the internal network.

![](_resources/04%20Unified%20Kill%20Chain/6bcf4639d8a57d625decc085091a7418_MD5.jpg)

## Pivoting ([MITRE Tactic TA0008](https://attack.mitre.org/tactics/TA0008/))

Once the attacker has access to the system, they would use it as their staging site and a tunnel between their command operations and the victim’s network. The system would also be used as the distribution point for all malware and backdoors at later stages.

## Discovery ([MITRE Tactic TA0007](https://attack.mitre.org/tactics/TA0007/))

The adversary would uncover information about the system and the network it is connected to. Within this stage, the knowledge base would be built from the active user accounts, the permissions granted, applications and software in use, web browser activity, files, directories and network shares, and system configurations.

## Privilege Escalation ([MITRE Tactic TA0004](https://attack.mitre.org/tactics/TA0004/))

Following their knowledge-gathering, the adversary would try to gain more prominent permissions within the pivot system. They would leverage the information on the accounts present with vulnerabilities and misconfigurations found to elevate their access to one of the following superior levels:

- SYSTEM/ ROOT.
- Local Administrator.
- A user account with Admin-like access.
- A user account with specific access or functions.

## Execution ([MITRE Tactic TA0002](https://attack.mitre.org/tactics/TA0002/))

Recall when the adversary set up their attack infrastructure. Once the attacker has access to the system, they would use it as their staging site and a tunnel between their command operations and the victim’s network. The system would also be used as the distribution point for all malware and backdoors at later stages. and weaponised payloads? This is where they deploy their malicious code using the pivot system as their host. Remote trojans, C2 scripts, malicious links and scheduled tasks are deployed and created to facilitate a recurring presence on the system and uphold their persistence.

## Credential Access ([MITRE Tactic TA0006](https://attack.mitre.org/tactics/TA0006/))

Working hand in hand with the Privilege Escalation stage, the adversary would attempt to steal account names and passwords through various methods, including keylogging and credential dumping. This makes them harder to detect during their attack as they would be using legitimate credentials.

## Lateral Movement ([MITRE Tactic TA0008](https://attack.mitre.org/tactics/TA0008/))

With the credentials and elevated privileges, the adversary would seek to move through the network and jump onto other targeted systems to achieve their primary objective. The stealthier the technique used, the better.

### Answer the questions below

**As a SOC analyst, you pick up numerous alerts pointing to failed login attempts from an administrator account. What stage of the kill chain would an attacker be seeking to achieve?**

Since the answer can be found above, I won’t be posting it. You can follow along to learn and discover where they are located.

From the question, I am assuming that they already had access to the system, and were trying to gain higher privledged access. Scroll up to the Section with MITRE Tactic TA0004, in the first sentence you will find the highlighted part that describes what the question is asking. Once you find it, highlight & copy (ctrl +c ) or type the answer into the TryHackMe answer field, then click submit.

![](_resources/04%20Unified%20Kill%20Chain/de09ee6b6796b27357c86c1e104122d2_MD5.jpg)

**Mimikatz, a known attack tool, was detected running on the IT Manager’s computer. What is the mission of the tool?**

So let’s first go find out what Mimikatz is, go up to one of the links to a MITRE Tactic and click on it to open a new tab.

![](_resources/04%20Unified%20Kill%20Chain/527a5fda5e324e48d667da19ffacf36e_MD5.jpg)

Once the MITRE ATT&CK page loads, click the Software link along the top.

![](_resources/04%20Unified%20Kill%20Chain/20258e16f4a6a29f4aa243f00f559550_MD5.jpg)

On the next page that loads, you will see on the left side of the screen a list of software, scroll down till you reach Mimikatz and click on it.

![](_resources/04%20Unified%20Kill%20Chain/9643c8583d8061bc9890787ce4cd45ba_MD5.jpg)

On the right side of the webpage you will see a description of Mimikatz, this is what we were looking for. Now lets head back to the TryHackMe task to find what term we are looking for.

![](_resources/04%20Unified%20Kill%20Chain/baea574b44ed4b2b2503e798042cdffe_MD5.jpg)

Looking through the different Tactics we see the answer can be found in the Credential Access Section, the answer is at the end of the first sentence. Once you find it, highlight & copy (ctrl +c ) or type the answer into the TryHackMe answer field, then click submit.

![](_resources/04%20Unified%20Kill%20Chain/9f8738d43bd6acd7f54daa6431ebc2be_MD5.jpg)

# Task 7 Phase: Out (Action on Objectives)

![](_resources/04%20Unified%20Kill%20Chain/9526a5d0865098084dc9565fe8b3ebbb_MD5.jpg)

This phase wraps up the journey of an adversary’s attack on an environment, where they have critical asset access and can fulfil their attack goals. These goals are usually geared toward compromising the confidentiality, integrity and availability (CIA) triad.

![](_resources/04%20Unified%20Kill%20Chain/944b83c0871393747c65abdfe094ea5d_MD5.jpg)

The tactics to be deployed by an attacker would include:

## Collection [MITRE Tactic (TA0009)](https://attack.mitre.org/tactics/TA0009/%3E%3Cp%20style=)

After all the hunting for access and assets, the adversary will be seeking to gather all the valuable data of interest. This, in turn, compromises the confidentiality of the data and would lead to the next attack stage — Exfiltration. The main target sources include drives, browsers, audio, video and email.

## Exfiltration ([MITRE Tactic TA0010](https://attack.mitre.org/tactics/TA0010/))

To elevate their compromise, the adversary would seek to steal data, which would be packaged using encryption measures and compression to avoid any detection. The C2 channel and tunnel deployed in the earlier phases will come in handy during this process.

## Impact ([MITRE Tactic TA0040](https://attack.mitre.org/tactics/TA0040/))

If the adversary seeks to compromise the integrity and availability of the data assets, they would manipulate, interrupt or destroy these assets. The goal would be to disrupt business and operational processes and may involve removing account access, disk wipes, and data encryption such as ransomware, defacement and denial of service (DoS) attacks.

## Objectives

With all the power and access to the systems and network, the adversary would seek to achieve their strategic goal for the attack.

For example, if the attack was financially motivated, they may seek to encrypt files and systems with ransomware and ask for payment to release the data. In other instances, the attacker may seek to damage the reputation of the business, and they would release private and confidential information to the public.

### Answer the questions below

**While monitoring the network as a SOC analyst, you realise that there is a spike in the network activity, and all the traffic is outbound to an unknown IP address. What stage could describe this activity?**

Since the answer can be found above, I won’t be posting it. You can follow along to learn and discover where they are located.

Scroll up till you see MIRTE Tactic TA0010, the last sentence in this section gives away what the attacker is using to get the data. Once you find it, highlight & copy (ctrl +c ) or type the answer into the TryHackMe answer field, then click submit.

![](_resources/04%20Unified%20Kill%20Chain/87a0e822cfb71a7dc67f2e261aa5e881_MD5.jpg)

**Personally identifiable information (PII) has been released to the public by an adversary, and your organisation is facing scrutiny for the breach. What part of the CIA triad would be affected by this action?**

Let’s start by Googling the CIA triad, to find out exactly what it is and where the PII would fall into it. So head to Google, in the search bar in the middle of the screen type CIA triad, and press enter to search.

![](_resources/04%20Unified%20Kill%20Chain/4ce9563a1a70f89e0605844838fefb4e_MD5.jpg)

Once the search loads, on the right side I had a sample load from TechTarget explaining what the CIA triad is, at least a little bit. But it at least gives up the Pillars, which is all we really need.

![](_resources/04%20Unified%20Kill%20Chain/38210c4369d9f15d857c91d7219ebd8d_MD5.jpg)

So let me define what each Pillar is then we can answer the question.

- Confidentiality- The ability to keep data secret.
- Integrity- The ability to keep data from being tampered with.
- Availability- The ability to readily access to the data.

Knowing that it was Personal Identifable information (PII) that was released to the public, only one of the pillars of the CIA traid seems to be the answer.

Answer: Confidentiality

# Task 8 Practical

![](_resources/04%20Unified%20Kill%20Chain/58e1bbdf470f1c173e82edaca5d0889c_MD5.jpg)

**Deploy** the static site attached to the task. You will need to match the various actions of an attacker to the correct phase of the Unified Kill Chain framework to reveal the flag.

### Answer the questions below

**Match the scenario prompt to the correct phase of the Unified Kill Chain to reveal the flag at the end. What is the flag?**

To start off you need to click the green View Site button at the top of the Task.

![](_resources/04%20Unified%20Kill%20Chain/b54866a467954f37761f435b049c684b_MD5.jpg)

The screen will split in half and on the right side will be the practical.

![](_resources/04%20Unified%20Kill%20Chain/c91037d00584e9fda7b17416edd74271_MD5.jpg)

The first practical question is; The Attacker uses tools to gather information about a system. What phase of the Unified Kill Chain is this? If you go back to Task 4 you can see the whole Unified Kill Chain, look at all three of these links to see which is the info gathering phase.

![](_resources/04%20Unified%20Kill%20Chain/ba78ded44c3befbe35fdc9ff1fad0c59_MD5.jpg)

Once you figure out the phase, click button to go to the next question.

![](_resources/04%20Unified%20Kill%20Chain/4512fb0ab5526c2ddb1415be7283eb79_MD5.jpg)

The next question is; The Attacker installs a malicious script to allow them remote access at a later date. What phase of the Unified Kill Chain is this?

![](_resources/04%20Unified%20Kill%20Chain/5684be44ee8b7e57f0027745c719de1d_MD5.jpg)

If you go back to Task 4 you can see the whole Unified Kill Chain, look at all three of these links to see which is the remote access at a later date phase.

![](_resources/04%20Unified%20Kill%20Chain/f49915fe3c3e85616270e77b5e238dfe_MD5.jpg)

Once you figure out the phase, click button to go to the next question.

![](_resources/04%20Unified%20Kill%20Chain/7600a56116245a56d6dd6295e239b496_MD5.jpg)

The next question is; The hacked machine is being controlled from an Attacker’s own server. What phase of the Unified Kill Chain is this?

![](_resources/04%20Unified%20Kill%20Chain/4f7f05b43d306aa43dd8277be8fa20fe_MD5.jpg)

If you go back to Task 4 you can see the whole Unified Kill Chain, look at all three of these links to see which is the controlling a victims machine from an Attacker’s own server.

![](_resources/04%20Unified%20Kill%20Chain/3830253db51feae3968001c182bdc724_MD5.jpg)

Once you figure out the phase, click button to go to the next question.

![](_resources/04%20Unified%20Kill%20Chain/835c9c74520548a95e833f084e191d38_MD5.jpg)

The next question is; The Attacker uses the hacked machine to access other servers on the same network. What phase of the Unified Kill Chain is this?

![](_resources/04%20Unified%20Kill%20Chain/2bf9a7b0e0a6615e41a06d1ee5b159a3_MD5.jpg)

If you go back to Task 4 you can see the whole Unified Kill Chain, look at all three of these links to see which is the controlling a victims machine from an Attacker’s own server.

![](_resources/04%20Unified%20Kill%20Chain/ccba006440fc5b5e45d42f278a63ca34_MD5.jpg)

Once you figure out the phase, click button to go to the next question.

![](_resources/04%20Unified%20Kill%20Chain/6dcc8a621915bb9b55ffc5e326012adc_MD5.jpg)

The next question is; The Attacker steals a database and sells this to a 3rd party. What phase of the Unified Kill Chain is this?

![](_resources/04%20Unified%20Kill%20Chain/aa31ccefa0f868cd73d5893174713f4d_MD5.jpg)

If you go back to Task 4 you can see the whole Unified Kill Chain, look at all three of these links to see which is the Attackers intended purpose.

![](_resources/04%20Unified%20Kill%20Chain/1b0db2ccf964813f078e897f78dc0ce3_MD5.jpg)

Once you figure out the phase, click the button.

![](_resources/04%20Unified%20Kill%20Chain/851ed01e400b70e40d0eaaeed98d27df_MD5.jpg)

This time at the bottom will reveal the flag. Highlight & copy (ctrl +c ) or type the answer into the TryHackMe answer field, then click submit.

![](_resources/04%20Unified%20Kill%20Chain/82e02173ab1c464cddfd7fbf7018688e_MD5.jpg)

Answer: THM{UKC_SCENARIO}

# Task 9 Conclusion

![](_resources/04%20Unified%20Kill%20Chain/000378022cbd21690a1c8937c6093d6f_MD5.jpg)

Congrats on making it through the Unified Kill Chain room. Hopefully, you understand the importance that frameworks such as the UKC play in identifying risk and potential mitigating attacks by reconstructing the various steps an attacker took.

As mentioned in this room, the UKC is a modern extension of other frameworks, such as Lockheed Martin’s “Cyber Kill Chain” framework. If you are interested in learning more about frameworks in cybersecurity (highly recommended!), you should check out these rooms on TryHackMe:

- [Principles of Security](https://tryhackme.com/room/principlesofsecurity)
- [Pentesting Fundamentals](https://tryhackme.com/room/pentestingfundamentals)
- [Cyber Kill Chain](https://tryhackme.com/room/cyberkillchainzmt)

🎉🎉Congrats!!! You completed the Unified Kill Chain Room!!!🎉🎉