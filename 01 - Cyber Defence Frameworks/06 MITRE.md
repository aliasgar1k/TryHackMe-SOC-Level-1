https://www.youtube.com/watch?v=9lgoY0b8sx0&list=PLKJGe-yb9iQb_RY1-IRCMFUmMGU_xlNsp&index=5
https://medium.com/@AbhijeetSingh4/mitre-soc-lavel-1-tryhackme-walkthrough-46a8c69bf989
https://medium.com/@haircutfish
https://medium.com/@valerie7995/mitre-tryhackme-b1c229e4346a

# Task 1 Introduction to MITRE

For those that are new to the cybersecurity field, you probably never heard of MITRE. Those of us that have been around might only associate MITRE with CVEs **([Common Vulnerabilities and Exposures](https://cve.mitre.org/))** list, which is one resource you’ll probably check when searching for an exploit for a given vulnerability. But MITRE researches in many areas, outside of cybersecurity, for the ‘safety, stability, and well-being of our nation.’ These areas include artificial intelligence, health informatics, space security, to name a few.

From **[Mitre.org](https://www.mitre.org/about/corporate-overview)**: “At MITRE, we solve problems for a safer world. Through our federally funded R&D centers and public-private partnerships, we work across government to tackle challenges to the safety, stability, and well-being of our nation.”

In this room, we will focus on other projects/research that the US-based non-profit MITRE Corporation has created for the cybersecurity community, specifically:

- ATT&CK® (**A**dversarial **T**actics, **T**echniques, **and C**ommon **K**nowledge) Framework
- CAR (**C**yber **A**nalytics **R**epository) Knowledge Base
- ENGAGE (sorry, not a fancy acronym)
- D3FEND (**D**etection, **D**enial, and **D**isruption **F**ramework **E**mpowering **N**etwork **D**efense)
- AEP (**A**TT&CK **E**mulation **P**lans)

Let’s dive in, shall we…

Room updated: July 1st, 2022

Read the above. >> No Answer Needed <<

# Task 2 Basic Terminology

Before diving in, let’s briefly discuss a few terms that you will often hear when dealing with the framework, threat intelligence, etc.

**APT** is an acronym for **Advanced Persistent Threat**. This can be considered a team/group (**threat group**), or even country (**nation-state group**), that engages in long-term attacks against organizations and/or countries. The term ‘advanced’ can be misleading as it will tend to cause us to believe that each APT group all have some super-weapon, e.i. a zero-day exploit, that they use. That is not the case. As we will see a bit later, the techniques these APT groups use are quite common and can be detected with the right implementations in place. You can view FireEye’s current list of APT groups **[here](https://www.fireeye.com/current-threats/apt-groups.html).**

**TTP** is an acronym for **Tactics**, **Techniques**, and **Procedures**, but what does each of these terms mean?

- The **Tactic** is the adversary’s goal or objective.
- The **Technique** is how the adversary achieves the goal or objective.
- The **Procedure** is how the technique is executed.

If that is not that clear now, don’t worry. Hopefully, as you progress through each section, TTPs will make more sense.

Read the above. >> No Answer Needed <<

# Task 3 ATT&CK® Framework

![](_resources/06%20MITRE/7f8c6505857ad91e9b0ff1f1a655f4da_MD5.webp)

What is the ATT&CK® framework? According to the **[website](https://attack.mitre.org/)**, “MITRE ATT&CK® is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.” In 2013, MITRE began to address the need to record and document common TTPs (**Tactics, Techniques, and Procedures**) that APT (**Advanced Persistent Threat**) groups used against enterprise Windows networks. This started with an internal project known as FMX (**Fort Meade Experiment**). Within this project, selected security professionals were tasked to emulated adversarial TTPs against a network, and data was collected from the attacks on this network. The gathered data helped construct the beginning pieces of what we know today as the ATT&CK® framework.

The ATT&CK® framework has grown and expanded throughout the years. One notable expansion was that the framework focused solely on the Windows platform but has expanded to cover other platforms, such as macOS and Linux. The framework is heavily contributed to by many sources, such as security researchers and threat intelligence reports. Note this is not only a tool for blue teamers. The tool is also useful for **red teamers**.

If you haven’t done so, navigate to the ATT&CK® [website](https://attack.mitre.org/).

Direct your attention to the bottom of the page to view the **ATT&CK® Matrix for Enterprise**. Across the top of the matrix, there are 14 categories. Each category contains the techniques an adversary could use to perform the tactic. The categories cover the seven-stage Cyber Attack Lifecycle (credit Lockheed Martin for the Cyber Kill Chain).

![](_resources/06%20MITRE/6e86d590b8ae3294f8cca505630e3ea0_MD5.jpg)

(ATT&CK Matrix v11.2)

Under **Initial Access**, there are 9 techniques. Some of the techniques have sub-techniques, such as Phishing.

![](_resources/06%20MITRE/61816bab22d308f95ac7c85b1c1cfd9e_MD5.jpg)

If we click on the gray bar to the right, a new layer appears listing the sub-techniques.

![](_resources/06%20MITRE/7fd1578eb4aaa41d3dc81242f0c9b516_MD5.jpg)

To get a better understanding of this technique and it’s associated sub-techniques, click on Phishing.

We have been directed to a page dedicated to the technique known as Phishing and all related information regarding the technique, such as a brief description, **Procedure Examples**, and **Mitigations**.

![](_resources/06%20MITRE/e381484fb4d51a9a0995c6f2fd1403b8_MD5.jpg)

You can alternatively resort to using the Search feature to retrieve all associated information regarding a given technique, sub-technique, and/or group.

![](_resources/06%20MITRE/76f8f9dd6eacaa054b76dd5b4d9d09ae_MD5.jpg)

Lastly, the same data can be viewed via the **MITRE ATT&CK® Navigator**: “The ATT&CK® Navigator is designed to provide basic navigation and annotation of ATT&CK® matrices, something that people are already doing today in tools like Excel. We’ve designed it to be simple and generic — you can use the Navigator to visualize your defensive coverage, your red/blue team planning, the frequency of detected techniques, or anything else you want to do.”

You can access the Navigator view when visiting a group or tool page. The ATT&CK® Navigator Layers button will be available.

![](_resources/06%20MITRE/eedae56b9e25f19954341b5eb284aee0_MD5.jpg)

In the sub-menu select **view**.

![](_resources/06%20MITRE/90d42b5015359a534ca0a23415832d97_MD5.jpg)

Let’s get acquainted with this tool. Click **[here](https://mitre-attack.github.io/attack-navigator/#layerURL=https%3A%2F%2Fattack.mitre.org%2Fgroups%2FG0008%2FG0008-enterprise-layer.json)** to view the ATT&CK® Navigator for Carbanak.

At the top left, there are 3 sets of controls: **selection controls**, **layer controls**, and **technique controls**. I encourage you to inspect each of the options under each control to get familiar with them. The question mark at the far right will provide additional information regarding the navigator.

![](_resources/06%20MITRE/ad3d3ba5977d3ea3d271512ee6ed83f0_MD5.jpg)

To summarize, we can use the ATT&CK Matrix to map a threat group to their tactics and techniques. There are various methods the search can be initiated.

The questions below will help you become more familiar with the ATT&CK®. It is recommended to start answering the questions from the **[Phishing page](https://attack.mitre.org/techniques/T1566/)**. Note, that this link is for version 8 of the ATT&CK Matrix.

### Answer the questions below

![](_resources/06%20MITRE/cf5a0bca0bef5d6cd6f0fd77ee055b82_MD5.jpg)

# Task 4 CAR Knowledge Base

**[Cyber Analytics Repository](https://car.mitre.org/)**

The official definition of **CAR** is “The MITRE Cyber Analytics Repository (CAR) is a knowledge base of analytics developed by MITRE based on the MITRE ATT&CK® adversary model. CAR defines a data model that is leveraged in its pseudocode representations but also includes implementations directly targeted at specific tools (e.g., Splunk, EQL) in its analytics. With respect to coverage, CAR is focused on providing a set of validated and well-explained analytics, in particular with regards to their operating theory and rationale.”

Instead of further attempting to explain what CAR is, let’s dive in. With our newly acquired knowledge from the previous section, we should feel comfortable and understand the information that CAR is providing to us.

Let’s begin our journey by reviewing **[CAR-2020–09–001: Scheduled Task — File Access](https://car.mitre.org/analytics/CAR-2020-09-001/).**

Upon visiting the page, we’re given a brief description of the analytics and references to ATT&CK (**technique**, **sub-technique**, and **tactic**).

![](_resources/06%20MITRE/4ca5187eeed282f66243659fc4d82a4f_MD5.jpg)

![](_resources/06%20MITRE/becb47fed37daa93a24c0027545d5590_MD5.jpg)

We’re also provided with Pseudocode and a query on how to search for this specific analytic within Splunk. A pseudocode is a plain, human-readable way to describe a set of instructions or algorithms that a program or system will perform.

![](_resources/06%20MITRE/10ea2d5bf306576678e5722260462779_MD5.jpg)

Note the reference to Sysmon. If you’re not familiar with Sysmon, check out the Sysmon [room](https://tryhackme.com/room/sysmon).

To take full advantage of CAR, we can view the **[Full Analytic List](https://car.mitre.org/analytics)** or the **[CAR ATT&CK® Navigator layer](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/mitre-attack/car/master/docs/coverage/car_analytic_coverage_04_05_2022.json)** to view all the analytics.

**Full Analytic List**

![](_resources/06%20MITRE/8ae51e6e899786d846bbb4a5454ef976_MD5.jpg)

In the Full Analytic List view, we can see what implementations are available for any given analytic at a single glance, along with what OS platform it applies to.

**CAR ATTACK Navigator**

![](_resources/06%20MITRE/826fa90a4fe07a7debc3eb3ec63199ed_MD5.jpg)

(The techniques highlighted in purple are the analytics currently in CAR)

Let’s look at another analytic to see a different implementation, **[CAR-2014–11–004: Remote PowerShell Sessions](https://car.mitre.org/analytics/CAR-2014-11-004/).**

Under Implementations, a pseudocode is provided and an EQL version of the pseudocode. EQL (pronounced as ‘equal’), and it’s an acronym for Event Query Language. EQL can be utilized to query, parse, and organize Sysmon event data. You can read more about this **[here](https://eql.readthedocs.io/en/latest/).**

![](_resources/06%20MITRE/c8546229c6734d887ffd6f383f06ebe7_MD5.jpg)

To summarize, CAR is a great place for finding analytics that takes us further than the Mitigation and Detection summaries in the ATT&CK® framework. This tool is not a replacement for ATT&CK® but an added resource.

### Answer the questions below

![](_resources/06%20MITRE/bc855eb2a4d464e11e5be8e677379a05_MD5.jpg)

# Task 5 MITRE Engage

**[MITRE ENGAGE](https://engage.mitre.org/)**

Per the website, “**MITRE Engage** is a framework for planning and discussing adversary engagement operations that empowers you to engage your adversaries and achieve your cybersecurity goals.”

MITRE Engage is considered an **Adversary Engagement Approach**. This is accomplished by the implementation of **Cyber Denial** and **Cyber Deception**.

With **Cyber Denial** we prevent the adversary’s ability to conduct their operations and with **Cyber Deception** we intentionally plant artifacts to mislead the adversary.

The Engage website provides a [starter kit](https://engage.mitre.org/starter-kit/) to get you ‘started’ with the Adversary Engagement Approach. The starter kit is a collection of whitepapers and PDFs explaining various checklists, methodologies, and processes to get you started.

As with MITRE ATT&CK, Engage has its own matrix. Below is a visual of the **Engage Matrix**.

![](_resources/06%20MITRE/60f1c93d2e20788e8fe20111d63a84ae_MD5.jpg)

(Source: [https://engage.mitre.org](https://engage.mitre.org/))

Let’s quickly explain each of these categories based on the information on the Engage website.

- **Prepare** the set of operational actions that will lead to your desired outcome (input)
- **Expose** adversaries when they trigger your deployed deception activities
- **Affect** adversaries by performing actions that will have a negative impact on their operations
- **Elicit** information by observing the adversary and learn more about their modus operandi (TTPs)
- **Understand** the outcomes of the operational actions (output)

Refer to the [Engage Handbook](https://engage.mitre.org/wp-content/uploads/2022/04/EngageHandbook-v1.0.pdf) to learn more.

You can interact with the [Engage Matrix Explorer](https://engage.mitre.org/matrix). We can filter by information from **[MITRE ATT&CK](https://attack.mitre.org/)**.

Note that by default the matrix focuses on **Operate**, which entails **Expose**, **Affect**, and **Elicit**.

![](_resources/06%20MITRE/7be28fc955379bf807f0f5e2c2c7fd6d_MD5.jpg)

You can click on **Prepare** or **Understand** if you wish to focus solely on that part of the matrix.

![](_resources/06%20MITRE/e9b04d2ab70123deb2fbd9ca1e8ec11e_MD5.jpg)

That should be enough of an overview. We’ll leave it to you to explore the resources provided to you on this website.

Before moving on, let’s practice using this resource by answering the questions below.

### Answer the questions below

![](_resources/06%20MITRE/8edd5c18580a7e6f67fcfb8651b5daea_MD5.jpg)

# Task 6 MITRE D3FEND

**[D3FEND](https://d3fend.mitre.org/)**

What is this MITRE resource? Per the **[D3FEND](https://d3fend.mitre.org/)** website, this resource is “A knowledge graph of cybersecurity countermeasures.”

D3FEND is still in beta and is funded by the Cybersecurity Directorate of the NSA.

**D3FEND** stands for **D**etection, **D**enial, and **D**isruption **F**ramework **E**mpowering **N**etwork **D**efense.

At the time of this writing, there are 408 artifacts in the D3FEND matrix. See the below image.

![](_resources/06%20MITRE/44ad6721e1e34555493fe27a13849f98_MD5.jpg)

Let’s take a quick look at one of the D3FENDs artifacts, such as Decoy File.

![](_resources/06%20MITRE/c4bd85ac1c5b77e626998a352b64d530_MD5.jpg)

As you can see, you’re provided with information on what is the technique (**definition**), how the technique works (**how it works**), things to think about when implementing the technique (**considerations**), and how to utilize the technique (**example**).

Note, as with other MITRE resources, you can filter based on the ATT&CK matrix.

Since this resource is in beta and will change significantly in future releases, we won’t spend that much time on D3FEND.

The objective of this task is to make you aware of this MITRE resource and hopefully you’ll keep an eye on it as it matures in the future.

We will still encourage you to navigate the website a bit by answering the questions below.

### Answer the questions below

![](_resources/06%20MITRE/d88819359cc401f95bcf591eefe12bda_MD5.jpg)

# Task 7 ATT&CK® Emulation Plans

If these tools provided to us by MITRE are not enough, under [MITRE ENGENUITY](https://mitre-engenuity.org/), we have **CTID**, the **Adversary Emulation Library**, and **ATT&CK® Emulation Plans**.

**CTID**

MITRE formed an organization named The **[Center of Threat-Informed Defense](https://mitre-engenuity.org/ctid/) (CTID)**. This organization consists of various companies and vendors from around the globe. Their objective is to conduct research on cyber threats and their TTPs and share this research to improve cyber defense for all.

Some of the companies and vendors who are participants of CTID:

- AttackIQ (founder)
- Verizon
- Microsoft (founder)
- Red Canary (founder)
- Splunk

Per the website, “Together with Participant organizations, we cultivate solutions for a safer world and advance threat-informed defense with open-source software, methodologies, and frameworks. By expanding upon the MITRE ATT&CK knowledge base, our work expands the global understanding of cyber adversaries and their tradecraft with the public release of data sets critical to better understanding adversarial behavior and their movements.”

**Adversary Emulation Library & ATT&CK® Emulations Plans**

The [Adversary Emulation Library](https://medium.com/mitre-engenuity/introducing-the-all-new-adversary-emulation-plan-library-234b1d543f6b) is a public library making adversary emulation plans a free resource for blue/red teamers. The library and the emulations are a contribution from CTID. There are several **[ATT&CK® Emulation Plans](https://github.com/center-for-threat-informed-defense/adversary_emulation_library)** currently available: **[APT3](https://attack.mitre.org/resources/adversary-emulation-plans/), [APT29](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/apt29),** and **[FIN6](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/fin6)**. The emulation plans are a step-by-step guide on how to mimic the specific threat group. If any of the C-Suite were to ask, “how would we fare if APT29 hits us?” This can easily be answered by referring to the results of the execution of the emulation plan.

Review the emulation plans to answer the questions below.

### Answer the questions below

![](_resources/06%20MITRE/3d21b7bb736cbfb18f0b4b9c8b9fbc38_MD5.jpg)

# Task 8 ATT&CK® and Threat Intelligence

**Threat Intelligence (TI)** or **Cyber Threat Intelligence (CTI)** is the information, or TTPs, attributed to the adversary. By using threat intelligence, as defenders, we can make better decisions regarding the defensive strategy. Large corporations might have an in-house team whose primary objective is to gather threat intelligence for other teams within the organization, aside from using threat intel already readily available. Some of this threat intel can be open source or through a subscription with a vendor, such as **[CrowdStrike](https://www.crowdstrike.com/)**. In contrast, many defenders wear multiple hats (roles) within some organizations, and they need to take time from their other tasks to focus on threat intelligence. To cater to the latter, we’ll work on a scenario of using ATT&CK® for threat intelligence. The goal of threat intelligence is to make the information actionable.

**Scenario:** You are a security analyst who works in the aviation sector. Your organization is moving their infrastructure to the cloud. Your goal is to use the ATT&CK® Matrix to gather threat intelligence on APT groups who might target this particular sector and use techniques targeting your areas of concern. You are checking to see if there are any gaps in coverage. After selecting a group, look over the selected group’s information and their tactics, techniques, etc.

### Answer the questions below

![](_resources/06%20MITRE/45466d4c602c3128613a5a38aafa0a8e_MD5.jpg)

# Task 9 Conclusion

In this room, we explored tools/resources that MITRE has provided to the security community. The room’s goal was to expose you to these resources and give you a foundational knowledge of their uses. Many vendors of security products and security teams across the globe consider these contributions from MITRE invaluable in the day-to-day efforts to thwart evil. The more information we have as defenders, the better we are equipped to fight back. Some of you might be looking to transition to become a SOC analyst, detection engineer, cyber threat analyst, etc. these tools/resources are a must to know.

As mentioned before, though, this is not only for defenders. As red teamers, these tools/resources are useful as well. Your objective is to mimic the adversary and attempt to bypass all the controls in place within the environment. With these resources, as the red teamer, you can effectively mimic a true adversary and communicate your findings in a common language that both sides can understand. In a nutshell, this is known as **purple teaming**.

Read the above. >> No Answer Needed <<