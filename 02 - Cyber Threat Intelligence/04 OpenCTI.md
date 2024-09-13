https://medium.com/@jcm3/yara-tryhackme-walkthrough-a1c56243fe8f
https://www.youtube.com/watch?v=uXpKr-ZGIp4 

# Task 1: Room Overview

This room will cover the concepts and usage of OpenCTI, an open-source threat intelligence platform. The room will help you understand and answer the following questions:

- What is OpenCTI and how is it used?
- How would I navigate through the platform?
- What functionalities will be important during a security threat analysis?

Prior to going through this room, we recommend checking out these rooms as prerequisites:

- [MITRE ATT&CK Framework](https://tryhackme.com/room/mitre)
- [TheHive](https://tryhackme.com/room/thehiveproject)
- [MISP](https://tryhackme.com/room/misp)
- [Threat Intelligence Tools](http://tryhackme.com/room/threatinteltools)

![](_resources/04%20OpenCTI/99c52eeed0c2771e96bebc283bb40806_MD5.jpg)

# Task 2: Introduction to OpenCTI

Cyber Threat Intelligence is typically a managerial mystery to handle, with organisations battling with how to input, digest, analyse and present threat data in a way that will make sense. From the rooms that have been linked on the overview, it is clear that there are numerous platforms that have been developed to tackle the juggernaut that is Threat Intelligence.

## OpenCTI

[OpenCTI](https://github.com/OpenCTI-Platform/opencti) is another open-sourced platform designed to provide organisations with the means to manage CTI through the storage, analysis, visualisation and presentation of threat campaigns, malware and IOCs.

## Objective

Developed by the collaboration of the [French National cybersecurity agency (ANSSI)](https://www.ssi.gouv.fr/), the platform’s main objective is to create a comprehensive tool that allows users to capitalise on technical and non-technical information while developing relationships between each piece of information and its primary source. The platform can use the [MITRE ATT&CK framework](https://tryhackme.com/room/mitre) to structure the data. Additionally, it can be integrated with other threat intel tools such as MISP and TheHive. Rooms to these tools have been linked in the overview.

![](_resources/04%20OpenCTI/b1185cffde5f0138f80f8e4a6ac39fe4_MD5.jpg)

# Task 3: OpenCTI Data Model

## OpenCTI Data Model

OpenCTI uses a variety of knowledge schemas in structuring data, the main one being the Structured Threat Information Expression ([STIX2](https://oasis-open.github.io/cti-documentation/stix/intro)) standards. STIX is a serialised and standardised language format used in threat intelligence exchange. It allows for the data to be implemented as entities and relationships, effectively tracing the origin of the provided information.

This data model is supported by how the platform’s architecture has been laid out. The image below gives an architectural structure for your know-how.

![](_resources/04%20OpenCTI/fae50ce3139aabb807c875f1f2692baa_MD5.jpg)

Source: [OpenCTI Public Knowledge Base](https://luatix.notion.site/OpenCTI-Public-Knowledge-Base-d411e5e477734c59887dad3649f20518)

The highlight services include:

- **GraphQL API:** The API connects clients to the database and the messaging system.
- **Write workers:** Python processes utilised to write queries asynchronously from the RabbitMQ messaging system.
- **Connectors:** Another set of Python processes used to ingest, enrich or export data on the platform. These connectors provide the application with a robust network of integrated systems and frameworks to create threat intelligence relations and allow users to improve their defence tactics.

According to OpenCTI, connectors fall under the following classes:

![](_resources/04%20OpenCTI/b7360af930a5861f59ddfe2c868fbbbb_MD5.webp)

Refer to the [connectors](https://github.com/OpenCTI-Platform/connectors) and [data model](https://luatix.notion.site/Data-model-4427344d93a74fe194d5a52ce4a41a8d) documentation for more details on configuring connectors and the data schema.

# Task 4: OpenCTI Dashboard 1

Follow along with the task by launching the attached machine and using the credentials provided; log in to the OpenCTI Dashboard via the AttackBox on `[http://MACHINE_IP:8080/](http://MACHINE_IP:8080/)`. Give the machine 10 minutes to start up, and using the AttackBox on fullscreen is advisable.

Username: **info@tryhack.io**

Password: **TryHackMe1234**

## OpenCTI Dashboard

Once connected to the platform, the opening dashboard showcases various visual widgets summarising the threat data ingested into OpenCTI. Widgets on the dashboard showcase the current state of entities ingested on the platform via the total number of entities, relationships, reports and observables ingested, and changes to these properties noted within 24 hours.

![](_resources/04%20OpenCTI/157edcba15791a6d0a83a4e2f92820a2_MD5.gif)

## Activities & Knowledge

The OpenCTI categorises and presents entities under the **Activities and Knowledge** groups on the left-side panel. The activities section covers security incidents ingested onto the platform in the form of reports. It makes it easy for analysts to investigate these incidents. In contrast, the Knowledge section provides linked data related to the tools adversaries use, targeted victims and the type of threat actors and campaigns used.

### Analysis

The Analysis tab contains the input entities in reports analysed and associated external references. Reports are central to OpenCTI as knowledge on threats and events are extracted and processed. They allow for easier identification of the source of information by analysts. Additionally, analysts can add their investigation notes and other external resources for knowledge enrichment. As displayed below, we can look at the **Triton** Software report published by MITRE ATT&CK and observe or add to the details provided.

![](_resources/04%20OpenCTI/6b420cb98ac37541cb17564a8e912c30_MD5.gif)

### Events

Security analysts investigate and hunt for events involving suspicious and malicious activities across their organisational network. Within the Events tab, analysts can record their findings and enrich their threat intel by creating associations for their incidents.

![](_resources/04%20OpenCTI/8338dfd6e6329a13328c140e068aee61_MD5.gif)

### Observations

Technical elements, detection rules and artefacts identified during a cyber attack are listed under this tab: one or several identifiable makeup indicators. These elements assist analysts in mapping out threat events during a hunt and perform correlations between what they observe in their environments against the intel feeds.

![](_resources/04%20OpenCTI/a738873e4d8ae8faad9dab6a7f660ee7_MD5.gif)

### Threats

All information classified as threatening to an organisation or information would be classified under threats. These will include:

- **Threat Actors:** An individual or group of attackers seeking to propagate malicious actions against a target.
- **Intrusion Sets:** An array of TTPs, tools, malware and infrastructure used by a threat actor against targets who share some attributes. APTs and threat groups are listed under this category on the platform due to their known pattern of actions.
- **Campaigns:** Series of attacks taking place within a given period and against specific victims initiated by advanced persistent threat actors who employ various TTPs. Campaigns usually have specified objectives and are orchestrated by threat actors from a nation-state, crime syndicate or other disreputable organisation.

![](_resources/04%20OpenCTI/7beacb9d7e9ca71ec32ea6786c2b291b_MD5.jpg)

### Arsenal

This tab lists all items related to an attack and any legitimate tools identified from the entities.

- **Malware:** Known and active malware and trojan are listed with details of their identification and mapping based on the knowledge ingested into the platform. In our example, we analyse the **4H RAT** malware and we can extract information and associations made about the malware.
- **Attack Patterns:** Adversaries implement and use different TTPs to target, compromise, and achieve their objectives. Here, we can look at the details of the **Command-Line Interface and make decisions based on the relationships established on the platform and navigate through an investigation associated with the technique.**
- **Courses of Action:** MITRE maps out concepts and technologies that can be used to prevent an attack technique from being employed successfully. These are represented as Courses of Action (CoA) against the TTPs.
- **Tools:** Lists all legitimate tools and services developed for network maintenance, monitoring and management. Adversaries may also use these tools to achieve their objectives. For example, for the Command-Line Interface attack pattern, it is possible to narrow down that **CMD** would be used as an execution tool. As an analyst, one can investigate reports and instances associated with the use of the tool.
- **Vulnerabilities:** Known software bugs, system weaknesses and exposures are listed to provide enrichment for what attackers may use to exploit and gain access to systems. The Common Vulnerabilities and Exposures (CVE) list maintained by MITRE is used and imported via a connector.

![](_resources/04%20OpenCTI/a78f21c026c6d2f53f86a173d9d06372_MD5.gif)

### Entities

This tab categorises all entities based on operational sectors, countries, organisations and individuals. This information allows for knowledge enrichment on attacks, organisations or intrusion sets.

![](_resources/04%20OpenCTI/617d098e39dc4093a9115a98b80ecace_MD5.gif)

### Answer the questions below:

**What is the name of the group that uses the 4H RAT malware?**

After you deployed your VMs and either SSH in or login using the attackbox, navigate to the OpenCTI site: `[http://<IP ADDRESS>:8080/](http://10.10.114.192:8080/)` where IP address is referring to the OpenCTI VM IP. We know from the task that malware is under Arsenal so let’s click the **Arsenal** tab on the left and I would say to search for “4H RAT” but it’s right there on the top row, click on it and we’ll go to the 4H RAT page where we’ll find the info, in the details pane on the right:

![](_resources/04%20OpenCTI/ba26d17224e0e7db5f14f029fdce5ef6_MD5.jpg)

![](_resources/04%20OpenCTI/ead2011fd5f9a8bb81159cf5ae0588cb_MD5.jpg)

Answer: Putter Panda

**What kill-chain phase is linked with the Command-Line Interface Attack Pattern?**

We know we’re looking for an attack pattern here and again, per the task, this is located under the **Arsenal** tab. Click **Arsenal > Attack Pattern > Command-Line Interface**

![](_resources/04%20OpenCTI/7093be0e988b4863d995b3e58fc4a862_MD5.jpg)

We’ll find the kill chain phases associated with this attack pattern on the right under details:

![](_resources/04%20OpenCTI/8726e05ca778a52c8d917543dad4493a_MD5.jpg)

Answer: execution-ics

**Within the Activities category, which tab would house the Indicators?**

We can find this info in the task description:

![](_resources/04%20OpenCTI/d8777d653f308a1eebd16c00285e8912_MD5.jpg)

Answer: Observations

# Task 5: OpenCTI: Dashboard 2

## General Tabs Navigation

The day-to-day usage of OpenCTI would involve navigating through different entities within the platform to understand and utilise the information for any threat analysis. We will be looking at the **Cobalt Strike** malware entity for our walkthrough, mainly found under the Arsenal tab we’ve covered previously. When you select an intelligence entity, the details are presented to the user through:

- **Overview Tab:** Provides the general information about an entity being analysed and investigated. In our case, the dashboard will present you with the entity ID, confidence level, description, relations created based on threats, intrusion sets and attack patterns, reports mentioning the entity and any external references.

![](_resources/04%20OpenCTI/d90e652d05589114596439393c4aa369_MD5.jpg)

- **Knowledge Tab:** Presents linked information associated with the entity selected. This tab will include the associated reports, indicators, relations and attack pattern timeline of the entity. Additionally, an analyst can view fine-tuned details from the tabs on the right-hand pane, where information about the threats, attack vectors, events and observables used within the entity are presented.

![](_resources/04%20OpenCTI/94529c0816996779facf7f7882a56aa1_MD5.gif)

- **Analysis Tab**: Provides the reports where the identified entry has been seen. The analysis provides usable information about a threat and guides investigation tasks.

![](_resources/04%20OpenCTI/efbe14d1a46e794c91f0e05303d68d0a_MD5.jpg)

- **Indicators Tab**: Provides information on IOC identified for all the threats and entities.
- **Data Tab:** Contains the files uploaded or generated for export that are related to the entity. These assist in communicating information about threats being investigated in either technical or non-technical formats.
- **History Tab:** Changes made to the element, attributes, and relations are tracked by the platform worker and this tab will outline the changes.

### Answer the questions below:

**What Intrusion sets are associated with the Cobalt Strike malware with a Good confidence level? (Intrusion1, Intrusion2)**

Let’s open up the Cobalt Strike malware: go to Arsenal > Malware > Cobalt Strike:

![](_resources/04%20OpenCTI/5fff9ced33e58586e4680ac3bec8f554_MD5.jpg)

Then we’ll click **Knowledge > Intrusion Sets** and our answer will be the resulting data:

![](_resources/04%20OpenCTI/080fbd2e89948adf92d1bce0a6683753_MD5.jpg)

Answer: CopyKittens, FIN7

**Who is the author of the entity?**

We;’ll find this on the overview tab:

![](_resources/04%20OpenCTI/f6d02a3481a977040a685cee00d38f97_MD5.jpg)

Answer: THE MITRE CORPORATION

# Task 6: Investigative Scenario

As a SOC analyst, you have been tasked with investigations on malware and APT groups rampaging through the world. Your assignment is to look into the **CaddyWiper** malware and **APT37** group. Gather information from OpenCTI to answer the following questions.

### Answer the questions below:

**What is the earliest date recorded related to CaddyWiper? Format: YYYY/MM/DD**

To get this info, I searched “caddy” under **Analysis > Reports** and clicked the **ESET CaddyWiper** report.

![](_resources/04%20OpenCTI/0761aa7a7cef30f0ab43bf524b50729d_MD5.jpg)

Our info is in the entity details description:

![](_resources/04%20OpenCTI/be3e4748967fbb82e6394b43992f7778_MD5.jpg)

Answer: 2022/03/15

**Which Attack technique is used by the malware for execution?**

**Arsenal > Malware > Knowledge > Attack Patterns:**

![](_resources/04%20OpenCTI/5b361a57ae4e0b12b9ae232823200716_MD5.jpg)

Answer: Native API

**How many malware relations are linked to this Attack technique?**

Click the answer in the matrix from last question and your answer will be on the next screen:

![](_resources/04%20OpenCTI/bc229541a6f032a12e32c164409f2bff_MD5.jpg)

Answer: 113

**Which 3 tools were used by the Attack Technique in 2016? (Ans: Tool1, Tool2, Tool3)**

Click tools on the right and sort by date, they’ll be the three earliest results:

![](_resources/04%20OpenCTI/15eb8131ae467dfcfdc9c032cc6837f9_MD5.jpg)

Answer: BloodHound, Empire, ShimRatReporter

**What country is APT37 associated with?**

Just searched apt37 in the top right, expanded the intrusion sets:

![](_resources/04%20OpenCTI/168cf3e99713c40fc322f1f750984766_MD5.jpg)

Answer: north korea

**Which Attack techniques are used by the group for initial access? (Ans: Technique1, Technique2)**

The way I did this was, from the APT37 page, click Attack Patterns, then scroll to initial access, open the two techniques and get their technique IDs:

Answer: T1189, T1566

# Task 7: Room Conclusion

Fantastic work on going through and completing the OpenCTI room.

In this room, we looked at the use of the OpenCTI platform when it comes to processing threat intel and assisting analysts in investigating incidents. Check out the documentation linked within the room to get more information about OpenCTI and the different tools and frameworks used.