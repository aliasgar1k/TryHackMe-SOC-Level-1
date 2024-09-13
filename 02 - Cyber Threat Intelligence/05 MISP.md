https://medium.com/@jcm3/misp-tryhackme-walkthrough-c7b00a9257e8
https://www.youtube.com/watch?v=uXpKr-ZGIp4 

# Task 1: Room Overview

## MISP — MALWARE INFORMATION SHARING PLATFORM**

This room explores the MISP Malware & Threat Sharing Platform through its core objective to foster sharing of structured threat information among security analysts, malware researchers and IT professionals.

## Room Objectives

We will be covering the following areas within the room:

- Introduction to MISP and why it was developed.
- Use cases MISP can be applied to
- Core features and terminologies.
- Dashboard Navigation.
- Event Creation and Management.
- Feeds and Taxonomies.

## Room Prerequisites

General familiarity with security concepts is: check out the [Pre-Security](https://tryhackme.com/path-action/presecurity/join) path and the [Jr. Security Analyst](https://tryhackme.com/room/jrsecanalystintrouxo) room.

At the end of the room, we will have an exercise task to test your knowledge of using MISP.

![](_resources/05%20MISP/a5eb259bcd86536e2f9a7d200abcf891_MD5.jpg)

# Task 2: MISP Introduction: Features & Terminologies

## What is MISP?

[MISP (Malware Information Sharing Platform)](https://www.misp-project.org/) is an open-source threat information platform that facilitates the collection, storage and distribution of threat intelligence and Indicators of Compromise (IOCs) related to malware, cyber attacks, financial fraud or any intelligence within a community of trusted members.

Information sharing follows a distributed model, with supported closed, semi-private, and open communities (public). Additionally, the threat information can be distributed and consumed by Network Intrusion Detection Systems (NIDS), log analysis tools and Security Information and Event Management Systems (SIEM).

MISP is effectively useful for the following use cases:

- **Malware Reverse Engineering**: Sharing of malware indicators to understand how different malware families function.
- **Security Investigations:** Searching, validating and using indicators in investigating security breaches.
- **Intelligence Analysis:** Gathering information about adversary groups and their capabilities.
- **Law Enforcement:** Using Indicators to support forensic investigations.
- **Risk Analysis:** Researching new threats, their likelihood and occurrences.
- **Fraud Analysis:** Sharing of financial indicators to detect financial fraud.

## What does MISP support?

![](_resources/05%20MISP/0a0d54a7596ff0ecf5024b60bb0edbb8_MD5.jpg)

MISP provides the following core functionalities:

- **IOC database:** This allows for the storage of technical and non-technical information about malware samples, incidents, attackers and intelligence.
- **Automatic Correlation:** Identification of relationships between attributes and indicators from malware, attack campaigns or analysis.
- **Data Sharing:** This allows for sharing of information using different models of distributions and among different MISP instances.
- **Import & Export Features:** This allows the import and export of events in different formats to integrate other systems such as NIDS, HIDS, and OpenIOC.
- **Event Graph:** Showcases the relationships between objects and attributes identified from events.
- **API support:** Supports integration with own systems to fetch and export events and intelligence.

The following terms are commonly used within MISP and are related to the functionalities described above and the general usage of the platform:

- **Events:** Collection of contextually linked information.
- **Attributes:** Individual data points associated with an event, such as network or system indicators.
- **Objects:** Custom attribute compositions.
- **Object References:** Relationships between different objects.
- **Sightings:** Time-specific occurrences of a given data point or attribute detected to provide more credibility.
- **Tags:** Labels attached to events/attributes.
- **Taxonomies:** Classification libraries are used to tag, classify and organise information.
- **Galaxies:** Knowledge base items used to label events/attributes.
- **Indicators:** Pieces of information that can detect suspicious or malicious cyber activity.

# Task 3: Using the System

For you to understand how MISP works and follow along in the task, launch the attached machine and use the credentials provided to log in to the Analyst Account on [https://LAB_WEB_URL.p.thmlabs.com/](https://lab_web_url.p.thmlabs.com/). Wait 1 minute for the URL and lab to start up.

Username: _Analyst@THM.thm_ Password: _Analyst12345&_

## Dashboard

The analyst’s view of MISP provides you with the functionalities to track, share and correlate events and IOCs identified during your investigation. The dashboard’s menu contains the following options, and we shall look into them further:

- **Home button:** Returns you to the application’s start screen, the event index page or the page set as a custom home page using the star in the top bar.
- **Event Actions:** All the malware data entered into MISP comprises an event object described by its connected attributes. The Event actions menu gives access to all the functionality related to the creation, modification, deletion, publishing, searching and listing of events and attributes.
- **Dashboard:** This allows you to create a custom dashboard using widgets.
- **Galaxies:** Shortcut to the list of [MISP Galaxies](https://github.com/MISP/misp-book/blob/main/galaxy) on the MISP instance. More on these on the Feeds & Taxonomies Task.
- **Input Filters:** Input filters alter how users enter data into this instance. Apart from the basic validation of attribute entry by type, the site administrators can define regular expression replacements and blocklists for specific values and block certain values from being exportable. Users can view these replacement and blocklist rules here, while an administrator can alter them.
- **Global Actions:** Access to information about MISP and this instance. You can view and edit your profile, view the manual, read the news or the terms of use again, see a list of the active organisations on this instance and a histogram of their contributions by an attribute type.
- **MISP:** Simple link to your baseurl.
- **Name:** Name (Auto-generated from Mail address) of currently logged in user.
- **Envelope:** Link to User Dashboard to consult some of your notifications and changes since the last visit. Like some of the proposals received for your organisation.
- **Log out:** The Log out button to end your session immediately.

![](_resources/05%20MISP/3379fdada4ed11f822b002270bad846c_MD5.jpg)

## Event Management

The Event Actions tab is where you, as an analyst, will create all malware investigation correlations by providing descriptions and attributes associated with the investigation. Splitting the process into three significant phases, we have:

- Event Creation.
- Populating events with attributes and attachments.
- Publishing.

We shall follow this process to create an event based on an investigation of Emotet Epoch 4 infection with Cobalt Strike and Spambot from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/2022/03/01/index.html). Follow along with the examples provided below.

## Event Creation

In the beginning, events are a storage of general information about an incident or investigation. We add the description, time, and risk level deemed appropriate for the incident by clicking the **Add Event** button. Additionally, we specify the distribution level we would like our event to have on the MISP network and community. According to MISP, the following distribution options are available:

- **Your organisation only:** This only allows members of your organisation to see the event.
- **This Community-only:** Users that are part of your MISP community will be able to see the event. This includes your organisation, organisations on this MISP server and organisations running MISP servers that synchronise with this server.
- **Connected communities:** Users who are part of your MISP community will see the event, including all organisations on this MISP server, all organisations on MISP servers synchronising with this server, and the hosting organisations of servers that are two hops away from this one.
- **All communities:** This will share the event with all MISP communities, allowing the event to be freely propagated from one server to the next.

Additionally, MISP provides a means to add a sharing group, where an analyst can define a predefined list of organisations to share events.

![](_resources/05%20MISP/251bee6f513e5f11748168f5754ade5e_MD5.jpg)

Event details can also be populated by filling out predefined fields on a defined template, including adding attributes to the event. We can use the email details of the CobaltStrike investigation to populate details of our event. We will be using the **Phishing E-mail** category from the templates.

![](_resources/05%20MISP/303ffb759690d63ee5196e80026b3f57_MD5.jpg)

## Attributes & Attachments

Attributes can be added manually or imported through other formats such as OpenIOC and ThreatConnect. To add them manually, click the **Add Attribute** and populate the form fields.

Some essential options to note are:

- **For Intrusion Detection System:** This allows the attribute to be used as an IDS signature when exporting the NIDS data unless it overrides the permitted list. If not set, the attribute is considered contextual information and not used for automatic detection.
- **Batch import:** If there are several attributes of the same type to enter (such as a list of IP addresses, it is possible to join them all into the same value field, separated by a line break between each line. This will allow the system to create separate lines for each attribute.

In our example below, we add an Emotet Epoch 4 C2 IP address associated with the infection as our attributes, obtained from the IOC text file.

![](_resources/05%20MISP/91c760c49bfc76bbddd187f108584ce3_MD5.jpg)

The analyst can also add file attachments to the event. These may include malware, report files from external analysis or simply artefacts dropped by the malware. We have added the Cobalt Strike EXE binary file to our event in our example. You also have to check the Malware checkbox to mark the file as malware. This will ensure that it is zipped and passworded to protect users from accidentally downloading and executing the file.

![](_resources/05%20MISP/81fb9581b8531f1cee095752f944c15e_MD5.gif)

## Publish Event

Once the analysts have created events, the _organisation admin_ will review and publish those events to add them to the pool of events. This will also share the events to the distribution channels set during the creation of the events.

![](_resources/05%20MISP/8e559fb18efba89e41346835602e9e6f_MD5.gif)

### Answer the questions below:

**How many distribution options does MISP provide to share threat information?**

In the task text:

![](_resources/05%20MISP/1006294faec2c2cab81246922a588d75_MD5.jpg)

Answer: 4

**Which user has the role to publish events?**

![](_resources/05%20MISP/a9dffdd7133a380e3e2ac083fcbf41c0_MD5.jpg)

Answer: organisation admin

# Task 4: Feeds & Taxonomies

## Feeds

Feeds are resources that contain indicators that can be imported into MISP and provide attributed information about security events. These feeds provide analysts and organisations with continuously updated information on threats and adversaries and aid in their proactive defence against attacks.

MISP Feeds provide a way to:

- Exchange threat information.
- Preview events along with associated attributes and objects.
- Select and import events to your instance.
- Correlate attributes identified between events and feeds.

Feeds are enabled and managed by the **Site Admin** for the analysts to obtain information on events and indicators.

![](_resources/05%20MISP/3b1e27c8d2ff6044cddcbe16ed4ed05d_MD5.gif)

## Taxonomies

A taxonomy is a means of classifying information based on standard features or attributes. On MISP, taxonomies are used to categorise events, indicators and threat actors based on tags that identify them.

![](_resources/05%20MISP/a60f35b375824215da8d2ef137da71dc_MD5.jpg)

Analysts can use taxonomies to:

- Set events for further processing by external tools such as [VirusTotal](https://virustotal.com/).
- Ensure events are classified appropriately before the Organisation Admin publishes them.
- Enrich intrusion detection systems’ export values with tags that fit specific deployments.

Taxonomies are expressed in machine tags, which comprise three vital parts:

- **Namespace:** Defines the tag’s property to be used.
- **Predicate:** Specifies the property attached to the data.
- **Value:** Numerical or text details to map the property.

(Source: MISP)

Taxonomies are listed under the _Event Actions_ tab. The site admin can enable relevant taxonomies.

![](_resources/05%20MISP/be5592bc90c35edc5edb727ac6762f71_MD5.gif)

## Tagging

Information from feeds and taxonomies, tags can be placed on events and attributes to identify them based on the indicators or threats identified correctly. Tagging allows for effective sharing of threat information between users, communities and other organisations using MISP to identify various threats.

In our CobaltStrike event example, we can add tags by clicking on the buttons in the **Tags** section and searching from the available options appropriate to the case. The buttons represent _global_ tags and _local_ tags, respectively. It is also important to note that you can add your unique tags to your MISP instance as an analyst or organisation that would allow you to ingest, navigate through and share information quickly within the organisation.

![](_resources/05%20MISP/2d091d0246e20cd20451ec7df1472074_MD5.gif)

## Tagging Best Practices

### Tagging at Event level vs Attribute Level

Tags can be added to an event and attributes. Tags are also inheritable when set. It is recommended to set tags on the entire event and only include tags on attributes when they are an exception from what the event indicates. This will provide a more fine-grained analysis.

### The minimal subset of Tags

The following tags can be considered a must-have to provide a well-defined event for distribution:

- [**Traffic Light Protocol:**](https://www.first.org/tlp/) Provides a colour schema to guide how intelligence can be shared.
- **Confidence:** Provides an indication as to whether or not the data being shared is of high quality and has been vetted so that it can be trusted to be good for immediate usage.
- **Origin:** Describes the source of information and whether it was from automation or manual investigation.
- **Permissible Actions Protocol:** An advanced classification that indicates how the data can be used to search for compromises within the organisation.

# Task 5: Scenario Event

[CIRCL](https://www.circl.lu) (Computer Incident Respons Center Luxembourg) published an event associated with PupyRAT infection. Your organisation is on alert for remote access trojans and malware in the wild, and you have been tasked to investigate this event and correlate the details with your SIEM. Use what you have learned from the room to identify the event and complete this task.

### Answer the questions below:

**What event ID has been assigned to the PupyRAT event?**

For this you’ll either need to use the attackbox to launch the webapp or connect through a vpn, which is how I’ll be doing it. Launch the webapp using the link provided in task 3, login using the creds provided in the same task and then search pupyrat, ID will be displayed after:

![](_resources/05%20MISP/b1d3d9386e0697d975aeb1740facae00_MD5.jpg)

Answer: 1145

**The event is associated with the adversary gaining ____ into organisations.**

Click on the event ID and under **Tags** we’ll get our answer:

![](_resources/05%20MISP/ee357232b95c509b6bfbee148d96150e_MD5.jpg)

Answer: remote access

**What IP address has been mapped as the PupyRAT C2 Server**

For this I just did a Ctrl+F for “c2” which got no relevant hits, then searched “command” and that got me the answer:

![](_resources/05%20MISP/021a743ec68c742cadbdf762be577f4d_MD5.jpg)

Answer: 89.107.62.39

**From the Intrusion Set Galaxy, what attack group is known to use this form of attack?**

just scroll down to galaxies and it’s right there:

![](_resources/05%20MISP/ab603ca88105698cfb575b4ffbf18431_MD5.jpg)

Answer: magic hound

**There is a taxonomy tag set with a Certainty level of 50. Which one is it?**

![](_resources/05%20MISP/0a2160f8986f6c9147dc8f4ccfbd3892_MD5.jpg)

Answer: osint

# Task 6: Conclusion

## Recap

Hopefully, you learned a lot about MISP and its use in sharing malware and threat information in this room. This tool is useful in the real world regarding incident reporting. You should be able to use the knowledge gained to effectively document, report and share incident information.

Additional Resources

There is plenty of information and capabilities that were not covered in this room. This leaves plenty of room for research and learning more about MISP. To guide you towards that, look at the following attached links and feel free to come back to the room to practice.

- [MISP Book](https://www.circl.lu/doc/misp/)
- [MISP GitHub](https://github.com/MISP/)
- [CIRCL MISP Training Module 1](https://www.youtube.com/watch?v=aM7czPsQyaI)
- [CIRCL MISP Training Module 2](https://www.youtube.com/watch?v=Jqp8CVHtNVk)

We wish to give credit to [CIRCL](https://www.circl.lu/services/misp-malware-information-sharing-platform/) for providing guidelines that supported this room.