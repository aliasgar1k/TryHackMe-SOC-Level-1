https://www.youtube.com/watch?v=yG7qx1y4v90


https://medium.com/@haircutfish/tryhackme-wireshark-the-basics-task-1-introduction-task-2-tool-overview-985289ceb43f
https://medium.com/@haircutfish/tryhackme-wireshark-the-basics-task-3-packet-dissection-task-4-packet-navigation-64d1f39e5807
https://medium.com/@haircutfish/tryhackme-wireshark-the-basics-task-5-packet-filtering-task-6-conclusion-27f3fb3a2898
# Task 1 Introduction

Wireshark is an open-source, cross-platform network packet analyzer tool capable of sniffing and investigating live traffic and inspecting packet captures (PCAP). It is commonly used as one of the best packet analysis tools. In this room, we will look at the basics of Wireshark and use it to perform fundamental packet analysis.

**Note:** A VM is attached to this room. You don’t need SSH or RDP; the room provides a “Split View” feature. We suggest completing the [**Network Fundamentals**](https://tryhackme.com/module/network-fundamentals) module before starting working in this room.

There are two capture files given in the VM. You can use the “http1.pcapng” file to simulate the actions shown in the screenshots. Please note that you need to use the “Exercise.pcapng” file to answer the questions.

### Answer the questions below

All the answers can be found above, so I won’t be providing them here.

**Which file is used to simulate the screenshots?**

The Answer to this question can be found in the last paragraph of the above section. Once you find it, type the answer into the TryHackMe answer field and click submit.

![](_resources/09%20Wireshark%20-%20The%20Basics/93abc2b2c20421f440e874a7f5e9b7dc_MD5.jpg)

**Which file is used to answer the questions?**

The Answer to this question can be found in the last paragraph of the above section. Once you find it, type the answer into the TryHackMe answer field and click submit.

![](_resources/09%20Wireshark%20-%20The%20Basics/44aefece617ed7372cbfbbb705eefea9_MD5.jpg)

# Task 2 Tool Overview

## Use Cases

Wireshark is one of the most potent traffic analyzer tools available in the wild. There are multiple purposes for its use:

- Detecting and troubleshooting network problems, such as network load failure points and congestion.
- Detecting security anomalies, such as rogue hosts, abnormal port usage, and suspicious traffic.
- Investigating and learning protocol details, such as response codes and payload data.

**Note:** Wireshark is not an Intrusion Detection System (IDS). It only allows analysts to discover and investigate the packets in depth. It also doesn’t modify packets; it reads them. Hence, detecting any anomaly or network problem highly relies on the analyst’s knowledge and investigation skills.

## GUI and Data

Wireshark GUI opens with a single all-in-one page, which helps users investigate the traffic in multiple ways. At first glance, five sections stand out.

![](_resources/09%20Wireshark%20-%20The%20Basics/7b9bc18b413f309ea3b9db6cebd899b9_MD5.jpg)

The below picture shows Wireshark’s main window. The sections explained in the table are highlighted. Now open the Wireshark and go through the walkthrough.

![](_resources/09%20Wireshark%20-%20The%20Basics/f5d289df27f5f4b677d7bbcb936d17de_MD5.jpg)

## Loading PCAP Files

The above picture shows Wireshark’s empty interface. The only available information is the recently processed “http1.cap” file. Let’s load that file and see Wireshark’s detailed packet presentation. Note that you can also use the **“File”** menu, dragging and dropping the file, or double-clicking on the file to load a pcap.

![](_resources/09%20Wireshark%20-%20The%20Basics/28c0c52f0dbba73f9fdb15dda0680ebe_MD5.jpg)

Now, we can see the processed filename, detailed number of packets and packet details. Packet details are shown in three different panes, which allow us to discover them in different formats.

![](_resources/09%20Wireshark%20-%20The%20Basics/9aa05493ec77f6eb4e9d27a2802ca14e_MD5.jpg)

## Coloring Packets

Along with quick packet information, Wireshark also color packets in order of different conditions and the protocol to spot anomalies and protocols in captures quickly (this explains why almost everything is green in the given screenshots). This glance at packet information can help track down exactly what you’re looking for during analysis. You can create custom color rules to spot events of interest by using display filters, and we will cover them in the next room. Now let’s focus on the defaults and understand how to view and use the represented data details.

Wireshark has two types of packet coloring methods: temporary rules that are only available during a program session and permanent rules that are saved under the preference file (profile) and available for the next program session. You can use the “right-click menu” or **“View → Coloring Rules”** menu to create permanent coloring rules. The **“Colorize Packet List”** menu activates/deactivates the coloring rules. Temporary packet coloring is done with the “right-click menu” or **“View → Conversation Filter”** menu, which is covered in TASK-5.

The default permanent colouring is shown below.

![](_resources/09%20Wireshark%20-%20The%20Basics/9b52cd37aa08616375d491a839c47b4c_MD5.jpg)

## Traffic Sniffing

You can use the blue **“shark button”** to start network sniffing (capturing traffic), the red button will stop the sniffing, and the green button will restart the sniffing process. The status bar will also provide the used sniffing interface and the number of collected packets.

![](_resources/09%20Wireshark%20-%20The%20Basics/3a0f5c6426a1ab8324d8c84d550e6aae_MD5.jpg)

## Merge PCAP Files

Wireshark can combine two pcap files into one single file. You can use the **“File → Merge”** menu path to merge a pcap with the processed one. When you choose the second file, Wireshark will show the total number of packets in the selected file. Once you click “open”, it will merge the existing pcap file with the chosen one and create a new pcap file. Note that you need to save the “merged” pcap file before working on it.

![](_resources/09%20Wireshark%20-%20The%20Basics/5eb8b031d0bd31d50fc39c0ea7418fa8_MD5.jpg)

## View File Details

Knowing the file details is helpful. Especially when working with multiple pcap files, sometimes you will need to know and recall the file details (File hash, capture time, capture file comments, interface and statistics) to identify the file, classify and prioritize it. You can view the details by following “**Statistics → Capture File Properties”** or by clicking the **“pcap icon located on the left bottom”** of the window.

![](_resources/09%20Wireshark%20-%20The%20Basics/1f1c22e19b34da5c064db779b5aeb399_MD5.jpg)

### Answer the questions below

Use the “Exercise.pcapng” file to answer the questions.

If you haven’t already, scroll to the top of this write-up and follow the steps it takes to load the pcap file into Wireshark. Once you have done this, proceed to the questions.

**Read the “capture file comments”. What is the flag?**

Go to the toolbar at the top of Wireshark, and look for _Statistics._

![](_resources/09%20Wireshark%20-%20The%20Basics/f77ab4cd51a45555f58472b7f004ec6f_MD5.jpg)

Either click on _Statistics_ or press the letter _S_ to have the drop-down appear. On the drop-down menu, click _Capture File Properties._

![](_resources/09%20Wireshark%20-%20The%20Basics/b79504685e3d930d1536491fc42363ea_MD5.jpg)

The _Wireshark — Capture File Properties_ window will pop up. Look at the bottom of this window for the _Capture File Comments_ section. Once you see it, scroll to the bottom.

![](_resources/09%20Wireshark%20-%20The%20Basics/5d561215803a11ae790b2cde07d950f2_MD5.jpg)

When you reach the bottom of this section, you will see _Flag:_ followed by the flag. Highlight the flag, then copy (ctrl +c) then paste (ctrl +v) the flag in the TryHackMe answer field and click submit.

![](_resources/09%20Wireshark%20-%20The%20Basics/30afaf47850e0d83bc9250410c743448_MD5.jpg)

Answer: TryHackMe_Wireshark_Demo

**What is the total number of packets?**

Starting back on the main page of Wireshark, look at the bottom info bar. Look for the word _Packets:_, the answer will be to the right of this word. Highlight the number, then copy (ctrl +c) then paste (ctrl +v) the flag in the TryHackMe answer field and click submit.

![](_resources/09%20Wireshark%20-%20The%20Basics/1509c44d005f5fbd1c4d389bcfff5d3d_MD5.jpg)

Answer: 58620

**What is the SHA256 hash value of the capture file?**

Go to the toolbar at the top of Wireshark, and look for _Statistics._

![](_resources/09%20Wireshark%20-%20The%20Basics/f77ab4cd51a45555f58472b7f004ec6f_MD5.jpg)

Either click on _Statistics_ or press the letter _S_ to have the drop-down appear. On the drop-down menu, click _Capture File Properties._

![](_resources/09%20Wireshark%20-%20The%20Basics/b79504685e3d930d1536491fc42363ea_MD5.jpg)

The _Wireshark — Capture File Properties_ window will pop up. Look in the _Details_ section for _Hash(SHA256):_, When you find it, you will see a long string of alphanumeric characters. This is the answer, highlight the hash, then copy (ctrl +c) then paste (ctrl +v) the flag in the TryHackMe answer field and click submit.

![](_resources/09%20Wireshark%20-%20The%20Basics/dc68618aa26f7e204a8d751d229c5d9f_MD5.jpg)

Answer: f446de335565fb0b0ee5e5a3266703c778b2f3dfad7efeaeccb2da5641a6d6eb

# Task 3 Packet Dissection

## Packet Dissection

Packet dissection is also known as protocol dissection, which investigates packet details by decoding available protocols and fields. Wireshark supports a long list of protocols for dissection, and you can also write your dissection scripts. You can find more details on dissection [**here**](https://github.com/boundary/wireshark/blob/master/doc/README.dissector).

**Note:** This section covers how Wireshark uses OSI layers to break down packets and how to use these layers for analysis. It is expected that you already have background knowledge of the OSI model and how it works.

## Packet Details

You can click on a packet in the packet list pane to open its details (double-click will open details in a new window). Packets consist of 5 to 7 layers based on the OSI model. We will go over all of them in an HTTP packet from a sample capture. The picture below shows viewing packet number 27.

![](_resources/09%20Wireshark%20-%20The%20Basics/b6cb4f789abdd262a702deb1b42b86cb_MD5.jpg)

Each time you click a detail, it will highlight the corresponding part in the packet bytes pane.

![](_resources/09%20Wireshark%20-%20The%20Basics/819d26aa9b5fbf9dc47abb8a2b616102_MD5.jpg)

Let’s have a closer view of the details pane.

![](_resources/09%20Wireshark%20-%20The%20Basics/e5fcaafb8a14a7b5e8c3fbad1b11e8e7_MD5.jpg)

We can see seven distinct layers to the packet: frame/packet, source [MAC], source [IP], protocol, protocol errors, application protocol, and application data. Below we will go over the layers in more detail.

**The Frame (Layer 1):** This will show you what frame/packet you are looking at and details specific to the Physical layer of the OSI model.

![](_resources/09%20Wireshark%20-%20The%20Basics/642c5bcbffc71df2bf60d14956a959a7_MD5.jpg)

**Source \[MAC\] (Layer 2):** This will show you the source and destination MAC Addresses; from the Data Link layer of the OSI model.

![](_resources/09%20Wireshark%20-%20The%20Basics/517b480650e461d02534c74fe01fe4b0_MD5.jpg)

**Source \[IP\] (Layer 3):** This will show you the source and destination IPv4 Addresses; from the Network layer of the OSI model.

![](_resources/09%20Wireshark%20-%20The%20Basics/9e3ddc55e773c66d49739d470744b453_MD5.jpg)

**Protocol (Layer 4):** This will show you details of the protocol used (UDP/TCP) and source and destination ports; from the Transport layer of the OSI model.

![](_resources/09%20Wireshark%20-%20The%20Basics/0700de6474a9d53b237daf5e3e693f85_MD5.jpg)

**Protocol Errors:** This continuation of the 4th layer shows specific segments from TCP that needed to be reassembled.

![](_resources/09%20Wireshark%20-%20The%20Basics/3425169f3a5f98b853e1f55b8ac0c890_MD5.jpg)

**Application Protocol (Layer 5):** This will show details specific to the protocol used, such as HTTP, FTP, and SMB. From the Application layer of the OSI model.

![](_resources/09%20Wireshark%20-%20The%20Basics/a3dbc93e6822f6bd2eaf7ec98f83b75c_MD5.jpg)

**Application Data:** This extension of the 5th layer can show the application-specific data.

![](_resources/09%20Wireshark%20-%20The%20Basics/f578aec80d432a0b8d09380a1159e12c_MD5.jpg)

Now that we understand what a general packet is composed of, let’s look at various application protocols and their specific details.

### Answer the questions below

Use the “Exercise.pcapng” file to answer the questions.

**View packet number 38. Which markup language is used under the HTTP protocol?**

Once the file has opened in Wireshark, look at the Menu Bar at the top of the Window. Click on _Go_, a drop down menu will appear. Click on _Go To Packet…_

![](_resources/09%20Wireshark%20-%20The%20Basics/09ef592384bc5dcdf262684f7ad466b2_MD5.jpg)

On the right side of the window, the Packet search Bar will appear. Type _38_ into the field, and press enter or click the _Got To Packet_ button.

![](_resources/09%20Wireshark%20-%20The%20Basics/fa74dfb5e91a19b8b196df28583c99eb_MD5.jpg)

You will be brought right to directly to the packet. You should be able to see the answer sitting right under the _Hypertext Transfer Protocol_ section. You can type the answer into the answer section or Copy and Paste the answer (under this screen shot, I will show how to copy the correct field).

![](_resources/09%20Wireshark%20-%20The%20Basics/a1c6541e1f84b224a6d5dc2e6d5a5c75_MD5.jpg)

Right-click on the answer. From the drop-down menu, hover over copy. A new drop-down will appear, click on _Description_. You now have the answer copied on your clipboard. Click on the answer section of THM, paste it via _CTRL + V,_ and click submit.

![](_resources/09%20Wireshark%20-%20The%20Basics/c6803c33971a35942be65cbc5bfd34fc_MD5.jpg)

Answer: eXtensible Markup Language

**What is the arrival date of the packet? (Answer format: Month/Day/Year)**

We learned about this from the section _The Frame (Layer 1)_ above. Clicking on the first sections drop-down icon, it will open the details of said section.

![](_resources/09%20Wireshark%20-%20The%20Basics/71117971ad67bd965667085693b9cac4_MD5.jpg)

With this layers details being displayed, look down till you see _Arrival Time_. You will see the answer right after the colon. The format is two digits for the month, two digits for the day, and four digits for the month (00/00/0000). Type this answer into the THM answer field, and click submit.

![](_resources/09%20Wireshark%20-%20The%20Basics/84e924a810ff2471f5ed4018f3803d03_MD5.jpg)

Answer: 05/13/2004

**What is the TTL value?**

Now you want to move down to the _IP Layer (Internet Protocol Version 4)_, and click the drop-down icon to view this layers details.

![](_resources/09%20Wireshark%20-%20The%20Basics/8f97d56552f819938bec3a27476b02f1_MD5.jpg)

In the details, look for _Time to live:,_ the answer will be found here. Once you find it, type the answer into the THM answer field, and click submit.

![](_resources/09%20Wireshark%20-%20The%20Basics/ac6e5da2ad159f3c23fd1c86fff6217c_MD5.jpg)

Answer: 47

**What is the TCP payload size?**

Move down one more layer to the _Protocol Layer (Transmission Control Protocol)_, and click the drop-down icon.

![](_resources/09%20Wireshark%20-%20The%20Basics/e90717310436cc9a50a643600696c4fe_MD5.jpg)

In the details, look for _TCP Segment Len:,_ the answer will be found here. Additionally, the answer can be found in the layer overview at the end after _Len: ._ Once you find it, type the answer into the THM answer field, and click submit.

![](_resources/09%20Wireshark%20-%20The%20Basics/3074781c2dd84e4434b14a36499ecaca_MD5.jpg)

Answer: 424

**What is the e-tag value?**

Move down two more layers to the _Application Layer (Hypertext Transfer Protocol)_, and click the drop-down icon.

![](_resources/09%20Wireshark%20-%20The%20Basics/501b8987a11c6de6442340b33e0733fd_MD5.jpg)

In the details, look for _ETag:,_ the answer will be found here. Click on it and using _copy (CTRL+ C)_. Go over to the THM answer field and use _paste ( CTRL+V)_. Now just delete the extra data (_ETag: “ “\r\n)_ that was copied over. It should leave only the answer left, now just click submit.

![](_resources/09%20Wireshark%20-%20The%20Basics/612fd99f07346c5cec16d5293bd06445_MD5.jpg)

Answer: 9a01a-4696–7e354b00

# Task 4 Packet Navigation

## Packet Numbers

Wireshark calculates the number of investigated packets and assigns a unique number for each packet. This helps the analysis process for big captures and makes it easy to go back to a specific point of an event.

![](_resources/09%20Wireshark%20-%20The%20Basics/84b5bea518bf04e21cb1781ba937bf3c_MD5.jpg)

## Go to Packet

Packet numbers do not only help to count the total number of packets or make it easier to find/investigate specific packets. This feature not only navigates between packets up and down; it also provides in-frame packet tracking and finds the next packet in the particular part of the conversation. You can use the **“Go”** menu and toolbar to view specific packets.

![](_resources/09%20Wireshark%20-%20The%20Basics/984d1a4474961ff66bc4ce8e458c4d70_MD5.jpg)

## Find Packets

Apart from packet number, Wireshark can find packets by packet content. You can use the **“Edit → Find Packet”** menu to make a search inside the packets for a particular event of interest. This helps analysts and administrators to find specific intrusion patterns or failure traces.

There are two crucial points in finding packets. The first is knowing the input type. This functionality accepts four types of inputs (Display filter, Hex, String and Regex). String and regex searches are the most commonly used search types. Searches are case insensitive, but you can set the case sensitivity in your search by clicking the radio button.

The second point is choosing the search field. You can conduct searches in the three panes (packet list, packet details, and packet bytes), and it is important to know the available information in each pane to find the event of interest. For example, if you try to find the information available in the packet details pane and conduct the search in the packet list pane, Wireshark won’t find it even if it exists.

![](_resources/09%20Wireshark%20-%20The%20Basics/6cf7628a5593b08faa3ffb9fc3e26007_MD5.jpg)

## Mark Packets

Marking packets is another helpful functionality for analysts. You can find/point to a specific packet for further investigation by marking it. It helps analysts point to an event of interest or export particular packets from the capture. You can use the **“Edit”** or the “right-click” menu to mark/unmark packets.

Marked packets will be shown in black regardless of the original colour representing the connection type. Note that marked packet information is renewed every file session, so marked packets will be lost after closing the capture file.

![](_resources/09%20Wireshark%20-%20The%20Basics/946ff31417401d196e2c3dc8bb5a43af_MD5.jpg)

## Packet Comments

Similar to packet marking, commenting is another helpful feature for analysts. You can add comments for particular packets that will help the further investigation or remind and point out important/suspicious points for other layer analysts. Unlike packet marking, the comments can stay within the capture file until the operator removes them.

![](_resources/09%20Wireshark%20-%20The%20Basics/a930cf7c2a429aaf556911193e70b737_MD5.jpg)

## Export Packets

Capture files can contain thousands of packets in a single file. As mentioned earlier, Wireshark is not an IDS, so sometimes, it is necessary to separate specific packages from the file and dig deeper to resolve an incident. This functionality helps analysts share the only suspicious packages (decided scope). Thus redundant information is not included in the analysis process. You can use the **“File”** menu to export packets.

![](_resources/09%20Wireshark%20-%20The%20Basics/1bc76eb8655e03619c746ce3b861faa6_MD5.jpg)

## Export Objects (Files)

Wireshark can extract files transferred through the wire. For a security analyst, it is vital to discover shared files and save them for further investigation. Exporting objects are available only for selected protocol’s streams (DICOM, HTTP, IMF, SMB and TFTP).

![](_resources/09%20Wireshark%20-%20The%20Basics/09b7317e1d02a0bd59c1f68762bc8b6c_MD5.jpg)

## Time Display Format

Wireshark lists the packets as they are captured, so investigating the default flow is not always the best option. By default, Wireshark shows the time in “Seconds Since Beginning of Capture”, the common usage is using the UTC Time Display Format for a better view. You can use the **“View → Time Display Format”** menu to change the time display format.

![](_resources/09%20Wireshark%20-%20The%20Basics/fa3e1fa4982f2a504365dc5710be6759_MD5.jpg)

![](_resources/09%20Wireshark%20-%20The%20Basics/ba08c49f40d7132c2068fa1ec0f966a8_MD5.jpg)

## Expert Info

Wireshark also detects specific states of protocols to help analysts easily spot possible anomalies and problems. Note that these are only suggestions, and there is always a chance of having false positives/negatives. Expert info can provide a group of categories in three different severities. Details are shown in the table below.

![](_resources/09%20Wireshark%20-%20The%20Basics/1d36495805b906ba8890bbe93033c763_MD5.jpg)

Frequently encountered information groups are listed in the table below. You can refer to Wireshark’s official documentation for more information on the expert information entries.

![](_resources/09%20Wireshark%20-%20The%20Basics/df2bdaabf7b4f67fe333bf0fa13284e3_MD5.jpg)

You can use the **“lower left bottom section”** in the status bar or **“Analyse → Expert Information”** menu to view all available information entries via a dialogue box. It will show the packet number, summary, group protocol and total occurrence.

![](_resources/09%20Wireshark%20-%20The%20Basics/f4d266ac726358b624028525e8fe7db4_MD5.jpg)

### Answer the questions below

Use the “Exercise.pcapng” file to answer the questions.

**Search the “r4w” string in packet details. What is the name of artist 1?**

Start by clicking _Edit_ from the Menu Bar at the top of the window. From the drop-down menu click _Find Packet…_.

![](_resources/09%20Wireshark%20-%20The%20Basics/4a72b7782e213ea72475a6a57a759a0e_MD5.jpg)

A new section will appear under the Filter bar. This is the _Find Packet_ search bar. It should already be set up to be looking for strings, which you can see in the drop-down next to the search bar. Type in the green search bar _r4w_, and either press enter or click the _Find_ button.

![](_resources/09%20Wireshark%20-%20The%20Basics/5259296406a546d011687be3c7854a29_MD5.jpg)

Give Wireshark a moment to find the string amoungst the Packet. Once it does, you should be able to see it in the Packet Detail section, highlighted in blue. As you can see we have HTML, reading over the line it states _painted by_ followed by the text `<a href=’artists.php?artist=1'>`. This is how you declaire a link in HTML, and the text that follows is the link text that the user will see. Looking at the link text we can see that it is associated with _artist 1_. So knowing this along with how HTML links are declaired, you can find the answer directly after the aforementioned text. Once you find it, type the answer into the THM answer field, then click submit.

![](_resources/09%20Wireshark%20-%20The%20Basics/16191434371e6f359a15407d51c7ee7c_MD5.jpg)

Answer: r4w8173

**Go to packet 12 and read the comments. What is the answer?**

Go back up to the top of the window and click the _Go_ tab from the Menu Bar. Then from the drop-down click the _Go to Packet…._ option.

![](_resources/09%20Wireshark%20-%20The%20Basics/30b355ab14dca39d4af6e1873028146a_MD5.jpg)

On the right side of the window, the Packet search Bar will appear. Type _12_ into the field, and either press enter or click the _Got To Packet_ button.

![](_resources/09%20Wireshark%20-%20The%20Basics/9f4a4bb1815071880df93970e17a6e37_MD5.jpg)

You will then be brought to Packet 12. At the top of the Packet Details section you can see _Packet comments._ You could click on it so see the comments, but they are not easily readable. So we will go with the other option of viewing Packet Comments. To do this, click the _Edit_ tab from the Menu bar at the top of the window. From the drop-down menu, click the _Packet Comment…_ option.

![](_resources/09%20Wireshark%20-%20The%20Basics/b324a2e9899b5f47865d848ecaab10db_MD5.jpg)

A pop up window will appear with the Packet Comments inside. As you can see _This_is_Not_a_Flag_, is written over and over again. But there is more, so scroll down to get more directions.

![](_resources/09%20Wireshark%20-%20The%20Basics/4b356e8d3325ae79080a6751f4070d5c_MD5.jpg)

Once you reach the bottom, you are greated with the next steps of how to complete this question. I ended up copying (_CTRL+C_) and pasting (_CTRL+V_) the detailed steps here in notepad so I could reference them later. But feel free to just use the screen show I have below to instead.

![](_resources/09%20Wireshark%20-%20The%20Basics/80dc9e73ace0f0fc8df3861dd3e8cf00_MD5.jpg)

First we need to go to Packet _39765_, to do this we will use the same process that we did to find Packet _12_. Go back up to the top of the window and click the _Go_ tab from the Menu Bar. Then from the drop-down click the _Go to Packet…._ option.

![](_resources/09%20Wireshark%20-%20The%20Basics/0a23a1b6193e36be75b96cee8caa5080_MD5.jpg)

On the right side of the window, the Packet search Bar will appear. Type _39765_ into the field, and either press enter or click the _Got To Packet_ button.

![](_resources/09%20Wireshark%20-%20The%20Basics/7ce04b832c43dcd4a0b93b7b0682d162_MD5.jpg)

The next steps stated _Look at the “packet details pane”. Right-click on the JPEG section and “Export packet bytes”_. Looking at the Packet Detail area, the last section is _JPEG File Interchange Format_. Right-click on this section, then click _Export Packet Bytes…_ from the drop-down menu.

![](_resources/09%20Wireshark%20-%20The%20Basics/3ae937cf123ed8c53ff78a023970189a_MD5.jpg)

A window will pop-up so that you can save/export the Packet Bytes. You can add what ever name you would like to this, but I like to make mine discriptive. So I named mine _wireshark-exported-jpeg_. After you have named the file, click the _Save_ button in the bottom right.

![](_resources/09%20Wireshark%20-%20The%20Basics/b6bb8a90f6cb1f167f8dcb0186701342_MD5.jpg)

Now use the Minimize button in the top right of the window, to minimize Wireshark.

![](_resources/09%20Wireshark%20-%20The%20Basics/53d56df066f75174702c9af8b0919c47_MD5.jpg)

On the Desktop, click one of the two _Terminal_ icons to open a terminal instance.

![](_resources/09%20Wireshark%20-%20The%20Basics/4d60e8702d2058edaac812e3b6d9d678_MD5.jpg)

When the terminal window appears, type the following command `md5sum ~/Desktop/{Name of the file you just extracted}`. So in my case the command was _md5sum ~/Desktop/wireshark-exported-jpeg_. Then press enter to run the command.

![](_resources/09%20Wireshark%20-%20The%20Basics/a74639e7f4e7a586792e701c3cedb65b_MD5.jpg)

After you have press enter and ran the command, you will see the md5 hash of the image file along with the path to the file. Highlight and copy (_CTRL+SHIFT+C_) the hash portion from the terminal. Then paste (_CTRL+V_) the hash into the THM answer field, and click submit.

![](_resources/09%20Wireshark%20-%20The%20Basics/6dcb468eb52482662701bff6162add29_MD5.jpg)

Answer: 911cd574a42865a956ccde2d04495ebf

**There is a “.txt” file inside the capture file. Find the file and read it; what is the alien’s name?**

Click the Wireshark icon on the left side of the screen to bring Wireshark back up.

![](_resources/09%20Wireshark%20-%20The%20Basics/7c6f66b9326945e36108287fd058d272_MD5.jpg)

This time we are goin to start by clicking the _File_ tab from the Menu Bar. From the drop-down, hover your cursor over the _Export Objects_ option. Another drop-down menu will appear, on this one click the _HTTP…_ option.

![](_resources/09%20Wireshark%20-%20The%20Basics/0576650bdcfb0f02755d05b14dcf282a_MD5.jpg)

A new window will pop-up for the _Export — HTTP object list_. At the bottom of the window is a _Text Filter:_ field, type _.txt_ into this field.

![](_resources/09%20Wireshark%20-%20The%20Basics/7b9bd027672d18d0797980fc61d5900c_MD5.jpg)

It should automatically filter out everything except what matches the filter. You should only have one result, click on the packet and then click the _Save_ button.

![](_resources/09%20Wireshark%20-%20The%20Basics/7babc4bb2299c4e910f3c9aa2b7d4999_MD5.jpg)

The _Save Object As…_ pop-up window will appear. First click _Desktop_ from the quick menu on the left side of the window. From there click the _Save_ button at the bottom right.

![](_resources/09%20Wireshark%20-%20The%20Basics/e77118a7aad76f9beebc276c23f2f9e6_MD5.jpg)

Now use the Minimize button in the top right of the window, to minimize Wireshark.

![](_resources/09%20Wireshark%20-%20The%20Basics/53d56df066f75174702c9af8b0919c47_MD5.jpg)

On the Desktop you will now see the _note.txt_ file. Double-click the file to open it.

![](_resources/09%20Wireshark%20-%20The%20Basics/ca369ff048784a69ee25ad95b670213b_MD5.jpg)

When the file opens you are greeted by this lovely ASCII art Alien head. Scroll down to find out the Aliens name.

![](_resources/09%20Wireshark%20-%20The%20Basics/20b9109cfc0a6fe931cdd7396ca8ed3a_MD5.jpg)

Once you scroll down far enough you will see the Aliens name in giant ASCII art letters. Type what you find into the THM answer field, and click submit.

![](_resources/09%20Wireshark%20-%20The%20Basics/71559c24fe5a4689f1d04626e45e42d5_MD5.jpg)

Answer: Packetmaster

**Look at the expert info section. What is the number of warnings?**

Click the Wireshark icon on the left side of the screen to bring Wireshark back up.

![](_resources/09%20Wireshark%20-%20The%20Basics/7c6f66b9326945e36108287fd058d272_MD5.jpg)

Finally for this task, click on the _Analyze_ tab from the Menu bar. In the drop-down click on _Expert Information_.

![](_resources/09%20Wireshark%20-%20The%20Basics/db6535adfa42be9ee197266c0b6f35e2_MD5.jpg)

The _Expert Information_ window will pop-up. Look for the color _yellow_ or the severity of _Warning._ Once you find it, follow the row all the way to the right. You will see the number of _Warning_s, and thus the answer to this question. Type the answer into the THM answer field, and click submit.

![](_resources/09%20Wireshark%20-%20The%20Basics/ded1266fec763b52a7702d106dfd979c_MD5.jpg)

Answer: 1636

# Task 5 Packet Filtering

## Packet Filtering

Wireshark has a powerful filter engine that helps analysts to narrow down the traffic and focus on the event of interest. Wireshark has two types of filtering approaches: capture and display filters. Capture filters are used for **“capturing”** only the packets valid for the used filter. Display filters are used for **“viewing”** the packets valid for the used filter. We will discuss these filters’ differences and advanced usage in the next room. Now let’s focus on basic usage of the display filters, which will help analysts in the first place.

Filters are specific queries designed for protocols available in Wireshark’s official protocol reference. While the filters are only the option to investigate the event of interest, there are two different ways to filter traffic and remove the noise from the capture file. The first one uses queries, and the second uses the right-click menu. Wireshark provides a powerful GUI, and there is a golden rule for analysts who don’t want to write queries for basic tasks: **“If you can click on it, you can filter and copy it”**.

## Apply as Filter

This is the most basic way of filtering traffic. While investigating a capture file, you can click on the field you want to filter and use the “right-click menu” or **“Analyse → Apply as Filter”** menu to filter the specific value. Once you apply the filter, Wireshark will generate the required filter query, apply it, show the packets according to your choice, and hide the unselected packets from the packet list pane. Note that the number of total and displayed packets are always shown on the status bar.

![](_resources/09%20Wireshark%20-%20The%20Basics/b8e576c019f137d7d5a429f67514ae14_MD5.jpg)

## Conversation filter

When you use the “Apply as a Filter” option, you will filter only a single entity of the packet. This option is a good way of investigating a particular value in packets. However, suppose you want to investigate a specific packet number and all linked packets by focusing on IP addresses and port numbers. In that case, the “Conversation Filter” option helps you view only the related packets and hide the rest of the packets easily. You can use the”right-click menu” or “**Analyse → Conversation Filter**” menu to filter conversations.

![](_resources/09%20Wireshark%20-%20The%20Basics/fc150fc3ebacac5c9275963ccfb823f9_MD5.jpg)

## Colourise Conversation

This option is similar to the “Conversation Filter” with one difference. It highlights the linked packets without applying a display filter and decreasing the number of viewed packets. This option works with the “Colouring Rules” option ad changes the packet colours without considering the previously applied colour rule. You can use the “right-click menu” or **“View → Colourise Conversation”** menu to colourise a linked packet in a single click. Note that you can use the **“View → Colourise Conversation → Reset Colourisation”** menu to undo this operation.

![](_resources/09%20Wireshark%20-%20The%20Basics/306eeb0f4ec4a1b6b78b2406a4cd99ac_MD5.jpg)

## Prepare as Filter

Similar to “Apply as Filter”, this option helps analysts create display filters using the “right-click” menu. However, unlike the previous one, this model doesn’t apply the filters after the choice. It adds the required query to the pane and waits for the execution command (enter) or another chosen filtering option by using the **“.. and/or..”** from the “right-click menu”.

![](_resources/09%20Wireshark%20-%20The%20Basics/3a423baf49a5f6de227535ab8b6b83b6_MD5.jpg)

## Apply as Column

By default, the packet list pane provides basic information about each packet. You can use the “right-click menu” or **“Analyse → Apply as Column”** menu to add columns to the packet list pane. Once you click on a value and apply it as a column, it will be visible on the packet list pane. This function helps analysts examine the appearance of a specific value/field across the available packets in the capture file. You can enable/disable the columns shown in the packet list pane by clicking on the top of the packet list pane.

![](_resources/09%20Wireshark%20-%20The%20Basics/d14e7a7a504783bfab7ab015d3d07ebd_MD5.jpg)

## Follow Stream

Wireshark displays everything in packet portion size. However, it is possible to reconstruct the streams and view the raw traffic as it is presented at the application level. Following the protocol, streams help analysts recreate the application-level data and understand the event of interest. It is also possible to view the unencrypted protocol data like usernames, passwords and other transferred data.

You can use the”right-click menu” or **“Analyse → Follow TCP/UDP/HTTP Stream”** menu to follow traffic streams. Streams are shown in a separate dialogue box; packets originating from the server are highlighted with blue, and those originating from the client are highlighted with red.

![](_resources/09%20Wireshark%20-%20The%20Basics/1798977d3852b42f56c4abffd71ad66a_MD5.jpg)

Once you follow a stream, Wireshark automatically creates and applies the required filter to view the specific stream. Remember, once a filter is applied, the number of the viewed packets will change. You will need to use the “**X** **button**” located on the right upper side of the display filter bar to remove the display filter and view all available packets in the capture file.

### Answer the questions below

Use the “Exercise.pcapng” file to answer the questions.

**Go to packet number 4. Right-click on the “Hypertext Transfer Protocol” and apply it as a filter. Now, look at the filter pane. What is the filter query?**

Start by clicking on Packet 4 (which should be the fourth packet from the top).

![](_resources/09%20Wireshark%20-%20The%20Basics/da681d62d19c45c42394a39565a84e41_MD5.jpg)

Move down to the Packet Detail section, right-click on _Hypertext Transfer Protocol._ On the drop-down at appears hover over _Apply as Filter_. Another drop-down will appear, move the cursor over to this new menu can click on _Selected_.

![](_resources/09%20Wireshark%20-%20The%20Basics/7356032cd7db8fd05fd7e885e65886fa_MD5.jpg)

After you have clicked _Selected_, look at the Filter Bar. You will see the Filter that you just applied, and the answer to this question. Type the anser into the THM answer field, and click submit.

![](_resources/09%20Wireshark%20-%20The%20Basics/2d5b7c4d75f66d1291f2a0ee4e4844d5_MD5.jpg)

Answer: http

**What is the number of displayed packets?**

You can easily find this answer in the bottom right of the Wireshark window. Look for _Displayed_, and the number to the right is the answer. Type the anser into the THM answer field, and click submit.

![](_resources/09%20Wireshark%20-%20The%20Basics/37c72ef15998916de916e22083f20767_MD5.jpg)

Answer: 1089

**Go to packet number 33790 and follow the stream. What is the total number of artists?**

As we did before in the previous task, click on the _Go_ tab from the Menu bar at the top of the Window. A drop-down will appear, click _Go to Packet…_

![](_resources/09%20Wireshark%20-%20The%20Basics/83436a35ae653e496edf6cc45099f1be_MD5.jpg)

On the right side of the window, the Packet search Bar will appear. Type _33790_ into the field, and press enter or click the _Got To Packet_ button.

![](_resources/09%20Wireshark%20-%20The%20Basics/cfac9e60ff906c52ecfd2b4b4c0b5f34_MD5.jpg)

Packet _33790_ should now be selected, right-click on this Packet. On the drop-down menu, hover your cursor over _Follow_. When the new drop-down menu appears, click on _HTTP Stream_.

![](_resources/09%20Wireshark%20-%20The%20Basics/99c38b40a90a344a3ed234f990922f74_MD5.jpg)

When the _Follow HTTP Stream_ window pops-up, look to the bottom of said window for the _Find_ bar. As we learned from the previous task, the way that page is set up we can search for _artist=_. So type _artist=_ into the _Find_ bar, then click the _Find Next_ button.

![](_resources/09%20Wireshark%20-%20The%20Basics/f26ff3675c370ef12b739626453e0cac_MD5.jpg)

The first hit is for _artist=1_, so continue to click _Find Next_ until we don’t see this pattern or it starts over.

![](_resources/09%20Wireshark%20-%20The%20Basics/adbd24fe8056e17c0e60850f6f65effd_MD5.jpg)

After repeating the process a couple of time, you should be able to find the answer. Once you find it, type it into the THM answer field, and click submit.

![](_resources/09%20Wireshark%20-%20The%20Basics/fa97922e0fb5b9f70062fda08a03428e_MD5.jpg)

Answer: 3

**What is the name of the second artist?**

Going back to the _Follow HTTP Stream_ window, look for _artist=2_. The name to the right of this, after the `<h3>`, is the answer. Type the anser into the THM answer field, and click submit.

![](_resources/09%20Wireshark%20-%20The%20Basics/a5fa723cb31769ec79eb47950355c454_MD5.jpg)

Answer: Blad3

# Task 6 Conclusion

**Congratulations!** You just finished the “Wireshark: The Basics” room. In this room, we covered Wireshark, what it is, how it operates, and how to use it to investigate traffic captures.

Want to learn more? We invite you to complete the [**Wireshark: Packet Operations**](https://tryhackme.com/jr/wiresharkpacketoperations) room to improve your Wireshark skills by investigating packets in-depth.

