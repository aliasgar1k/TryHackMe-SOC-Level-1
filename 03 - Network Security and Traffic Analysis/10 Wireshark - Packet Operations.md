https://www.youtube.com/watch?v=89WiZqBEq-I
https://www.youtube.com/watch?v=x7EJSY0bOK4

https://medium.com/@haircutfish/wireshark-packet-operations-task-1-introduction-task-2-statistics-summary-139bf7d786f7
https://medium.com/@haircutfish/wireshark-packet-operations-task-3-statistics-protocol-details-task-4-packet-filtering-48e7403b8d02
https://medium.com/@haircutfish/tryhackme-wireshark-packet-operations-task-6-advanced-filtering-task-7-conclusion-433cf82227a1

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/aa7d6779c033e234361df35e4a77556b_MD5.jpg)

# Task 1 Introduction

In this room, we will cover the fundamentals of packet analysis with Wireshark and investigate the event of interest at the packet-level. Note that this is the second room of the Wireshark room trio, and it is suggested to visit the first room ([**Wireshark: The Basics**](https://tryhackme.com/room/wiresharkthebasics)) to practice and refresh your Wireshark skills before starting this one.

In the first room, we covered the basics of the Wireshark by focusing on how it operates and how to use it to investigate traffic captures. In this room, we will cover advanced features of the Wireshark by focusing on packet-level details with Wireshark statistics, filters, operators and functions.

**Note:** A VM is attached to this room. You don’t need SSH or RDP; the room provides a “Split View” feature. Access to the machine will be provided in-browser and will deploy in Split View mode in your browser. If you don’t see it, use the blue Show Split View button at the top right of this room page to show it. **DO NOT** directly interact with any domains and IP addresses in this room. The domains and IP addresses are included for reference reasons only.

# Task 2 Statistics | Summary

## Statistics

This menu provides multiple statistics options ready to investigate to help users see the big picture in terms of the scope of the traffic, available protocols, endpoints and conversations, and some protocol-specific details like DHCP, DNS and HTTP/2. For a security analyst, it is crucial to know how to utilise the statical information. This section provides a quick summary of the processed pcap, which will help analysts create a hypothesis for an investigation. You can use the **“Statistics”** menu to view all available options. Now start the given VM, open the Wireshark, load the “Exercise.pcapng” file and go through the walkthrough.

## Resolved Addresses

This option helps analysts identify IP addresses and DNS names available in the capture file by providing the list of the resolved addresses and their hostnames. Note that the hostname information is taken from DNS answers in the capture file. Analysts can quickly identify the accessed resources by using this menu. Thus they can spot accessed resources and evaluate them according to the event of interest. You can use the **“Statistics → Resolved Addresses”** menu to view all resolved addresses by Wireshark.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/8b7f2ebbd5353aae954a54fffe566a60_MD5.jpg)

## Protocol Hierarchy

This option breaks down all available protocols from the capture file and helps analysts view the protocols in a tree view based on packet counters and percentages. Thus analysts can view the overall usage of the ports and services and focus on the event of interest. The golden rule mentioned in the previous room is valid in this section; you can right-click and filter the event of interest. You can use the **“Statistics → Protocol Hierarchy”** menu to view this info.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/1646f1e62fbbea98e56f954c20deef58_MD5.jpg)

## Conversations

Conversation represents traffic between two specific endpoints. This option provides the list of the conversations in five base formats; ethernet, IPv4, IPv6, TCP and UDP. Thus analysts can identify all conversations and contact endpoints for the event of interest. You can use the **“Statistic → Conversations”** menu to view this info.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/59ae9c0289b7be77ffca1677713fffa0_MD5.jpg)

## Endpoints

The endpoints option is similar to the conversations option. The only difference is that this option provides unique information for a single information field (Ethernet, IPv4, IPv6, TCP and UDP ). Thus analysts can identify the unique endpoints in the capture file and use it for the event of interest. You can use the **“Statistics → Endpoints”** menu to view this info.

Wireshark also supports resolving MAC addresses to human-readable format using the manufacturer name assigned by IEEE. Note that this conversion is done through the first three bytes of the MAC address and only works for the known manufacturers. When you review the ethernet endpoints, you can activate this option with the **“Name resolution”** button in the lower-left corner of the endpoints window.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/614e36b351dca2c8b2c51ec30cee4634_MD5.jpg)

Name resolution is not limited only to MAC addresses. Wireshark provides IP and port name resolution options as well. However, these options are not enabled by default. If you want to use these functionalities, you need to activate them through the **“Edit → Preferences → Name Resolution”** menu. Once you enable IP and port name resolution, you will see the resolved IP address and port names in the packet list pane and also will be able to view resolved names in the “Conversations” and “Endpoints” menus as well.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/0d128ac90c1d0934eba6250b25c8e938_MD5.jpg)

Endpoint menu view with name resolution:

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/afe177d291247e8dcc56c10dda31da78_MD5.jpg)

Besides name resolution, Wireshark also provides an IP geolocation mapping that helps analysts identify the map’s source and destination addresses. But this feature is not activated by default and needs supplementary data like the GeoIP database. Currently, Wireshark supports MaxMind databases, and the latest versions of the Wireshark come configured MaxMind DB resolver. However, you still need MaxMind DB files and provide the database path to Wireshark by using the **“Edit → Preferences → Name Resolution → MaxMind database directories”** menu. Once you download and indicate the path, Wireshark will automatically provide GeoIP information under the IP protocol details for the matched IP addresses.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/74c415711e166302ce81b46abb883f35_MD5.jpg)

Endpoints and GeoIP view.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/bf7986e1bca496960d45586210b5b1f0_MD5.jpg)

**_Note: You need an active internet connection to view the GeoIP map. The lab machine doesn’t have an active internet connection!_**

### Answer the questions below

**Investigate the resolved addresses. What is the IP address of the hostname starts with “bbc”?**

At the top of the Wireshark window, click on _Statistics_ from the menu bar. In the drop-down, click on _Resolved Addresses._

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/ed2975dafc9cc43602f1cb9bec2445b8_MD5.jpg)

The _Wireshark — Resolved Addresses_ window will pop-up. At the top of this window is a search field labeled _Search for entry (min 3 characters)._ Type _bbc_ into this search field.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/ab2b745e5648d66db19ed6c4efd42398_MD5.jpg)

After you have typed _bbc_ into the search field. It will auto filter any matches. There should be only one Hostname that matches to the query. The address that was resolved from this Hostname is the answer to the question. You can click on the _IP Address_, and use copy (_CTRL+C)._ Then paste (_CTRL+V_) the answer into the THM answer field, and click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/b10f5169f9a2d59801c16918f5993ae9_MD5.jpg)

Answer: 199.232.24.81

**What is the number of IPv4 conversations?**

Go back up to the Menu bar and click _Statistics_ again. This time click on the _Conversations_ option from the drop-down menu.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/e85c24060800f5d227427b8b9ea4e133_MD5.jpg)

The _Conversations_ window will pop-up. You can see the different tabs at the top of this window. The tab that pertains to this question is the _IPv4_ tab. Look at the number on this tab, this is the answer to this question. Type it into the answer field on THM, and then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/3a10e3ee5dcf2c51b51e1d0ed239fa24_MD5.jpg)

Answer: 435

**How many bytes (k) were transferred from the “Micro-St” MAC address?**

Once again, head back up to the menu bar and click _Statistics_. On the drop-down menu click _Endpoints_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/151f418dcaf0dc2826d2c4d8da3691b9_MD5.jpg)

The _Endpoints_ window will pop-up. Look at the bottom left of the window. Click the checkbox next to _Name Resolution_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/63664b44a5e1192113a7e81885695ec5_MD5.jpg)

After checking the _Name Resolution_ checkbox, the MAC address will now display the resolved Name. Looking down through the list, you need to find the name _Micro-St_. Once you find it look across the row till you get to the _Bytes_ column, displaying the amount of _Bytes_ that were transferred from that Name/MAC Address. Once you have found the answer, type it into the THM answer field, then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/2831de0a0121f39819ce7dfc81ea5302_MD5.jpg)

Answer: 7474

**What is the number of IP addresses linked with “Kansas City”?**

You are going to stick with the _Endpoints_ window for this question. Going back to it, you will want to click on the tab labeled _IPv4_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/419b21c8a545e3753b7d9f24bcf690d6_MD5.jpg)

You will now be presented with the IPv4 Endpoints from the pcapng file in the table format. Look for the column labeled _City_, and click on it to alphabitize them.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/8f51f6e705fe91e8fae44d3b6a41dde3_MD5.jpg)

Scroll down till you find _Kansas City_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/9c7d997bd8ea30421d35e55f4ce98aa6_MD5.jpg)

Once you have found it, count the number of times it appears and you will have your answer. Type your answer into the THM answer field, and then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/dccc3cd7caf4ebb45c865f8c06a93163_MD5.jpg)

Answer: 4

**Which IP address is linked with “Blicnet” AS Organisation?**

One last time, head back to the _Endpoints_ window. This time you are going to want to scroll to the right until you see the column _As Organization._

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/4a7dd1c6cd990369af6e2ac77172fd5b_MD5.jpg)

Like before, when you find the column _As Organization._ Click on it to alphabatize it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/be9e6cfe13a19d903836a6054c2eba09_MD5.jpg)

Scroll up till you see _Blicnet_ in the _As Organization column._

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/ee83a402ed7dcd6dd0a150aca26f6a3b_MD5.jpg)

When you find it, click on the row to highlight it. Then scroll to the left till you see the _Address_ column.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/851b169bc09d24743bdfe2f71ba5c71d_MD5.jpg)

Once you reach the _Address_ column, you will see the IPv4 address associated with _Blicnet_ and thus the answer. Type it into the THM answer field, and then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/42c74e7118ea473b67ed010a4a7ee227_MD5.jpg)

Answer: 188.246.82.7

# Task 3 Statistics | Protocol Details

## IPv4 and IPv6

Up to here, almost all options provided information that contained both versions of the IP addresses. The statistics menu has two options for narrowing the statistics on packets containing a specific IP version. Thus, analysts can identify and list all events linked to specific IP versions in a single window and use it for the event of interest. You can use the **“Statistics → IPvX Statistics”** menu to view this info.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/27f93dc3988b17363afbdc1b0fe595c4_MD5.jpg)

## DNS

This option breaks down all DNS packets from the capture file and helps analysts view the findings in a tree view based on packet counters and percentages of the DNS protocol. Thus analysts can view the DNS service’s overall usage, including rcode, opcode, class, query type, service and query stats and use it for the event of interest. You can use the **“Statistics → DNS”** menu to view this info.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/48bd823b0a0adcf8d2c5f624bd94cbcc_MD5.jpg)

## HTTP

This option breaks down all HTTP packets from the capture file and helps analysts view the findings in a tree view based on packet counters and percentages of the HTTP protocol. Thus analysts can view the HTTP service’s overall usage, including request and response codes and the original requests. You can use the **“Statistics → HTTP”** menu to view this info.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/7fa41067b6e26a328e5efefc3283797c_MD5.jpg)

### Answer the questions below

**What is the most used IPv4 destination address?**

At the top of the Wireshark window, click on _Statistics_ from the menu bar. In the drop-down, move your cursor down to _IPv4 Statistics_. Once you hover your cursor over _IPv4 Statistics_, another drop-down will appear. Move your cursor over to this new drop-down and click on _Destinations and Ports_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/5accbfe8db1bce4f3780a0f6f60cf3af_MD5.jpg)

The _Destinations and Ports_ window will pop-up. Give Wireshark a moment to finish calculating. Once it has finished, look at the column names at the top. You are looking for the column labeled _Count_. When you find it click on it twice to orginize the table from highest count to lowest count.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/3d7bc3e901f499624bc307c8c575e447_MD5.jpg)

The IPv4 address at the top of the list is theDestination IPv4 address that appears the most in the pcapng file. This also is the answer to the question. Type the answer in the THM answer field, and then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/398642b184c0ddd52f450cb6d3c3ddb8_MD5.jpg)

Answer: 10.100.1.33

**What is the max service request-response time of the DNS packets?**

Heading back up to the top of the window, and click the _Statistics_ tab. On the drop-down click the _DNS_ option.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/fb2d9e19ab0b5684b8077801a2a43efb_MD5.jpg)

When the _DNS_ window pops-up, look down the first column till you see _request-response time (secs)_. Move to the right on the row, till you reach the column _Max Val_. The number in this column is the answer to the question. Type the answer in the THM answer field, and then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/39ca9c3c540a645cd10cdd551d265029_MD5.jpg)

Answer: 0.467897

**What is the number of HTTP Requests accomplished by “rad[.]msn[.]com?**

Heading back up to the top of the window, and click the _Statistics_ tab. On the drop-down hover over the _HTTP_ option. On the new drop-down menu, click the _Requests_ option.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/f3e8d23d3a6d14f9227e2c377e23c005_MD5.jpg)

When the _Requests_ pop-up window loads, scroll down till you see _rad.msn.com_.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/080a6fe659ed38e52d5e48e45ca88776_MD5.jpg)

Once you find it, scroll to the right of the row till you reach the next column.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/8aa7af520b247a647b6f1ff2f6d60a79_MD5.jpg)

When you reach the next column, it is labeled _Count_. The number you find in this column is the answer to the question. Type the answer in the THM answer field, and then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/4db98bd5b40efb55754b9074dc6182f8_MD5.jpg)

Answer: 39

# Task 4 Packet Filtering | Principles

## Packet Filtering

In the previous room ([**Wireshark | The Basics**](https://tryhackme.com/room/wiresharkthebasics)), we covered packet filtering and how to filter packets without using queries. In this room, we will use queries to filter packets. As mentioned earlier, there are two types of filters in Wireshark. While both use similar syntax, they are used for different purposes. Let’s remember the difference between these two categories.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/134ffa39f452542394e70e77fce42224_MD5.jpg)

**Note:** You cannot use the display filter expressions for capturing traffic and vice versa.

The typical use case is capturing everything and filtering the packets according to the event of interest. Only experienced professionals use capture filters and sniff traffic. This is why Wireshark supports more protocol types in display filters. Please ensure you thoroughly learn how to use capture filters before using them in a live environment. Remember, you cannot capture the event of interest if your capture filter is not matching the specific traffic pattern you are looking for.

## Capture Filter Syntax

These filters use byte offsets hex values and masks with boolean operators, and it is not easy to understand/predict the filter’s purpose at first glance. The base syntax is explained below:

- **Scope:** host, net, port and portrange.
- **Direction:** src, dst, src or dst, src and dst,
- **Protocol:** ether, wlan, ip, ip6, arp, rarp, tcp and udp.
- **Sample filter to capture port 80 traffic:** `tcp port 80`

You can read more on capture filter syntax from [here](https://www.wireshark.org/docs/man-pages/pcap-filter.html) and [here](https://gitlab.com/wireshark/wireshark/-/wikis/CaptureFilters#useful-filters). A quick reference is available under the **“Capture → Capture Filters”** menu.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/935ab375654a1ac152e1da353dc29da0_MD5.jpg)

## Display Filter Syntax

This is Wireshark’s most powerful feature. It supports 3000 protocols and allows conducting packet-level searches under the protocol breakdown. The official “[Display Filter Reference](https://www.wireshark.org/docs/dfref/)” provides all supported protocols breakdown for filtering.

- **Sample filter to capture port 80 traffic:** `tcp.port == 80`

Wireshark has a built-in option (Display Filter Expression) that stores all supported protocol structures to help analysts create display filters. We will cover the “Display Filter Expression” menu later. Now let’s understand the fundamentals of the display filter operations. A quick reference is available under the **“Analyse → Display Filters”** menu.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/ca6bd65cc7afa6ce3a6db15df5b1b8c0_MD5.jpg)

## Comparison Operators

You can create display filters by using different comparison operators to find the event of interest. The primary operators are shown in the table below.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/75187b9d9387dce37359c4c3faadad8b_MD5.jpg)

**Note:** Wireshark supports decimal and hexadecimal values in filtering. You can use any format you want according to the search you will conduct.

## Logical Expressions

Wireshark supports boolean syntax. You can create display filters by using logical operators as well.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/6905f5b8c539828df78c7f0f44a7baed_MD5.jpg)

## Packet Filter Toolbar

The filter toolbar is where you create and apply your display filters. It is a smart toolbar that helps you create valid display filters with ease. Before starting to filter packets, here are a few tips:

- Packet filters are defined in lowercase.
- Packet filters have an autocomplete feature to break down protocol details, and each detail is represented by a “dot”.
- Packet filters have a three-colour representation explained below.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/2dece1076e27b9e7aa6be54e4f6c040c_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/304a88c794203e38ba6889c2be1b9206_MD5.jpg)

Filter toolbar features are shown below.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/e56d4464508b6796f42d3570d83684a6_MD5.jpg)

We’ve covered lots of principles and syntax. Let’s put these into practice and start filtering packets in the next task.

# Task 5 Packet Filtering | Protocol Filters

## Protocol Filters

As mentioned in the previous task, Wireshark supports 3000 protocols and allows packet-level investigation by filtering the protocol fields. This task shows the creation and usage of filters against different protocol fields.

## IP Filters

IP filters help analysts filter the traffic according to the IP level information from the packets (Network layer of the OSI model). This is one of the most commonly used filters in Wireshark. These filters filter network-level information like IP addresses, version, time to live, type of service, flags, and checksum values.

The common filters are shown in the given table.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/2a324af626ab61345741bb4cb5ddca95_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/f57243c1de022abb200e83d38a741b7e_MD5.jpg)

## TCP and UDP Filters

TCP filters help analysts filter the traffic according to protocol-level information from the packets (Transport layer of the OSI model). These filters filter transport protocol level information like source and destination ports, sequence number, acknowledgement number, windows size, timestamps, flags, length and protocol errors.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/865f1f14987837072d4deb7f5520dc26_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/51a64eab7e5196ad50fb833c704cdd2e_MD5.jpg)

## Application Level Protocol Filters | HTTP and DNS

Application-level protocol filters help analysts filter the traffic according to application protocol level information from the packets (Application layer of the OSI model ). These filters filter application-specific information, like payload and linked data, depending on the protocol type.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/6586c011de710fca1882ece7029dcbb1_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/6dbe48b22c76b32e342bcb980885c692_MD5.jpg)

## Display Filter Expressions

As mentioned earlier, Wireshark has a built-in option (Display Filter Expression) that stores all supported protocol structures to help analysts create display filters. When an analyst can’t recall the required filter for a specific protocol or is unsure about the assignable values for a filter, the Display Filter Expressions menu provides an easy-to-use display filter builder guide. It is available under the **“Analyse → Display Filter Expression”** menu.

It is impossible to memorise all details of the display filters for each protocol. Each protocol can have different fields and can accept various types of values. The Display Filter Expressions menu shows all protocol fields, accepted value types (integer or string) and predefined values (if any). Note that it will take time and require practice to master creating filters and learning the protocol filter fields.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/abcc550108b0d14815c118aa6672edc5_MD5.jpg)

**Note:** The [**first room**](https://tryhackme.com/room/wiresharkthebasics) introduced the “Colouring Rules” (Task-2). Now you know how to create display filters and filter the event of interest. You can use the **“View → Coloring Rules”** menu to assign colours to highlight your display filter results.

### Answer the questions below

**What is the number of IP packets?**

Starting at the _Filter Bar_, type in `ip` and press enter. It will filter pretty quickly. Look at the bottom right of the Wireshark window. You are looking for the word _Displayed:_. The numbers to the right of _Displayed_, is the answer. Type the answer in the THM answer field, and then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/349af2b37312c33a0df949a9b1d15892_MD5.jpg)

Answer: 81420

**What is the number of packets with a “TTL value less than 10”?**

Going back to the _Filter Bar_, this time we are looking for _TTL_. Keeping with the same filter we just in the previous question, we are going to add onto it. The filter will be `ip.ttl <10`, and will look for IPv4 address that have a time to live of less than 10. After you have entered in this filter, press enter to use it. You should only have the Packets that match the filter remaining. Again, go back down to _Displayed_ in the bottom right of the Wireshark window. The number to the right is the answer to this question. Type the answer in the THM answer field, and then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/1d01b4fce7d1563b91160bd03dd7ddfb_MD5.jpg)

Answer: 66

**What is the number of packets which uses “TCP port 4444”?**

Going back to the _Filter Bar_, this time we are looking for Packets that use _TCP over port 4444_. So the filter you want to use is pretty straight forward. It is `tcp.port == 4444`, type this into the _Filter Bar_ and press enter. Again, go back down to _Displayed_ in the bottom right of the Wireshark window. The number to the right is the answer to this question. Type the answer in the THM answer field, and then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/455c82604c617d6a6db3f38311212249_MD5.jpg)

Answer: 632

**What is the number of “HTTP GET” requests sent to port “80”?**

Going back to the _Filter Bar_, this time we are looking for Packets that are making _HTTP GET Requests over port 80._ This one has a little more to it but it isn’t difficult if you build it using what is givin and know of HTTP requests. Let’s start with the HTTP request part, THM gave it to us in the question with `http.request` _._ From there we know from the question that we are looking for _GET_, which is the method of the HTTP request. So we can add method to our filter, so it is now `http.request.method == GET`. Now we have to add port 80, taking a queue from the previous question, we would need `tcp.port == 80`. Finally to combine these and search for both adding an `and`. So the final filter is now `http.reqeust.method == GET and tcp.port == 80`. Now that you have put the filter into the _Filter Bar,_ press enter to use the filter. Again, go back down to _Displayed_ in the bottom right of the Wireshark window. The number to the right is the answer to this question. Type the answer in the THM answer field, and then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/e101ae1783c28c5bea5bca1dae69408d_MD5.jpg)

Answer: 527

**What is the number of “type A DNS Queries”?**

Last time going back to the _Filter Bar_, this time we are looking for Packets that are making _DNS Queries_, but only for _type A_. It sounds like this one is going to be complicated, but it’s quiet simple. Start typing in the _Filter Bar,_ `dns.`. The first entry in the drop down menu looks like exactly what we are looking for.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/83e1deafaebe0f4220f606f146bd8ac9_MD5.jpg)

Either finish typing or click on the entry in the drop down menu. So that the filter should be `dns.a`. Press enter to use the filter. For the last time in this room, go back down to _Displayed_ in the bottom right of the Wireshark window. The number to the right is the answer to this question. Type the answer in the THM answer field, and then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/262adf6e371d94f47f19af56cc0709e6_MD5.jpg)

Answer: 51

# Task 6 Advanced Filtering

So far, you have learned the basics of packet filtering operations. Now it is time to focus on specific packet details for the event of interest. Besides the operators and expressions covered in the previous room, Wireshark has advanced operators and functions. These advanced filtering options help the analyst conduct an in-depth analysis of an event of interest.

## Filter: "contains"

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/058170230295b90b022c33d4e00aae48_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/91af3d9fdaaafb75e7fc0fbc91d47d92_MD5.jpg)

## Filter: "matches"

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/4d9131ed6b0670da323e373f9c98ccec_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/4ca9859d15fc2641e424b311c26c875e_MD5.jpg)

## Filter: "in"

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/d0e8045ec072875ebeec70531109d2a0_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/c20eaf2778af240042379823e5e25373_MD5.jpg)

## Filter: "upper"

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/149f3f5723baed65b9e57dcd3e575378_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/85c00e137b1510696d599192c3029fb4_MD5.jpg)

## Filter: "lower"

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/85fcd752c5dbf23b7a2e7cae32d3e267_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/f8e7a2fc31c9c8394cf3e4897b1f0c45_MD5.jpg)

## Filter: "string"

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/225f5211e0632d0249d565c00a082191_MD5.jpg)

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/7a5cf30961722829bffab583e870a3d7_MD5.jpg)

## Bookmarks and Filtering Buttons

We’ve covered different types of filtering options, operators and functions. It is time to create filters and save them as bookmarks and buttons for later usage. As mentioned in the previous task, the filter toolbar has a filter bookmark section to save user-created filters, which helps analysts re-use favourite/complex filters with a couple of clicks. Similar to bookmarks, you can create filter buttons ready to apply with a single click.

Creating and using bookmarks.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/1ecbd630878366c40fa35ae78d232407_MD5.jpg)

Creating and using display filter buttons.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/5826e69197751fae639dc93fbc1d9231_MD5.jpg)

## Profiles

Wireshark is a multifunctional tool that helps analysts to accomplish in-depth packet analysis. As we covered during the room, multiple preferences need to be configured to analyse a specific event of interest. It is cumbersome to re-change the configuration for each investigation case, which requires a different set of colouring rules and filtering buttons. This is where Wireshark profiles come into play. You can create multiple profiles for different investigation cases and use them accordingly. You can use the **“Edit → Configuration Profiles”** menu or the **“lower right bottom of the status bar → Profile”** section to create, modify and change the profile configuration.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/85c80780d50d56633eb7ce3066557e19_MD5.jpg)

### Answer the questions below

**Find all Microsoft IIS servers. What is the number of packets that did not originate from “port 80”?**

To start this one I needed a quick refresher on how to do _is not_, in the Wireshark filters. To do this go to the Menu bar at the top of the Wireshark and click _Analyze_. From the drop-down menu, click _Display filters…_

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/0763265e3d13f92ad1c8e217f77a4977_MD5.jpg)

The window will pop-up for _Display Filters_. Looking through the differnt examples we can find 3 examples of how to add an _is not_ type expression to the filter. We also find one that is not so good, but will work. Knowing how to craft our filter now, click the _OK_ button in the bottom right of the window to close it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/094c0282979b6f13304e02856742bacd_MD5.jpg)

Click on the mint green _Filter Bar,_ time to craft our filter! From the question, we know we are looking for a _Microsoft IIS Server_. Reading back over the _Contains_ filter section, we should know how to craft the first part of this filter. Since it is a server we are looking for, we want to use the syntax `http.server`. Followed by what this section should _contain_, `contains "Microsoft"`. Great we have the first part of our filter, time to build the second. If we remember from the _Display Filters_ window, to filter if something _is not_ in a packet we use `!(_place command here_)`. So filtering out any that use port 80 the syntax would be `!(tcp.port == 80)`. The full filter will be `http.server contains "Microsoft" and !(tcp.port == 80)`, then press enter to use this filter on the pcapng.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/03b73072d93ec34a4bd4079a4c973fb7_MD5.jpg)

Look at the bottom right of the Wireshark window. You are looking for the word _Displayed:_. The numbers to the right of _Displayed_, is the answer. Type the answer in the THM answer field, and then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/91cc55b907e7c1ff8b28a06c89d52ad3_MD5.jpg)

Answer: 21

**Find all Microsoft IIS servers. What is the number of packets that have “version 7.5”?**

We need to first find out where the version number is displayed. To do this look in the Packet Detail section. If you look at _Server_, you will see _Microsoft — IIS_. After which you will see a number, this is the version of Microsoft IIS. Now we know where the version number is, let’s go make a filter.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/31e82399052c0f091e38b3016e38ce05_MD5.jpg)

Click on the mint green _Filter Bar,_ time to craft our filter! Since we are still looking for the _Microsoft-IIS_ server, we can keep the first part of the filter. Additionally, since the we know that the version number is on the same line as type of server (_Microsoft-IIS)._ We can craft the filter to reflect that. So the filter should be `http.server contains “Microsoft” and http.server contains “7.5”`. Now press enter to use this filter on the pcapng.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/5e8566ebada2d69d0fcbd1dafb39f1a8_MD5.jpg)

Look at the bottom right of the Wireshark window. You are looking for the word _Displayed:_. The numbers to the right of _Displayed_, is the answer. Type the answer in the THM answer field, and then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/13010e15de00b07ae978aa77031c7a0a_MD5.jpg)

Answer: 71

**What is the total number of packets that use ports 3333, 4444 or 9999?**

Click on the mint green _Filter Bar,_ time to craft our filter! Since we are looking for ports, we want to start off the filter with `tcp.port`. Along with `in` since we are looking for a range of port numbers. Finally finishing off with the port numbers that need to be in `{}` (curly brackets) to signify the ports, `{3333 4444 9999}`. Side note, these ports are used since attackers commonly use these ports in metasploitable and other reverse shells. So the finally filter should be `tcp.port in {3333 4444 9999}`. Now press enter to use this filter on the pcapng.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/714621fc2d1be4bc56e2f2b4056d761e_MD5.jpg)

Look at the bottom right of the Wireshark window. You are looking for the word _Displayed:_. The numbers to the right of _Displayed_, is the answer. Type the answer in the THM answer field, and then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/515268b38b91768c51d20d2eb674c8bb_MD5.jpg)

Answer: 2235

**What is the number of packets with “even TTL numbers”?**

Click on the mint green _Filter Bar,_ time to craft our filter! Going back to Task 5 we had to search for packets that had a TTL of < 10. To find the TTL we use `ip.ttl` . Now we need to convert this input to a string, so that it can match to our regex (regular expression) later on. We do this by placing our `ip.ttl` inside of the `string()` function, so it looks like `string(ip.ttl)`. The quilifier we need is `matches` , to indicate that the TTL will match to our regex. Finally, to match it to an even number we use the regex `"[02468]$"` . This regex is showing the number at the end (`$`), must match an even (`[02468]`). All together the filter should look like `string(ip.ttl) matches "[02468]$"` . Now press enter to use this filter on the pcapng.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/03de4f3842b99b5a00b5f23af55be0c4_MD5.jpg)

Look at the bottom right of the Wireshark window. You are looking for the word _Displayed:_. The numbers to the right of _Displayed_, is the answer. Type the answer in the THM answer field, and then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/ecf4db9f1c565a841be1cd2bbafa6ccf_MD5.jpg)

Answer: 77289

**Change the profile to “Checksum Control”. What is the number of “Bad TCP Checksum” packets?**

This time instead of creating the filter, right off the bat. We need to first change the profile. To do this go to the menu bar at the top of the window. Click on the _Edit_ option, then from the drop-down menu click _Configuration Profiles…_

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/9b48874d78bc50281dcf96bf0311a38d_MD5.jpg)

The Configuration profile window will pop-up, look for the _Checksum Control._ Once you find it, click on it then click on the _OK_ button in the bottom right of the window.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/8a0412e303f92f052fce141a6c850be1_MD5.jpg)

Click on the mint green _Filter Bar,_ time to craft our filter! I started by typing in `tcp.checksum`, and Wireshark gave me a drop down of possible filters I may want to use. Since the question wants us to find the _Bad Checksum_, I felt that the filter `tcp.checksum_bad.expert`, was the correct filter. After selecting it, I press enter to use this filter on the pcapng.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/52cd98ac99e30354f8f9c87d2fd85c03_MD5.jpg)

This turned out to be the correct filter we were looking for. Look at the bottom right of the Wireshark window. You are looking for the word _Displayed:_. The numbers to the right of _Displayed_, is the answer. Type the answer in the THM answer field, and then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/38d93dd3c64b78d499b78b50717266ac_MD5.jpg)

Answer: 34185

**Use the existing filtering button to filter the traffic. What is the number of displayed packets?**

For this question, THM already has the filter created for us. You need to look at the end of the mint green filter bar. You should see _gif/jpeg with http-200_, click on this to apply the filter then search using it.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/4c3d6f8a0e5a80dda860719a510c8fd6_MD5.jpg)

Look at the bottom right of the Wireshark window. You are looking for the word _Displayed:_. The numbers to the right of _Displayed_, is the answer. Type the answer in the THM answer field, and then click submit.

![](03%20-%20Network%20Security%20and%20Traffic%20Analysis/_resources/10%20Wireshark%20-%20Packet%20Operations/ba04988bd1fb717a3e8050b84e96260e_MD5.jpg)

Answer: 261

# Task 7 Conclusion

**Congratulations!**

You just finished the “Wireshark: Packet Operations” room. In this room, we covered Wireshark statistics, filters, operators and functions.

Want to learn more? We invite you to complete the **Wireshark: Traffic Analysis** room to improve your Wireshark skills by investigating suspicious traffic activities.
