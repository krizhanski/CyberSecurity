# 🌐 Exploring QUIC & HTTP/3.

Hi there! 👋

I am actively continuing my journey of learning and exploring the field of cybersecurity. Recently, I decided to dive deep into **QUIC** and **HTTP/3** to figure out exactly how this new standard works and what it means for network security.

 I wanted to look under the hood. I fired up Wireshark, intercepted the traffic, and saw with my own eyes exactly what is happening at the packet level. Alongside this hands-on practical analysis, I researched the topic across various technical sources to get a complete picture.

My main curiosity going into this was understanding the fundamental differences in the connection process—specifically, how the QUIC handshake actually happens and how it compares to the traditional TCP handshakes we are used to in HTTP/1.1 and HTTP/2.



### 🔍 What You Will Find in This Research:
* **Packet-Level Analysis:** A hands-on Wireshark breakdown of the QUIC handshake, encryption frames, and Connection IDs.
* **The Protocol Paradigm Shift:** Why the internet is moving away from TCP, and how QUIC integrates TLS 1.3 natively.
* **The Visibility Crisis:** How fully encrypted UDP streams blind traditional firewalls, IDS/IPS, and corporate proxies.
* **Attack Vectors:** Analysis of real-world threats, including the CPU-draining Rapid Reset Attack (CVE-2023-44487) and Rate-Limit Evasion.
* **The Connection Migration Challenge:** Why the ability to seamlessly switch IP addresses without dropping sessions is the biggest nightmare for network security appliances.
* **Defensive Recommendations:** 