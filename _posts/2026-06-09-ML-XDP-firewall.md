---
layout: post
title: "Coding Project: ML-Powered-Kernel-Firewall"
date: 2026-06-09
tags: [development]
---

# AI in the Kernel: Building a Real-Time eBPF/XDP Firewall
When dealing with DDoS attacks or aggressive port scans, every microsecond counts. Traditional firewalls running in the network stack often consume valuable CPU cycles just to drop malicious packets.
I recently decided to explore a different approach: What if we could use Machine Learning in the Linux Kernel, intercepting packets at the network interface card (NIC) level?

The result is **XDP-ML Firewall**, an AI-powered Intrusion Prevention System built with eBPF/XDP and **XGBoost**.

## What is eBPF/XDP and XGBoost?
* **eBPF** (Extended Berkeley Packet Filter) is a **kernel technology** that allows developers to run **safe**, 
**sandboxed** programs directly inside the operating system kernel at runtime **without changing the kernel source code** or loading external modules; Think of it like a "VM in the kernel".
* **XDP** (eXpress Data Path) is a high performance, programmable network packet-processing framework built into the Linux kernel. By intercepting network packets at the **lowest possible point**, right when they hit the network interface card,
XDP bypasses the heavy, traditional OS networking stack, delivering ultra low latency and wire speed performance
* **XGBoost** (eXtreme Gradient Boosting) is a highly popular machine learning algorithm designed to solve supervised learning problems. It uses an ensemble of **decision trees** and is widely known for its incredible speed, 
scalability, and predictive accuracy. I choose XGBoost because its one of the best choices for decision trees problems.

## The Architecture
To get maximum performance, the project is split into three layers:
1. **The Data Collection (eBPF/XDP)**: A C program attached to the network interface. It intercepts packets (TCP, UDP, ICMP) before they reach the OS network stack. 
It parses headers, tracks connection states using an eBPF LRU Hash Map, and extracts live features (e.g., payload size, inter-arrival time, TCP flags).
2. **The ML Engine**: An XGBoost classifier trained on the dataset "CIC-IDS2017" to find various types of attacks. Since Python cannot run in the kernel, the trained decision trees were converted into pure
C code (a LOT of if-else) using m2c, allowing the kernel to compute a Log-Odds score per connection in real-time very fast (I needed to scale up all the numbers in the model by 1,000,000 because float and double are not allowed in eBPF.
3. **The Control Dashboard**: A user-space Python dashboard utilizing the rich library to read the eBPF maps and provide live terminal monitoring.

## Overcoming Kernel Constraints & Data Engineering
Writing code for the kernel is uniquely challenging due to the strict eBPF Verifier, which ensures custom programs won't crash the system.
* **The State Limit (E2BIG)**: My initial ML model had 20 decision trees. The Verifier rejected it because the nested if/else branches created a combinatorial explosion of possible execution paths. By aggressively optimizing the XGBoost model down to 5 trees, I successfully bypassed the kernel's state limits while maintaining a high detection accuracy.
* **Feature Engineering in C**: The initial data was about 2.7m rows, when about 1.7m was benign traffic and then 1m more from several different classes. After scaling down alot and giving up on multi-class classification
I ended up with about 550k samples from each class (benign and not benign). But the data itself was not accurate to my data, so I needed to scale it and limit the amount of min packets for each connection.
* **Kernel-User Communication**: One of the main challenges I had is understanding how is the kernel supposed to communicate with the user-space program. I tried **eBPF Ring Buffer**, writing into other files,
and finaly I understood that the best way is to use **eBPF Hash Maps** for simple communication (even that finding, loading and linking the map and the XDP program to the user program was kinda difficult).

Eventually, after a lot of debugging and playing with the data I ended up with a good model (93% accuracy) and a working system to load it into the kernel.

## Conclusion
Bringing Machine Learning to the kernel space using eBPF is a game changer for high performance security tooling. It allows us to combine the intelligence of AI with the unmatched speed of XDP packet dropping (And also AI in the kernel sounds cool ;).
You can check out the full source code and try the live dashboard on my [GitHub](https://github.com/ofri09bs/ML-powered-Kernel-Firewall/tree/main)
