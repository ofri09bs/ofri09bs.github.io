---
layout: post
title: "Coding Project: DLL Injection"
date: 2026-08-16
tags: [development]
---

## Getting Back to Cyber
It's been a while since my last update! After wrapping up some other projects and finishing my exams, I finally got the chance to dive back into Malware Development. 

For this project, my goal was to learn about Process Injection, and to build a tool that can establish a Reverse Shell with the highest possible Windows privileges (`NT AUTHORITY\SYSTEM`) by injecting a malicious payload into a legitimate system process.

## The Original Plan vs. Reality
Initially, I wanted to implement **Reflective DLL Injection** - an advanced technique that **loads a DLL directly into memory** without ever touching the disk, making it **extremely stealthy** and hard for AVs to detect. However, getting the manual mapping and PE parsing to work flawlessly was a bit too complex for now, and the DLL wasn't loading properly.

Instead of getting stuck, I tried a different approach: a Dropper combined with Classic DLL Injection. 

## The Attack Workflow
Here is exactly how the injector works behind the scenes:

### 1. The Dropper Mechanism
Instead of requiring the DLL to be downloaded or placed manually alongside the executable, the malicious DLL is **embedded directly inside the injector as a raw byte array**. When executed, the program drops (writes) this DLL file to the disk.

### 2. Privilege Escalation (`SeDebugPrivilege`)
To inject code into critical system processes, standard Administrator rights aren't always enough. The injector first adjusts its own access tokens to enable `SeDebugPrivilege`. This is a powerful Windows privilege that allows the process to inspect and modify the memory of almost any other process on the system.

### 3. Target Process 
The injector searches the running processes for a specific target name. Once found, it verifies if this process is running with `SYSTEM` privileges. If the target isn't running as SYSTEM, the injector exits to prevent wasting the payload on a low-privilege shell.

### 4. The Classic Injection
With the right privileges secured and the target process identified, the program performs the classic injection chain:
* `VirtualAllocEx`: Allocates memory inside the target process.
* `WriteProcessMemory`: Writes the path of our dropped DLL into the allocated space.
* `CreateRemoteThread` & `LoadLibraryA`: Forces the target process to spin up a new thread that loads our DLL.

### 5. The Payload
Once the DLL is loaded by the target process, it executes its payload: creating a hidden `cmd.exe` and establishing a reverse shell connection back to the attacker's machine. Because the host process runs as `SYSTEM`, our reverse shell inherits those maximum privileges.

## Source Code
You can check out the source code, the byte-array implementation, and the full project structure on my GitHub:

<div style="margin: 25px 0;">
  <a href="https://github.com/ofri09bs/DLL_Injection" target="_blank" style="background-color: #21262d; border: 1px solid #30363d; color: #58a6ff; padding: 10px 20px; text-decoration: none; border-radius: 6px; font-weight: bold; font-size: 0.9em; display: inline-block;">
    💻 View Injector Source Code on GitHub
  </a>
</div>

Reflective DLL injection is definitely still on my to-do list, but successfully chaining a dropper, token privilege escalation, and classic injection into a SYSTEM reverse shell was a great learning experience.
