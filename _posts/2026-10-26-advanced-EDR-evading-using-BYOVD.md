---
layout: post
title: "Advanced EDR evading using BYOVD"
date: 2026-10-26
tags: [development]
---

# Introduction
On this project I was focused about 1 important principle that I think is the most important in malware development - **evasion**.

So, what is the art of evasion?
Evasion techniques are made to evade many defence systems in the target computer, such as Antivirus, EDRs, XDRs, IPS, IDS, and many many many more systems that use static/signature/dynamic analysis to find your malware.

So this project focuses on **evading EDRs from all kinds and levels (kernel level and userland level) using BYOVD**.

# Execution Flow
The malware workflow is like that:
* First stage: The **vulnerable driver and the payload DLL gets dropped** to the victim's computer from and bytes array in the header files.
* Second stage: The **driver gets loaded into the kernel**, and first thing we do is to **leak the kernel base address** (defeating KASLR)
* Third stage: **Patching all the kernel targets** to blind EDRs
* Fourth stage: **Escalate priviliges** to Debug, locate system target, and **inject the DLL into the process** to get a **reverse shell**.

# The Vulnerable Driver (BYOVD - CVE-2019-16098)
To read and modify kernel memory from userland without triggering **Windows Driver Signature Enforcement (DSE)**, this project leverages a **BYOVD (Bring Your Own Vulnerable Driver)** attack using `RTCore64.sys` - a legitimate, digitally signed driver originally developed by MSI for their Afterburner overclocking utility (**CVE-2019-16098**).   
Because the driver holds a valid cryptographic signature, **Windows allows any local administrator to load it directly into Ring 0** without complaints.

The vulnerability stems from the driver exposing direct hardware and memory access routines to usermode via `DeviceIoControl` (specifically through IOCTLs `0x80002048` for reading and `0x8000204c` for writing) without performing any validation on the target address.   
By sending a simple structured request containing a target kernel virtual address, a size, and a value, our userland process gains a clean **Arbitrary Kernel Read/Write primitive**.   
Because these specific IOCTLs are designed to read and write up to 4 bytes (`DWORD`) per call, we have to carefully design our 64-bit pointer patches around a 4-byte boundary to avoid race conditions and BSODs, as explained in the sections below.

For much better explanation, check this [artical](https://seg-fault.gitbook.io/researchs/windows-security-research/exploit-development/rtcore64.sys-cve-2019-16098)

# Evading EDRs
So how could you evade a system that monitors every move you do and inspects everything from the lowest level? - You blind it.

Yes, so there are many many ways to evade EDRs, but I think blinding the EDR is the best way to do it, because the EDR thinks everything is working and fine, unlike just killing the EDR, other EDRs or a security monitor will IMMEDIATELY catch this kill your malware.

The main EDR blinding techniques in this malware are cutting off its data sources and function hooks, and jumping over the userland hooks; this is done by **ETW TI (Event Tracing for Windows Threat Intelligence) nulling, Callback Redirecting, and Indirect Syscalls.**

## Indirect Syscalls 
Indirect syscall is a technique designed to **evade EDRs in userland that analyze processes and may hook critical API calls** to detect malicious software. The technique works by **bypassing the need for WinAPI or even NTAPI**; instead, it executes the API calls directly, avoiding calls to external wrapper functions that might be subject to monitoring or inspection.

With this specific (indirect) technique, rather than simply executing the syscall instruction from our own assembly code, the program prepares the necessary parameters in the appropriate registers. It then **jumps to the function's original address within ntdll.dll to execute only the syscall instruction itself.** This prevents the detection of syscall executions originating from locations other than ntdll.dll.
```
Normal Call:      [Malware] ──> [Hooked ntdll.dll Stub] ──> [EDR Inspection!]
Direct Syscall:   [Malware ( executes 'syscall' )] ───────> [Kernel] (Flagged: RIP outside ntdll!)
Indirect Syscall: [Malware (sets SSN)] ──> [Jumps to 'syscall' address inside ntdll.dll] ──> [Kernel]
```
You are welcomed to check my [repo](https://github.com/ofri09bs/Indirect-Syscall-Injection) on indirect Syscalls for more detailed explanation.

## Callback Redirecting 
this technique allows us to silently blind an EDR by patching a single pointer in kernel memory; leaving the driver loaded, signed, and apparently healthy while generating zero process creation telemetry.

Windows has 3 fixed size arrays in `ntoskrnl`'s `.data` section. **Every kernel component that wants to be told about process/thread/image events registers a callback by putting a function pointer into one of these arrays**

The 3 arrays are: **`PspCreateProcessNotifyRoutine`**, **`PspCreateThreadNotifyRoutine`** and **`PspLoadImageNotifyRoutine`**; and they notify about process create/exit, thread create/exit and DLL/EXE image load, respectively.

Each element in the arrays contains an `_EX_CALLBACK_ROUTINE_BLOCK` structure (undocumented by windows) and every block hold a callback function address, something like this:
```
slot[i]  →  ┌─────────────────────────┐
            │ +0x00  RundownRef       │  refcount + flag bits
            │ +0x08  Function         │  actual function pointer
            │ +0x10  Context          │  usually NULL for Ex callbacks
            │ +0x18  padding          │
            └─────────────────────────┘
```

So using mostly WinDbg we can find the offset of the function address, and then **overwrite the callback function address with a `xor eax, eax; ret` gadget so the callback function never runs, the EDR doesn’t get notified, and function returns NTSTATUS_SUCSESS.** 
Note that we DONT just null the function pointer, because this could be very unstable and could lead to a BSOD (if you call a function with address 0)

We should also note 2 very important things; first, we don’t want to blind every component that registered a callback in these arrays, some of them are critical and should NOT be touched. This is why for every function address we iterate through, we check if it belongs to an known EDR (defined in a global list) by calculating to which loaded module the function address belongs to (using the linked list `PsLoadedModuleList`, checking if 
`FnAddress >= DllBase && FnAddress < DllBase+DllImageSize`). 

And second, our exploited driver gives us exactly 4 bytes to write/read, and an address is 8 bytes, so there could be a situation where we overwrite the first half of the address, and right after this before overwriting the second half, the kernel notifies the callback functions and we could get a BSOD because the kernel read the half overwritten pointer.
So, I decided to overwrite ONLY of the gadget address and the EDR function are in the same 4 byte memory range (which should be pretty common), so we could overwrite with 1 go, without any race errors.

## ETW-TI Nulling
Windows has a built in event tracing system called **ETW (Event Tracing for Windows).** Kernel components and usermode applications write events to it, and consumers subscribe to specific providers to read those events. Most ETW providers are for debugging, performance, or logging but there is one for security purposes - **Microsoft-Windows-Threat-Intelligence** is the kernel's own behavioral sensor, and it exists specifically so that **security products can detect process injection, remote memory operations, and credential theft.**

Unlike process/thread/image callbacks (which notify that something happened), TI events describe what was done to it - remote memory allocations, cross process writes, remote thread hijacking. These are the exact signals an EDR's behavioral engine consumes when it decides that a process is being injected into.

**By zeroing one byte in a kernel data structure, we silence the entire TI provider.** The EDR stays loaded, signed, and healthy but just blind from these attacks.

The kernel emits these events through a global `REGHANDLE`, `EtwThreatIntProvRegHandle`, which points to an `_ETW_REG_ENTRY` struct. The dispatcher checks the **EnableMask** byte before emitting; if it's zero, the event is skipped and the function returns `STATUS_SUCCESS` cleanly. The obvious attack is nulling the global handle itself, but that's an 8 byte pointer and our primitive is only 4 bytes; the two-write sequence could cause race condtions as I explained before, Zeroing EnableMask avoids this entirely. Before writing, we verify the provider's GUID so a shifted offset can never point us at the wrong entry, and we read back after the write to confirm the change landed.
```
EtwThreatIntProvRegHandle (Global in ntoskrnl)
       │
       ▼
┌──────────────────────────────┐
│ _ETW_REG_ENTRY               │
│  +0x00 RegList               │
│  ...                         │
│  +0x20 GuidEntry  ───────────┼──> ┌──────────────────────────────┐
└──────────────────────────────┘    │ _ETW_GUID_ENTRY              │
                                    │  ...                         │
                                    │  +0x60 ProviderEnableInfo    │
                                    │         └── EnableMask (1B) ◄┼── Overwrite with 0x00
                                    └──────────────────────────────┘
```
# The Payload
Although the main focus of this project is the EDR evading, I have also used a strong payload (that I have already created in past project) that **injects a DLL to a SYSTEM privileged instance of svchost.exe and creates a reverse shell**; but this time its way way stronger because Defender and any EDR that could have see and stop this malware - now cant. The DLL and the Driver files are written to an array of bytes and then dropped in the target computer.   
for the DLL code and deeper explanation check this [repo](https://github.com/ofri09bs/DLL-Injection). 


# Mitigations?
So, did my hard work pay off in the end? Did I create an unstoppable malware? - No. Of course not :(.
One of the main mitigation against this malware is as simple as black listing all the known vulnerable drivers (Microsoft has the "**Microsoft Vulnerable Driver Blocklist**" since version 22H2).
There are also mitigations like **HVCI** and **KPP** or even self checking EDRs that could detect this malware.
So yeah, unfortunately without a major 0day vulnerablity, there is no such thing as unstoppable malware.
