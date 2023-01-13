---
title: "Defeating Epsilon Loader V0.34 Vol. 2: The JNI Protection"
date: 2022-03-19
tags: [reverse-engineering, java, jni, indy]
authors: [UnfortuneCookie, Trdyun, Xiguajerry]
img_path: /assets/eloader034-p2/
---

## Intro

In the last article we deobfuscated the Indys and reveal the "real invocation", in this post we will focus on analyzing both the related bytecode and the DLL to reveal the truth.

## Disclaimer

The following pseudocode snippets are **heavily** beautified. You may not be able to instantly recognize some of these parts; lots of junk code and algorithms are unrolled. But that doesn’t really matter, as when you finish reading about this kind of protection, you will have a fine day breaking it (=

## DLL loading process

After we obtain the indy-deobfuscated sample, we are now able to analyze the `clinit` method of the class `ESKID` and find out how the DLL is loaded.

### 1.Recognization of runtime platform

The DLL loading process starts by trying to get system properties to determine the type of your operating system and grab the proper OS-specific DLL

This is an abstract of their implementation:

```java
String osType = System.getProperty("os.name").toLowerCase();
InputStream inStream = null;
if (osType.contains("win")) {
    inStream = ESKID.class.getResourceAsStream("/eskid.dll");
}

if (osType.contains("mac")) {
    InStream = ESKID.class.getResourceAsStream("/mac.dat");
}

if (osType.contains("nux")) {
    InStream = ESKID.class.getResourceAsStream("/unix.dat");
}
```

However, its cross-platform functionality is actually deformed because of the absence of the DLL file `mac.dat` and `unix.dat` .

### 2.Extracting and loading

Because of some restrictions, DLLs in the jar could not be loaded directly. Thus it's necessary to extract the DLL to a temporary file before loading it.

```java
File tempDllFile = File.createTempFile("eskidontop", ".dat");
FileOutputStream outStream = new FileOutputStream(tempDllFile);
byte[] buffer = new byte[2048];
int read;
while ((read = inStream.read(buffer)) != -1){
    outStream.write(buffer, 0, read);
}
inStream.close();
outStream.close();
tempDllFile.deleteOnExit();
System.load(tempDllFile.getAbsolutePath());
```

> All the pseudocode above are in the class `ESKID` .
{: .prompt-tip }

## Diving into the DLL

In an attempt to learn more about the native methods in the DLL, we analysed some other methods under the package `com/loader/epsilon` . We were surprised that almost every invocation which has a real role was just disappeared. What's more, we could only find invocations to the native methods. So it's time to analyse deeper into the DLL itself.

### Thunk function

We choose a random JNI function `Java_ESKID_AwUlqtUfLk` for our initial analyze.

![thunk_func](thunk_func.png)

The IDA has already marked this function as thunk function because it only has one instruction.

### 3 suspicious strings

Then we followed the jump to the function `Java_ESKID_AwUlqtUfLk_0` :

```nasm
.text:0000000180009EC0 Java_ESKID_AwUlqtUfLk_0 proc near       ; CODE XREF: Java_ESKID_AwUlqtUfLk↑j
.text:0000000180009EC0                                         ; DATA XREF: .pdata:00000001800AA0B4↓o
.text:0000000180009EC0
.text:0000000180009EC0 var_18          = qword ptr -18h
.text:0000000180009EC0
.text:0000000180009EC0                 sub     rsp, 38h
.text:0000000180009EC4                 mov     [rsp+38h+var_18], r8
.text:0000000180009EC9                 lea     r9, aLjavaLangStrin ; "(Ljava/lang/String;)Ljava/lang/String;"
.text:0000000180009ED0                 lea     r8, aC_0        ; "c"
.text:0000000180009ED7                 lea     rdx, aComLoaderEpsil_6 ; "com/loader/epsilon/$$$$$$$$ESKID$$$$$$$"...
.text:0000000180009EDE                 call    j_eCallStaticObjectMethodV
.text:0000000180009EDE
.text:0000000180009EE3                 add     rsp, 38h
.text:0000000180009EE7                 retn
.text:0000000180009EE7
.text:0000000180009EE7 Java_ESKID_AwUlqtUfLk_0 endp
```

Subsequently we observe 3 strings as arguments for the **single** `call`. we can obviously know that these strings are class name, method name and signature.

### Another Thunk Function

In turn we seek to the function `j_eCallStaticObjectMethodV` .

It turns out that `j_eCallStaticObjectMethodV` is another thunk function which jumps to the function `eCallStaticObjectMethodV` .

### JNI helper Function

The pseudocode of the function looks like this:

```c
jobject eCallStaticObjectMethodV(JNIEnv_ *env, const char *className, const char *methodName, const char *signature, ...)
{
  struct _jobject *clazz; // rbx
  struct _jmethodID *methodID; // rax
  va_list args; // [rsp+70h] [rbp+28h] BYREF

  va_start(args, signature);
  clazz = env->functions->FindClass(&env->functions, className);
  methodID = env->functions->GetStaticMethodID(&env->functions, clazz, methodName, signature);
  struct _jobject *result = env->functions->CallStaticObjectMethodV(&env->functions, clazz, methodID, args);
  va_end(args);
  return result
}
```

From this pseudocode we can recognize this function as JNI-helper function. Its role is to assist developers to call JNI methods comfortably.

### Summary

The functionalities of all the JNI functions are the same: they were used for hiding the invocations to the JVM methods.

The whole life-cycle of the obfuscated JVM method invocations can be summarize as the graph below:

![realCall](realCall.png)

In JVM layer, the invocations were hidden by the `invokedynamic` instruction and its invocation to the JNI method will be resolved during runtime. Finally the JNI functions in the DLL invoke the real target java method.

## Gathering data for further deobfuscation

In order to recover the real call, we need to gather information about the actual calls from the JNI functions.

So I just wrote a IDA-python script for this task.

Download link: [TODO]

> YOU NEED TO ADD JNI STRUCTURE IN IDA FIRST TO RUN THIS SCRIPT!
{: .prompt-danger }

```python
########################################################################
# Author: BotDebug (botdebug@outlook.com)
# Copyright 2022 HorizonLN
#
# HorizonLN licenses this file to you under the Apache License, Version
# 2.0 (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at:
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.
########################################################################


from idautils import *
from idc import *
import re
import json

proxy_call_infos = {}
for func in Functions():
    # filter out non-JNI functions
    if re.match(r"Java_ESKID_(.*)_0", get_func_name(func)) == None:
        continue

    # extract clazz,method,signature info from lea*3 pattern in JNI functions
    leaList = list(
        filter(lambda addr: print_insn_mnem(addr) == "lea", list(FuncItems(func)))
    )
    if len(leaList) != 3:
        print(
            "[ERROR] JNI function %s doesn't have complete info"
            % (get_func_name(func))
        )
        continue
    for leaAddr in leaList:
        unknown = str(get_strlit_contents(get_operand_value(leaAddr, 1)).decode())
        if re.match(r"\((.*)\)(.*)", unknown) != None:
            sig = unknown
        elif unknown.find("/") != -1:
            clazz = unknown
        else:
            method = unknown

    # find call/jmp to thunk function
    thunkCalls = list(
        filter(
            lambda addr: print_insn_mnem(addr) == "call"
            or print_insn_mnem(addr) == "jmp",
            list(FuncItems(func)),
        )
    )
    if len(thunkCalls) != 1:
        print(
            "[ERROR] could not find JMP/CALL thunk function in JNI function %s"
            % (get_func_name(func))
        )
        continue
    obfCallAddr = get_operand_value(thunkCalls[0], 0)

    # check whether the thunk function has JMP to the JNI-helper function
    if print_insn_mnem(obfCallAddr) != "jmp":
        print(
            "[ERROR] thunk function %s doesn't contain real jmp!"
            % (get_func_name(func))
        )
        continue

    """ Find JNI-call*3 pattern to grab target jvm methods' invoke-type.

        Simplified call-JNI pattern:
        call    [rax+JNINativeInterface_.FindClass]
        call    [r10+JNINativeInterface_.Get...MethodID]
        call    [r10+JNINativeInterface_.Call...MethodV]

        Step:
        1.Get the 3th call's member name in JNI structure.
        2.Determine invoke-type info by checking whether the name contains "Static". """
    JniHelperFuncItems = FuncItems(get_operand_value(obfCallAddr, 0))
    JNIcalls = list(
        filter(lambda addr: print_insn_mnem(addr) == "call", list(JniHelperFuncItems))
    )
    if len(JNIcalls) != 3:
        print(
            "[ERROR] JNI helper function %s doesn't match JNI-call*3 pattern!"
            % (get_func_name(func))
        )
        continue
    JNIstrucID = get_struc_id("JNINativeInterface_")
    JniMemberName = str(get_member_name(JNIstrucID, get_operand_value(JNIcalls[2], 0)))
    if JniMemberName.find("Static") != -1:
        invokeType = "static"
    else:
        invokeType = "virtual"

    proxyMethod = re.match(r"Java_ESKID_(.*)_0", get_func_name(func)).group(1)  #name of the native method in JVM
    proxy_call_info = {
        proxyMethod: {
            "clazz": clazz,
            "method": method,
            "signature": sig,
            "type": invokeType
        }
    }
    proxy_call_infos.update(proxy_call_info)

with open("proxy_info.json", "w", encoding="utf-8") as f:
    json.dump(proxy_call_infos, f, indent=4, sort_keys=False)
    print("data exported!")
```

Below is a small part of the result file --  `proxy_info.json` :

```json
{
    "AEuZjfSlxs": {
        "clazz": "javax/crypto/Cipher",
        "method": "init",
        "signature": "(ILjava/security/Key;)V",
        "type": "virtual"
    },
    "AJrdsSKYPD": {
        "clazz": "kotlin/io/ByteStreamsKt",
        "method": "readBytes",
        "signature": "(Ljava/io/InputStream;)[B",
        "type": "static"
    },
    "AKOjFEenlj": {
        "clazz": "com/loader/epsilon/$$$$$$$$ESKID$$$$$$$$$f",
        "method": "e",
        "signature": "(Ljava/lang/String;)Ljava/lang/String;",
        "type": "static"
    },
    ...
}
```

## Winner winner chicken dinner!

With the data we extracted, we can write another custom transformer to deobfuscate them automatically. The deobfuscation process is like the diagram below.

![diff](diff.png)Here's the source code: [public s00n]

We can combine part1 and part2 together to form the complete graph:

![overview](overview.png)

## Memes

The DLL was backdoored:

![dll_backdoor](dll_backdoor.png)

![ez_botdebug_p2](ez_botdebug_p2.png)

The GIF below is the real thing AntiLeak will do once triggered:

![just a meme](anti_leak_IRL.gif)

## Credit

Thanks @smallshen for hijacking our PCs using his POWERFUL AntiLeak

![copyrighted-jar-protected-by-smallshen](copyrighted-jar-protected-by-smallshen.png)

(We recommand Smallshen's writeup [BruhSkid](https://github.com/smallshen/BruhSkid) )

Thanks Juanye for encouraging us:

![juanye_laughs](juanye_laughs.png)

![juanye_laughs_p2](juanye_laughs_p2.png)

Thanks Six for enlightening us:

![six_enlightenment](six_enlightenment.png)
