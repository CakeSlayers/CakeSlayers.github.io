---
title: "Defeating Epsilon Loader V0.34 Vol. 2: JNI Protection"
date: 2022-03-19
tags: [reverse-engineering, jvm, jni]
authors: [UnfortuneCookie, Trdyun, Xiguajerry]
img_path: /assets/eloader034-p2/
---

## Intro

In the last article we deobfuscated the Indys and reveal the "real invocation", in this post we will focus on analyzing both the related bytecode and the DLL to reveal the truth.

## Disclaimer

The following pseudocode snippets are **heavily** beautified. You may not be able to instantly recognize some of these parts; lots of junk code and algorithms are unrolled. But that doesn’t really matter, as when you finish reading about this kind of protection, you will have a field day breaking it (=

## Basic Information About The DLL

| Name            |                                 |
|:---------------:|:-------------------------------:|
| Arch            | x86_64                          |
| Compiler        | Visual C/C++(19.00.30034)[C++]  |
| Packed?         | NO                              |
| Virus Detection | NO(Using Virus-Total & Intezer) |

## DLL loading process

With the indy-deobfuscated sample, we are now able to analyze the `clinit` method of the class `ESKID` and find out how the DLL is loaded.

### 1.OS identification

The DLL loading process starts by trying to get system properties to determine the type of your operating system and grab the proper OS-specific DLL

This is an abstract of their implementation:

```java
String osType = System.getProperty("os.name").toLowerCase();
InputStream inStream = null;
if (osType.contains("win")) {
    inStream = ESKID.class.getResourceAsStream("/eskid.dll");
}

if (osType.contains("mac")) {
    inStream = ESKID.class.getResourceAsStream("/mac.dat");
}

if (osType.contains("nux")) {
    inStream = ESKID.class.getResourceAsStream("/unix.dat");
}
```

However, its cross-platform functionality is actually deformed because of the absence of the DLL file `mac.dat` and `unix.dat` .

### 2.Extracting and loading

Because of some technical restrictions, the DLLs in the jar could not be loaded directly. Thus it's necessary to extract the DLL as a temporary file before loading it.

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

In an attempt to learn more about the native methods in the DLL, we analysed some of the other methods under the package `com/loader/epsilon` . To our surprise, most of the invocations were pointed to the native methods. So it's time to analyse deeper into the DLL itself.

### Thunk function

We choose the native method `Java_ESKID_AwUlqtUfLk` for our initial analyze.

![thunk_func](thunk_func.png)

The IDA has already marked this function as thunk function because it only has one instruction.

### 3 suspicious string arguments

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

Subsequently we can observe 3 strings as arguments for the **single** `call`. we can assume that these plain strings are class name, method name and signature.

### Another Thunk Function

In turn we seek to the function `j_CallStaticObjectMethod` which turns out to be another thunk function which jumps to the function `CallStaticObjectMethod` .

### Inlined JNI function 

The pseudocode of the function looks like this:

```c
jobject CallStaticObjectMethod(JNIEnv_ *env, const char *className, const char *methodName, const char *signature, ...)
{
  struct _jobject *clazz; // rbx
  struct _jmethodID *methodID; // rax
  va_list args; // [rsp+70h] [rbp+28h] BYREF

  va_start(args, signature);
  clazz = env->functions->FindClass(&env->functions, className);
  methodID = env->functions->GetStaticMethodID(&env->functions, clazz, methodName, signature);
  return Env->functions->CallStaticObjectMethodV(&env->functions, clazz, methodID, args);
}
```

From this pseudocode we can recognize this function as an inlined JNI function(source: [jni.h#L1351](https://github.com/openjdk/jdk8u-dev/blob/6244292d28e1cddcc70bc4dbf98adad13fe1e3d7/jdk/src/share/javavm/export/jni.h#L1351)) and its role is assisting developers to call JNI methods comfortably.

### Conclusion

The functionalities of all the native methods are the same: they were used for making invocations to the JVM methods.

The whole life-cycle of the obfuscated JVM method invocations can be summarize as the graph below:

![realCall](realCall.png)

In JVM layer, the invocations were hidden by the `invokedynamic` instruction and its invocation to the JNI method will be resolved during runtime. Finally the JNI functions in the DLL invoke the real target java method.

## Gathering data for further deobfuscation

In order to recover the real call, we need to gather all the information about the actual calls from the JNI functions.

So we can write an IDApython script for this task.
Download link: [gen_proxy_info.py](/assets/eloader034-p2/gen_proxy_info.py)
> YOU NEED TO ADD JNI STRUCTURE IN IDA FIRST TO RUN THIS SCRIPT!
{: .prompt-danger }

We started first by filtering out JNI functions, IDA's powerful auto-rename feature has already skipped the first thuck function for us, so we can just pick the functions which end with `_0` :

```python
for func in Functions():
    # filter out non-native methods
    if re.match(r"Java_ESKID_(.*)_0", get_func_name(func)) == None:
        continue
```

Then we extract the target clazz, method, signature from the lea*3 pattern:

```python
leaList = list(
    filter(lambda addr: print_insn_mnem(addr) == "lea", list(FuncItems(func)))
)
if len(leaList) != 3:
    print(
        "[ERROR] native method %s doesn't match lea*3 pattern!"
        % (get_func_name(func))
    )
    continue
for leaAddr in leaList:
    string = str(get_strlit_contents(get_operand_value(leaAddr, 1)).decode())
    if re.match(r"\((.*)\)(.*)", string) != None:
        sig = string
    elif string.find("/") != -1:
        clazz = string
    else:
        method = string
```

Now the JNI function is about to call the JNI-helper function to invoke the real target jvm method, however there's another thuck function which blocks our way, so we have to grab the address of the thunk function first:

```python
callThunk = list(
    filter(
        lambda addr: print_insn_mnem(addr) == "call"
        or print_insn_mnem(addr) == "jmp",
        list(FuncItems(func)),
    )
)
if len(callThunk) != 1:
    print(
        "[ERROR] could not find JMP/CALL thunk function in native method %s"
        % (get_func_name(func))
    )
    continue
thunkFuncAddr = get_operand_value(callThunk[0], 0)

# check whether the thunk function has JMP to the inlined JNI function
    if print_insn_mnem(thunkFuncAddr) != "jmp":
        print(
            "[ERROR] thunk function %s doesn't have jmp to the inlined JNI function!"
            % (get_func_name(func))
        )
        continue
```

Due to the thunk function address is actually the jmp instruction's address, we can extract JNI calls from the helper function in ease:

```python
JniHelperFuncItems = FuncItems(get_operand_value(thunkFuncAddr, 0))
JNIcalls = list(
    filter(lambda addr: print_insn_mnem(addr) == "call", list(JniHelperFuncItems))
)
if len(JNIcalls) != 3:
    print(
        "[ERROR] Inlined JNI function %s doesn't match JNI-call*3 pattern!"
        % (get_func_name(func))
    )
    continue
```

For the invocation types, we can easily determine them by their JNI function names:

```python
JNIstrucID = get_struc_id("JNINativeInterface_")
JniMemberName = str(get_member_name(JNIstrucID, get_operand_value(JNIcalls[2], 0)))
if JniMemberName.find("Static") != -1:
    invokeType = "static"
else:
    invokeType = "virtual"
```

Finally, dump the data to a json object:

```python
proxyMethod = re.match(r"Java_ESKID_(.*)_0", get_func_name(func)).group(1)  #name of the native method in JVM
proxy_call_infos += {
    proxyMethod: {
        "clazz": clazz,
        "method": method,
        "signature": sig,
        "type": invokeType
    }
}
```

Below is a small part of the result file --  [proxy_info.json](/assets/eloader034-p2/proxy_info.json) :

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

## Winner winner chicken dinner

With the data we extracted, we can write another custom transformer to deobfuscate them automatically. The deobfuscation process is like the diagram below.

![diff](diff.png)

Here's the source code: [JniProxyTransformer.java](/assets/eloader034-p2/JniProxyTransformer.java)
> YOU NEED TO ADD [Gson](https://github.com/google/gson) DEPENDENCY FIRST TO RUN THIS TRANSFORMER!!
{: .prompt-danger }

The only thing we want to highlight is how we determine whether the invocation type is `INVOKEINTERFACE`.
Actually the workaround is simple, we can just grab the target `clazz`'s `classNode` from the classpath and get that from its access property:

```java
int opcode;
if (classpath.get(proxyInfo.get("clazz")).access == Opcodes.ACC_INTERFACE) {
    opcode = Opcodes.INVOKEINTERFACE;
} else {
    opcode = Opcodes.INVOKEVIRTUAL;
}
```

We can combine part1 and part2 together to form a complete graph:

![overview](overview.png)

## Memes

The DLL was backdoored:

![dll_backdoor](dll_backdoor.png)

![ez_botdebug_p2](ez_botdebug_p2.png)

The GIF below is the real thing AntiLeak will do once triggered:

![just a meme](anti_leak_IRL.gif)

@smallshen hijacking our PCs using his POWERFUL AntiLeak

![copyrighted-jar-protected-by-smallshen](copyrighted-jar-protected-by-smallshen.png)

Thanks Juanye for encouraging us:

![juanye_laughs](juanye_laughs.png)

![juanye_laughs_p2](juanye_laughs_p2.png)

## Credits

Thanks Six for enlightening us:

![six_enlightenment](six_enlightenment.png)
