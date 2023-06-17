---
title: "Defeating Epsilon Loader V0.34 Vol. 3: Packet Encryption"
date: 2023-06-13
tags: [reverse-engineering, jvm, cryptography, network-packet]
authors: [BotDebug, Trdyun, SagiriXiguajerry]
img_path: /assets/eloader034-p3/
image:
    path: hexdump_preview.png
    lqip: hexdump_preview_lqip.jpg
    alt: Parsed EpsLoader packets
---

## Disclaimer

The following pseudocode snippets are **heavily** beautified. You may not be able to instantly recognize some of these parts; lots of junk code and algorithms are unrolled. But that doesn’t really matter, as when you finish reading this article, you will have a field day breaking it (=

## Intro

As we've already known, epsilon loader implemented some sorts of encryption on network packets so that crackers can't parse them directly and use them for their advantage.

So today we’ll go into details about how we broke their encryption.

## Analysis of Authentication Process

If you have ever tried to capture epsilon loader's network packets, you might be surprised by its **"plain-text"** client-to-server packets and **encrypted** server-to-client packets.

As a result, the content of the client-to-server packet **except** the hwid string can be parsed in ease. Just as the image below:
![client-to-server.png](client-to-server.png)

Once we look at the related code in the `$$$$$$$$ESKID$$$$$$$$$c.b()`, we can figured that the hwid string is composed of several system specifications, given by `System.getenv()`, `System.getProperty()` and `Runtime.getRuntime().availableProcessors()`:
![hwid.png](hwid.png)

Finally, the hwid string was encrypted by multiple ciphers, such as `sha-256`, `sha-1`, `sha-512`.

## Analysis of Encrypted Server-to-Client Packet

Then we tracking down the code of authentication and found several server-to-client packets:

```java
String passed = inStream.readUTF();
//checking the head packet to determain whether the authentication is passed
if (passed.equals("[PASSED]")){
  //authentication passed

  //essential packets
  String latestVersion = inStream.readUTF();
  int unknown1 = inStream.readInt();
  int unknown2 = inStream.readInt();
  
  Float currentVersion = 0.33f;
    if (currentVersion >= Float.parseFloat(latestVersion)){
        //version check passed
        
        //insert zip parsing process here
```

As you can see in the pseudocode above, there were 2 checks: authentication check and loader version check.

Once all the checks were passed, it would start to receive a stream of the jar file and parse all the files in it.

However there are 2 suspicious integer packets we haven't know their function: `unknown1` and `unknown2`, both of them were received before the jar.

Consequently, they should have some important roles.

Rolling down just a little we could find pseudocode like this:
![form_final_key](form_final_key.png)

Voila! We can see that it is traversing every byte of the encrypted file and doing xor calculations to every byte, just like a decryption process isn't it?

What's more, `unknown1` and `unknown2` are found participating in forming the final xor key!

Now we can rename them into `xor_key1` and `xor_key2`.

With the information we gathered, the whole server-to-client packet can be parsed in ease:
![parsed_packet](parsed_packet.png)

The whole process can be summarized as this diagram:
![decryption_process.png](decryption_process.png)

## Bonus: Bug Hunting

### Data loss in narrowing primitive conversion

At the early stage of our analysis, we tried to brute-force the XOR key in order to bypass the most annoying process and minimize the time expense.

Despite of the same result, the XOR key we brute-forced out was a single byte: **0xfd**, instead of the 32-bit integer **0x3e8fd** that we calculated from the network packets later.

That anomaly aroused our interest in finding its root cause, so we carefully checked the class decryption process and found something wrong with the type:
![data_loss](data_loss.png)

Just as the image shows, the convertion from 32-bit integer to 8-bit byte can result in data loss because of the narrowed data size.

As a result, all but the 8 lowest bits were discarded in the narrowing primitive conversion.([JLS §5.1.3](https://docs.oracle.com/javase/specs/jls/se20/html/jls-5.html#jls-5.1.3))

### XOR operation

What about the xor operation?
![xor_operation.png](xor_operation.png)

Xor operation happens in **binary level** and calculates **bit by bit**.

The calculation rules are as follow:

* If the bits at the ith position are the same we put 0 at that position.
* Else if the bits at the ith position are different we put 1 at that position.

It turns out that even without the higher bits, the calculation process of the lowest 8-bits are still unaffected because of the bit-by-bit calculation rule.

As the final decryption result we need is a single byte, the only necessity is **the lowest 8-bits** and the rest are **useless**.

What a tragic for eridani club  ^ ^
![meme&arg](meme&arg.png)

The **download link** for the deobfed EpsLoader V0.34 is **in the meme image** =)

### Credits

[BotDebug](https://github.com/StackC00ki3): deobfuscation, writer

[Trdyun](https://github.com/trdyun): decryption, authentication bypass

[SagiriXiguajerry](https://github.com/xiguajerry): co-writer

[Xiaoxin_xxecy](https://github.com/ImNotEcy): [_REDACTED_]
