---
title: "Defeating Epsilon Loader V0.34 Vol. 1: InvokeDynamic"
date: 2022-02-28
tags: [reverse-engineering, jvm, indy]
authors: [UnfortuneCookie, Trdyun, Xiguajerry]
img_path: /assets/eloader034-p1/
---

Epsilon Loader V0.34 had been considered as "STRONG obfuscated" as well as "uncrackable" by the 2B2T community for a long time. It was also widely believed that the authentication and verification part of Epsilon is achieved in the DLL[^1]. So let's look inside the DLL and the related JVM classes to determine what role the DLL plays and find out whether we can exploit it.

## Basic Information about the DLL

| Name            |                                 |
|:---------------:|:-------------------------------:|
| Arch            | x86_64                          |
| Compiler        | Visual C/C++(19.00.30034)[C++]  |
| Packed?         | NO                              |
| Virus Detection | NO(Using Virus-Total & Intezer) |

## Initial analysis of the DLL loading process

The first thing we want to figure out is the loading process of the DLL in JVM Bytecode-Level, so we searched for the string "DLL" using Recaf.

![stringSearchResult](stringSearchResult.png)

It's so lucky that the dll's filename was not encrypted. In this case we can find a suspicious class called `ESKID` and its static initizer `clinit` which contains the string.

## Indy[^2] in action

After analysing `clinit` a bit, we can notice that there are many occurences of `invokedynamic` instructions.(We assumed that you are familiar with this instruction, or we recommend you to read this article first:https://blogs.oracle.com/javamagazine/post/understanding-java-method-invocation-with-invokedynamic)

For instance, look at the following `invokedynamic` instruction:

```java
INVOKEDYNAMIC i(Ljava/lang/Object;Ljava/lang/Object;)Ljava/io/InputStream; [
      // handle kind 0x6 : INVOKESTATIC
ESKID.a(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;)Ljava/lang/invoke/CallSite;
      // arguments:
      "<str1>", 
      "<str2>", 
      "<str3>", 
      1
]
```

So following along the execution path, we see the `ESKID.a` method as the bootstrap method. This seems of interest so let’s also jump into that.

## The usage of the BSM[^3]

![HandleType](HandleType.png)

Using Threadtear's powerful CFG[^4] (The graph above is optimized), we can easily find out that the role of the 4th integer argument is to specify the invoke-type.

| Value | Invoke-Type |
|:-----:|:-----------:|
| 1     | Virtual     |
| 2     | Static      |
| 3     | Special     |

Although "str1", "str2" and "str3" were obfuscated, their functions can still be easily recognized:

| str1 | target class's name       |
|:----:|:-------------------------:|
| str2 | target method's name      |
| str3 | target method's signature |

## Algorithm

After we have known the function of the BSM, it's time for us to deal with the obfuscated strings.

```java
<push the obfuscated string to stack>
INVOKESTATIC ESKID.b (Ljava/lang/String;)Ljava/lang/String;
<working with the decoded string>
```

Bytecode above is the pattern of the string decryption. It's certain that `ESKID.b` is the method for string decryption in this case.

So let's dig deeper into the method `ESKID.b` :

![decryption_process](decryption_process.png)

Screenshot above is the last part of `ESKID.b`'s CFG.

As your seen, there are plenty of junk codes. But after analyzing the crucial part of the CFG above, we can still observe that there is a loop which traverses every `char` of the obfuscated string. Obviously this is the encrypting routine.

A simple kotlin *decryptor* implementation for this case would look like this:

```kotlin
fun decrypt(enc: String): String {
    var dec=""
    for (c in enc){
        dec+= (c.code xor (1406090362 xor 1406085967 shl 2)).toChar()
    }
    return dec
}
```

![visual_decryptor](visual_decryptor.png)

## Automation

With the information gathered from the previous section, we can finally get rid of the annoying invokedynamics and reveal the true invocation.

However, we found that every obfuscated class has a unique XOR key despite the decryption algorithm remains the same. What's more, the XOR key is protected by junk code. That's a stumbling block we have to deal with. So we have to write a custom transformer based on [java-deobfuscator](https://github.com/java-deobfuscator/deobfuscator) to automate the process.

First of all, we find BSM and decryptor method.

```java
//find BSM
MethodNode bsm = classNode.methods
        .filter(method -> method.desc.equals(bootstrapDesc))
        .findFirst().orElse(null);
if (bsm == null) return;

//find decryptor method
final InstructionPattern decryptionPattern = new InstructionPattern(
        new InvocationStep(INVOKESTATIC, classNode.name, null, "(Ljava/lang/String;)Ljava/lang/String;", false),
        new InvocationStep(INVOKESTATIC, "java/lang/Class", "forName", "(Ljava/lang/String;)Ljava/lang/Class;", false)
);
MethodInsnNode callDecryptor = (MethodInsnNode) Arrays.stream(bsm.instructions.toArray())
        .filter(ain -> {
            InstructionMatcher matcher = decryptionPattern.matcher(ain);
            return matcher.find() && (matcher.getCapturedInstructions("all").get(0) == ain);
        }).findFirst().orElse(null);
if (callDecryptor == null) {
    logger.error("[ESKID] [StaticIndyTransformer] call decryptor pattern not match in class {}", classNode.name);
    return;
}
MethodNode decryptor = TransformerHelper.findMethodNode(classNode, callDecryptor.name, callDecryptor.desc);
```

During the previous section, we have known that the value of the top stack frame is the key when the last `ixor` instruction is about to be executed by JVM. Therefore, we can analyze how the stack changes and grab the top-stack value as the XOR key.

So the following code shows how we filter out the last XOR instruction using `Deobfuscator`'s `InstructionMatcher` :

```java
final InstructionPattern algorithmPattern = new InstructionPattern(
        new OpcodeStep(IXOR),
        new OpcodeStep(I2C),
        new InvocationStep(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(C)Ljava/lang/StringBuilder;", false));
AbstractInsnNode lastIxor = Arrays.stream(decryptor.instructions.toArray())
        .filter(ain -> {
            InstructionMatcher matcher = algorithmPattern.matcher(ain);
            return matcher.find() && (matcher.getCapturedInstructions("all").get(0) == ain);
        }).findFirst().orElse(null);
if (lastIxor == null) {
    logger.error("[ESKID] [StaticIndyTransformer] algorithm pattern not match!");
    return;
}
```

Then we analyzed the frame statically using the power of [SimAnalyzer](https://github.com/Col-E/SimAnalyzer) and get the XOR key from the top of the stack:

```java
SimInterpreter interpreter = new SimInterpreter();
SimAnalyzer analyzer = new SimAnalyzer(interpreter);
Frame<AbstractValue>[] frames;
analyzer.setThrowUnresolvedAnalyzerErrors(false);
int xorKey;
try {
    frames = analyzer.analyze(classNode.name, decryptor);
    AbstractValue topValue = getTopStack(frames[decryptor.instructions.indexOf(lastIxor)]);
    //strict sanity check
    if (topValue == null
            || topValue.isValueUnresolved()
            || topValue.isNull()
            || topValue.isArray()
            || !topValue.isPrimitive()
            || topValue.getInsns().size() <= 1
            || topValue.getInsns().stream().anyMatch(a2 -> ILOAD <= a2.getOpcode() && a2.getOpcode() <= SASTORE)
            || !(topValue.getValue() instanceof Integer)) {
        logger.error("[ESKID] [StaticIndyTransformer] failed to get stack top value");
        return;
    }
    xorKey = (int) topValue.getValue();
    logger.debug("xor key found: {}", xorKey);
} catch (AnalyzerException e) {
    logger.error("failed to get frames in class: {} , method: {} , insn: {}", classNode.name, decryptor.name, TransformerHelper.insnToString(e.node));
    e.printStackTrace();
    return;
}
```

Now we have obtained all the information we need to preform the deobfuscation, so the last necessary part is how we determine the invocation type:

```java
Object[] bsmArgs = ((InvokeDynamicInsnNode) indy).bsmArgs;
int opcode;
switch ((int) bsmArgs[3]) {
    case 1: {
        opcode = INVOKEVIRTUAL;
        break;
    }
    case 2: {
        opcode = INVOKESTATIC;
        break;
    }
    case 3: {
        opcode = INVOKESPECIAL;
        break;
    }
    default: {
        logger.error("[ESKID] [StaticIndyTransformer] failed to get invocation type");
        return;
    }
}
```

You can download the complete source code of this Indy transformer via this link: [StaticIndyTransformer.java](/assets/eloader034-p1/StaticIndyTransformer.java)
> YOU NEED TO ADD [SimAnalyzer](https://github.com/Col-E/SimAnalyzer) DEPENDENCY FIRST TO RUN THIS TRANSFORMER!!
{: .prompt-danger }

## Final results

![result](result.png)

Screenshot above is a part of `ESKID` method.

## What’s next?

In Part 2 we'll dig into the details of the native DLL exploration and reveal the connections between Invokedynamic and JNI.

## Footnotes

[^1]: So-called **`Native Obfsucation`**

[^2]: Invokedynamic

[^3]: bootstrap method

[^4]: control flow graph
