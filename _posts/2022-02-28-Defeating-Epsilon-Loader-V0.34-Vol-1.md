---
title: "Defeating Epsilon Loader V0.34 Vol. 1: InvokeDynamic"
date: 2022-02-28
tags: [reverse-engineering, jvm, indy, cryptography]
authors: [BotDebug, Trdyun, SagiriXiguajerry]
img_path: /assets/eloader034-p1/
image:
    path: result_preview.png
    lqip: result_preview_lqip.jpg
    alt: Invokedynamic Deobfuscation
---

Epsilon Loader V0.34 had been considered as "STRONG obfuscated" as well as "uncrackable" by the 2B2T community for a long time.

It was also widely believed that the authentication and verification part of Epsilon is achieved in the DLL[^1].

So let's look inside the DLL and the related JVM classes to determine what role the DLL plays and find out the way to exploit it.

## Initial analysis of the DLL loading process

The first thing we want to figure out is the loading process of the DLL in JVM Bytecode-Level, so we search for the string "DLL" using Recaf.

![stringSearchResult](https://s1.ax1x.com/2023/06/18/pClfVVf.png)

It's so lucky that the dll's filename was not encrypted. Taking advantages of that we can find a suspicious class called `ESKID` and its static initizer `clinit` which contains the string.

## Indy[^2] In Action

After analysing `clinit` a bit, we can observe that there are many occurences of `invokedynamic` instructions. (More information about `invokedynamic`: <https://blogs.oracle.com/javamagazine/post/understanding-java-method-invocation-with-invokedynamic>)

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

Based on the knowledge of the `invokedynamic` instruction, we can see `ESKID.a` method as the bootstrap method and dig deeper into it.

## BSM[^3]

Using Threadtear's power, we can generate a CFG[^4] of the BSM[^3] (The graph below is optimized).

![HandleType](https://s1.ax1x.com/2023/06/18/pClfeIS.png)

Then we can easily find out that the role of the 4th integer argument is to specify the invoke-type:

| Value | Invoke-Type |
|:-----:|:-----------:|
| 1     | Virtual     |
| 2     | Static      |
| 3     | Special     |

It is obvious that "str1", "str2" and "str3" were obfuscated, however their functions can be identified easily:

| str1 | target class's name       |
|:----:|:-------------------------:|
| str2 | target method's name      |
| str3 | target method's signature |

## String Encryption Algorithm

After we know the roles the BSM plays , it's time for us to deal with those obfuscated strings.

```java
<push the obfuscated string to stack>
INVOKESTATIC ESKID.b (Ljava/lang/String;)Ljava/lang/String;
<working with the decoded string>
```

Bytecode above is the pattern of the string decryption.

It's certain that `ESKID.b` is the method for string decryption in this case.

Then we can take a glance at the method `ESKID.b` :

![decryption_process](https://s1.ax1x.com/2023/06/18/pClfAqP.png)

(Screenshot above is the last part of `ESKID.b`'s CFG.)

As you can see, there are plenty of junk codes.

But after analyzing the crucial part of the CFG above, we can assume that there is a loop which traverses every `char` of the obfuscated string.

That loop turns out to be the encrypting routine.

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

![visual_decryptor](https://s1.ax1x.com/2023/06/18/pClfZa8.png)

## Automation

With the information gathered from the previous section, we can finally get rid of the annoying invokedynamics and reveal the true invocation.

However, Every obfuscated class has a **unique** XOR key despite of the same decryption algorithm.

What's worse, the XOR key is protected by junk code. That's a stumbling block we have to deal with.

So our workaround is writing a custom transformer based on [java-deobfuscator](https://github.com/java-deobfuscator/deobfuscator) to automate the deobfuscation process.

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

During the previous section, we have known that the value of the top stack frame is the key when the last `ixor` instruction is about to be executed by JVM.

Therefore, we can analyze how the stack changes and grab the top-stack value as the XOR key.

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

Finally we have obtained all the information we need to preform the deobfuscation, so the last part is the invocation type identification:

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

You can download the complete source code of this Indy transformer via this: [StaticIndyTransformer.java](/assets/eloader034-p1/StaticIndyTransformer.java)
> YOU NEED TO ADD [SimAnalyzer](https://github.com/Col-E/SimAnalyzer) DEPENDENCY FIRST TO RUN THIS TRANSFORMER!!
{: .prompt-danger }

## Final results

![result](https://s1.ax1x.com/2023/06/18/pClfnPg.png)

Screenshot above is a part of `ESKID` method.

## Footnotes

[^1]: So-called **`Native Obfsucation`**

[^2]: Invokedynamic

[^3]: bootstrap method

[^4]: control flow graph
