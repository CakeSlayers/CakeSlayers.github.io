---
title: Defeating Epsilon Loader V0.34 JNI Protection Part 1
date: 2022-02-28
tags: [reverse-engineering, java, jni, indy]
img_path: /assets/img/eloader034-jni-p1/
---

Epsilon Loader V0.34 has been considered as "STRONG obfuscated" as well as "uncrackable" by the 2B2T community for a long time. It's also widely believed that the authentication part of Epsilon is achieved in the DLL. So let's look inside the DLL and related JVM classes to determine what role the DLL plays and find out whether we can exploit it.

## Basic Information about the DLL

| Arch            | x64                             |
|:---------------:|:-------------------------------:|
| Compiler        | Visual C/C++(19.00.30034)[C++]  |
| Packed?         | NO                              |
| Virus Detection | NO(Using Virus-Total & Intezer) |

## Initial analysis of DLL loading process

The first thing we wanted to do is to analyze the process of the DLL loading in Bytecode-Level, so we just searched for string "DLL" using Recaf.

![stringSearchResult](stringSearchResult.png)

So we traced down to the class called `ESKID` and analyze its method member "clinit".

## Indy[^1] in action

The first evident obstacle we have to deal with is the `Invokedynamic Obfuscation`.

For instance look at the following `invokedynamic` instruction (We assumed that we are experienced with this instruction. If you are not, I'd recommend you to the article:https://blogs.oracle.com/javamagazine/post/understanding-java-method-invocation-with-invokedynamic):

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

So we move on to the method `a`  which is the bootstrap method and start with the 4th argument because its integer type gives us a lot of enlightenment.

## Function of  the BSM[^2]

![HandleType](HandleType.png)

Using Threadtear's powerful CFG[^3] (The graph above is optimized) , we can figure out that the role of the integer argument is to specify the invoke-type.

| Value | Invoke-Type |
|:-----:|:-----------:|
| 1     | Virtual     |
| 2     | Static      |
| 3     | Special     |

Although "str1", "str2" and "str3"  were obfuscated strings but their functions can be easily recognized too.

| str1 | target class's name       |
|:----:|:-------------------------:|
| str2 | target method's name      |
| str3 | target method's signature |

## Algorithm

After we have known the function of the BSM[^2], it's time for us to reverse the algorithm and decrypt obfuscated strings.

```java
<push the obfuscated string to stack>
INVOKESTATIC ESKID.b (Ljava/lang/String;)Ljava/lang/String;
<working with the decoded string>
```

Bytecode above is the pattern of string decryption. It's certain that `ESKID.b` is the method for string decryption in this case.

So let's dig deeper into the method `ESKID.b` .

![decryption_process](decryption_process.png)

Screenshot above is the last part of `ESKID.b`'s CFG[^3] . 

As seen, there are plenty of annoying junk codes. But after analyzing the crucial part of the CFG[^3] above, we can still notice that there is a loop which goes through every `char` element of the obfuscated string. What's more, we may assume that the encryption algorithm is XOR.

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

Starting with nothing, we should find BSM[^2] and decryptor method first.

```java
//find BSM
MethodNode bsm = classNode.methods.parallelStream()
        .filter(method -> method.desc.equals(bootstrapDesc))
        .findFirst().orElse(null);
if (bsm == null) return;

//find decryptor method
final InstructionPattern decryptionPattern = new InstructionPattern(
        new InvocationStep(INVOKESTATIC, classNode.name, null, "(Ljava/lang/String;)Ljava/lang/String;", false),
        new InvocationStep(INVOKESTATIC, "java/lang/Class", "forName", "(Ljava/lang/String;)Ljava/lang/Class;", false)
);
MethodInsnNode callDecryptor = (MethodInsnNode) Arrays.stream(bsm.instructions.toArray())
        .parallel()
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

After some more analysis, we found that every obfuscated class has a unique XOR key despite the decryption algorithm remains the same. What's more, the XOR key is protected by junk code. That's a stumbling block we have to deal with.

During the previous section, we have known that just before the last `ixor` instruction is about to be executed by JVM, and the value of the top stack is the XOR key. Why don't we analyze the frame statically and grab the top-stack value as the  XOR key?

The following code shows how we filter out the last XOR instruction using `Deobfuscator`'s `InstructionMatcher`

```java
final InstructionPattern algorithmPattern = new InstructionPattern(
        new OpcodeStep(IXOR),
        new OpcodeStep(I2C),
        new InvocationStep(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(C)Ljava/lang/StringBuilder;", false));
AbstractInsnNode lastIxor = Arrays.stream(decryptor.instructions.toArray())
        .parallel()
        .filter(ain -> {
            InstructionMatcher matcher = algorithmPattern.matcher(ain);
            return matcher.find() && (matcher.getCapturedInstructions("all").get(0) == ain);
        }).findFirst().orElse(null);
if (lastIxor == null) {
    logger.error("[ESKID] [StaticIndyTransformer] algorithm pattern not match!");
    return;
}
```

Then we analyzed the frame statically using the power of SimAnalyzer and get the XOR key from the top of the stack:

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

Now we have obtained all the information we need to preform the deobfuscation, and the last necessary part is how we determine the invocation type. See the code snippet below:

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

Download the complete source code of this Indy transformer using the link: [public s00n]

## Final results

![result](result.png)

Screenshot above is a part of `ESKID` method.

## What’s next?

In Part 2 we'll dig into the details of the native DLL exploration and reveal the connections between Invokedynamic and JNI.

## Footnotes

[^1]: Invokedynamic

[^2]: bootstrap method

[^3]: control flow graph
