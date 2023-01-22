// Author: BotDebug (botdebug@outlook.com)
// Copyright 2022 HorizonLN
//
// HorizonLN licenses this file to you under the Apache License, Version
// 2.0 (the "License"); you may not use this file except in compliance with the
// License. You may obtain a copy of the License at:
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.
package com.javadeobfuscator.deobfuscator.transformers.eskid;

import com.javadeobfuscator.deobfuscator.config.TransformerConfig;
import com.javadeobfuscator.deobfuscator.matcher.InstructionMatcher;
import com.javadeobfuscator.deobfuscator.matcher.InstructionPattern;
import com.javadeobfuscator.deobfuscator.matcher.InvocationStep;
import com.javadeobfuscator.deobfuscator.matcher.OpcodeStep;
import com.javadeobfuscator.deobfuscator.transformers.Transformer;
import com.javadeobfuscator.deobfuscator.utils.InstructionModifier;
import com.javadeobfuscator.deobfuscator.utils.TransformerHelper;
import me.coley.analysis.SimAnalyzer;
import me.coley.analysis.SimInterpreter;
import me.coley.analysis.value.AbstractValue;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.analysis.AnalyzerException;
import org.objectweb.asm.tree.analysis.Frame;

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

public class StaticIndyTransformer extends Transformer<TransformerConfig> {
    AtomicInteger inlined = new AtomicInteger();

    @Override
    public boolean transform() throws Throwable {
        String bootstrapDesc = "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;)Ljava/lang/invoke/CallSite;";
        classNodes().forEach(classNode -> {
            //find BSM
            MethodNode bsm = classNode.methods.stream()
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

            //find the last XOR instruction
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

            //get top stack value
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
//                logger.debug("xor key found: {}", xorKey);
            } catch (AnalyzerException e) {
                logger.error("failed to get frames in class: {} , method: {} , insn: {}", classNode.name, decryptor.name, TransformerHelper.insnToString(e.node));
                e.printStackTrace();
                return;
            }

            classNode.methods.stream()
                    .filter(method -> method != decryptor && method != bsm)
                    .forEach(method -> {
                        InstructionModifier modifier = new InstructionModifier();
                        Arrays.stream(method.instructions.toArray())
                                .filter(ain -> ain instanceof InvokeDynamicInsnNode
                                        && ((InvokeDynamicInsnNode) ain).bsm.getOwner().equals(classNode.name)
                                        && ((InvokeDynamicInsnNode) ain).bsm.getName().equals(bsm.name)
                                        && ((InvokeDynamicInsnNode) ain).bsm.getDesc().equals(bsm.desc))
                                .forEach(indy -> {
                                    //determine the type of invocation
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

                                    //decrypt strings and get the real invocation
                                    String owner = decrypt(((String) bsmArgs[0]), xorKey).replace('.', '/');
                                    String name = decrypt((String) bsmArgs[1], xorKey);
                                    String desc = decrypt((String) bsmArgs[2], xorKey);
//                                    logger.debug("real owner: {}", owner);
//                                    logger.debug("real name: {}", name);
//                                    logger.debug("real desc: {}", desc);
                                    modifier.replace(indy, new MethodInsnNode(opcode, owner, name, desc, false));
                                    inlined.getAndIncrement();
                                });
                        modifier.apply(method);
                    });
            classNode.methods.remove(bsm);
            classNode.methods.remove(decryptor);

        });
        logger.info("[ESKID] [StaticIndyTransformer] Inlined {} indys", inlined.get());
        return inlined.get() > 0;
    }

    private AbstractValue getTopStack(Frame<AbstractValue> frame) {
        return (frame != null && frame.getStackSize() - 1 >= 0) ? frame.getStack(frame.getStackSize() - 1) : null;
    }

    private String decrypt(String enc, int key) {
        StringBuilder dec = new StringBuilder();
        for (char c : enc.toCharArray()) {
            dec.append((char) (c ^ key));
        }
        return String.valueOf(dec);
    }

}
