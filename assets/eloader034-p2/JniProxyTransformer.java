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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.javadeobfuscator.deobfuscator.config.TransformerConfig;
import com.javadeobfuscator.deobfuscator.transformers.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.MethodInsnNode;

import java.io.FileReader;
import java.lang.reflect.Type;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;


public class JniProxyTransformer extends Transformer<TransformerConfig> {

    AtomicInteger inlined = new AtomicInteger();

    @Override
    public boolean transform() throws Throwable {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        Type infoMapType = new TypeToken<Map<String, Map<String, String>>>() {}.getType();
        Map<String, Map<String, String>> proxyMap = gson.fromJson(new FileReader("path/to/proxy_info.json"), infoMapType);
        classNodes().stream()
                .filter(classNode -> !"ESKID".equals(classNode.name))
                .flatMap(classNode -> classNode.methods.stream())
                .forEach(method -> Arrays.stream(method.instructions.toArray())
                        .filter(ain -> ain instanceof MethodInsnNode
                                && "ESKID".equals(((MethodInsnNode) ain).owner))
                        .forEach(ain -> {
                            MethodInsnNode callNative = (MethodInsnNode) ain;
                            Map<String, String> proxyInfo = proxyMap.get(callNative.name);
                            switch (proxyInfo.get("type")) {
                                case ("static"): {
                                    method.instructions.set(ain, new MethodInsnNode(INVOKESTATIC, proxyInfo.get("clazz"), proxyInfo.get("method"), proxyInfo.get("signature")));
                                    break;
                                }

                                case ("virtual"): {
                                    int opcode;
                                    if (classpath.get(proxyInfo.get("clazz")).access == Opcodes.ACC_INTERFACE) {
                                        opcode = Opcodes.INVOKEINTERFACE;
                                    } else {
                                        opcode = Opcodes.INVOKEVIRTUAL;
                                    }
                                    method.instructions.set(ain, new MethodInsnNode(opcode, proxyInfo.get("clazz"), proxyInfo.get("method"), proxyInfo.get("signature")));
                                    break;
                                }

                                default: {
                                    logger.error("[JniProxy] failed to get invocation type");
                                    return;
                                }
                            }
                            inlined.getAndIncrement();
                        }));
        logger.info("[JniProxy] inlined {} call JNI proxy", inlined);
        return inlined.get() > 0;
    }
}
