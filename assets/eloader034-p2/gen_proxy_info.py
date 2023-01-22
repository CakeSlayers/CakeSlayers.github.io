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

    # extract clazz,method,signature from lea*3 pattern in JNI functions
    leaList = list(
        filter(lambda addr: print_insn_mnem(addr) == "lea", list(FuncItems(func)))
    )
    if len(leaList) != 3:
        print(
            "[ERROR] JNI function %s doesn't match lea*3 pattern!"
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

    # find call/jmp to thunk function
    callThunk = list(
        filter(
            lambda addr: print_insn_mnem(addr) == "call"
            or print_insn_mnem(addr) == "jmp",
            list(FuncItems(func)),
        )
    )
    if len(callThunk) != 1:
        print(
            "[ERROR] could not find JMP/CALL thunk function in JNI function %s"
            % (get_func_name(func))
        )
        continue
    thunkFuncAddr = get_operand_value(callThunk[0], 0)

    # check whether the thunk function has JMP to the JNI-helper function
    if print_insn_mnem(thunkFuncAddr) != "jmp":
        print(
            "[ERROR] thunk function %s doesn't have jmp to JNI-helper function!"
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
    JniHelperFuncItems = FuncItems(get_operand_value(thunkFuncAddr, 0))
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
    proxy_call_infos += {
        proxyMethod: {
            "clazz": clazz,
            "method": method,
            "signature": sig,
            "type": invokeType
        }
    }

with open("proxy_info.json", "w", encoding="utf-8") as f:
    json.dump(proxy_call_infos, f, indent=4, sort_keys=False)
    print("data exported!")
