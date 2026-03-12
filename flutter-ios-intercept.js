/* Global variables */
var appId = null;
var appId_iOS = null;

var BURP_PROXY_IP = "192.168.1.6";   // ← YOUR BURP IP
var BURP_PROXY_PORT = 8080;           // ← YOUR BURP PORT

var flutter_base = null;
var flutter_size = null;

var PT_LOAD_rodata_p_memsz = null;
var PT_LOAD_text_p_vaddr = null;
var PT_LOAD_text_p_memsz = null;
var PT_GNU_RELRO_p_vaddr = null;
var PT_GNU_RELRO_p_memsz = null;

var TEXT_segment_text_section_offset = null;
var TEXT_segment_text_section_size = null;
var TEXT_segment_cstring_section_offset = null;
var TEXT_segment_cstring_section_size = null;
var DATA_segment_const_section_offset = null;
var DATA_segment_const_section_size = null;

var ssl_client_string_pattern_found_addr = null;
var verify_cert_chain_func_addr = null;
var handshake_string_pattern_found_addr = null;
var verify_peer_cert_func_addr = null;

var Socket_CreateConnect_string_pattern_found_addr = null;
var Socket_CreateConnect_func_addr = null;

var GetSockAddr_func_addr = null;
var sockaddr = null;

function findAppId() {
    if (Process.platform === "linux") {
        var pm = Java.use('android.app.ActivityThread').currentApplication();
        return pm.getApplicationContext().getPackageName();
    } else {
        return ObjC.classes.NSBundle.mainBundle().bundleIdentifier().toString();
    }
}

function convertHexToByteString(hexString) {
    let cleanHexString = hexString.startsWith('0x') ? hexString.slice(2) : hexString;
    if (cleanHexString.length % 2 !== 0) cleanHexString = '0' + cleanHexString;
    let byteArray = cleanHexString.match(/.{1,2}/g);
    byteArray.reverse();
    return byteArray.join(' ');
}

function convertIpToByteArray(ipString) {
    return ipString.split('.').map(octet => parseInt(octet, 10));
}

function convertArrayBufferToHex(buffer) {
    let hexArray = [];
    let uint8Array = new Uint8Array(buffer);
    for (let byte of uint8Array) hexArray.push(byte.toString(16).padStart(2, '0'));
    return hexArray.join(' ');
}

function byteFlip(number) {
    let highByte = (number >> 8) & 0xFF;
    let lowByte = number & 0xFF;
    return (lowByte << 8) | highByte;
}

function scanMemory(scan_start_addr, scan_size, pattern, for_what) {
    Memory.scan(scan_start_addr, scan_size, pattern, {
        onMatch: function(address, size){
            if (for_what == "ssl_client") {
                ssl_client_string_pattern_found_addr = address;
                console.log(`[*] ssl_client string found at: ${address}`);
            }
            else if (for_what == "ssl_client_adrp_add") {
                var adrp, add;
                var disasm = Instruction.parse(address);
                if (disasm.mnemonic == "adrp") {
                    adrp = disasm.operands.find(op => op.type === 'imm')?.value;
                    disasm = Instruction.parse(disasm.next);
                    if (disasm.mnemonic != "add") disasm = Instruction.parse(disasm.next);
                    add = disasm.operands.find(op => op.type === 'imm')?.value;
                    if (adrp != undefined && add != undefined && ptr(adrp).add(add).toString() == ssl_client_string_pattern_found_addr.toString()) {
                        for (let off = 0;; off += 4) {
                            disasm = Instruction.parse(address.sub(off));
                            if (disasm.mnemonic == "sub") {
                                disasm = Instruction.parse(disasm.next);
                                if (disasm.mnemonic == "stp" || disasm.mnemonic == "str") {
                                    verify_cert_chain_func_addr = address.sub(off);
                                    console.log(`[*] verify_cert_chain @ ${verify_cert_chain_func_addr}`);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            else if (for_what == "handshake") {
                for (let off = 0;; off += 1) {
                    var arrayBuff = new Uint8Array(ptr(address).sub(0x6).sub(off).readByteArray(6));
                    var hexarray = convertArrayBufferToHex(arrayBuff);
                    if (hexarray == "2e 2e 2f 2e 2e 2f") {
                        handshake_string_pattern_found_addr = ptr(address).sub(0x6).sub(off);
                        console.log(`[*] handshake string found at: ${address}`);
                        break;
                    }
                }
                appId_iOS = findAppId();
            }
            else if (for_what == "handshake_adrp_add") {
                var adrp, add;
                var disasm = Instruction.parse(address);
                if (disasm.mnemonic == "adrp") {
                    adrp = disasm.operands.find(op => op.type === 'imm')?.value;
                    disasm = Instruction.parse(disasm.next);
                    if (disasm.mnemonic != "add") disasm = Instruction.parse(disasm.next);
                    add = disasm.operands.find(op => op.type === 'imm')?.value;
                    if (adrp != undefined && add != undefined && ptr(adrp).add(add).toString() == handshake_string_pattern_found_addr.toString()) {
                        console.log(`[*] Found adrp add for handshake: ${address}`);
                        for (let off = 0;; off += 4) {
                            disasm = Instruction.parse(address.sub(off));
                            if (disasm.mnemonic == "sub") {
                                disasm = Instruction.parse(disasm.next);
                                if (disasm.mnemonic == "stp" || disasm.mnemonic == "str") {
                                    verify_peer_cert_func_addr = address.sub(off);
                                    console.log(`[*] verify_peer_cert @ ${verify_peer_cert_func_addr}`);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            else if (for_what == "Socket_CreateConnect") {
                Socket_CreateConnect_string_pattern_found_addr = address;
                console.log(`[*] Socket_CreateConnect string found at: ${address}`);
            }
            else if (for_what == "Socket_CreateConnect_func_addr") {
                Socket_CreateConnect_func_addr = address.sub(0x10).readPointer();
                console.log(`[*] Socket_CreateConnect func @ ${Socket_CreateConnect_func_addr}`);
                if (Process.arch == 'arm64') {
                    var bl_count = 0;
                    for (let off = 0;; off += 4) {
                        let disasm = Instruction.parse(Socket_CreateConnect_func_addr.add(off));
                        if (disasm.mnemonic == "bl") {
                            bl_count++;
                            if (bl_count == 2) {
                                GetSockAddr_func_addr = ptr(disasm.operands.find(op => op.type === 'imm')?.value);
                                console.log(`[*] GetSockAddr @ ${GetSockAddr_func_addr}`);
                                break;
                            }
                        }
                    }
                }
            }
        },
        onComplete: function(){
            if (for_what == "ssl_client" && ssl_client_string_pattern_found_addr != null) {
                if (Process.arch == 'arm64') {
                    scanMemory(flutter_base.add(PT_LOAD_text_p_vaddr), PT_LOAD_text_p_memsz, "?9 ?? ?? ?0 29 ?? ?? 91", "ssl_client_adrp_add");
                }
            }
            else if (for_what == "handshake" && handshake_string_pattern_found_addr != null) {
                var adrp_add_pattern = "?2 ?? 00 ?0 42 ?? ?? 91 00 02 80 52 21 22 80 52 c3 29 80 52";
                if (appId_iOS == null) {
                    Thread.sleep(0.1);
                    appId_iOS = findAppId();
                }
                scanMemory(flutter_base.add(TEXT_segment_text_section_offset), TEXT_segment_text_section_size, adrp_add_pattern, "handshake_adrp_add");
            }
            else if (for_what == "Socket_CreateConnect" && Socket_CreateConnect_string_pattern_found_addr != null) {
                var addr_to_find = convertHexToByteString(Socket_CreateConnect_string_pattern_found_addr.toString());
                scanMemory(flutter_base.add(DATA_segment_const_section_offset), DATA_segment_const_section_size, addr_to_find, "Socket_CreateConnect_func_addr");
            }
            console.log(`[*] scan done: ${for_what}`);
        }
    });
}

function parseMachO(base) {
    base = ptr(base);
    var magic = base.readU32();
    if (magic != 0xfeedfacf) { console.log('Unknown magic: ' + magic); return; }
    var number_of_commands_offset = 0x10;
    var command_size_offset = 0x4;
    var segment_name_offset = 0x8;
    var vm_address_offset = 0x18;
    var vm_size_offset = 0x20;
    var file_offset = 0x28;
    var number_of_sections_offset = 0x40;
    var section64_header_base_offset = 0x48;
    var section64_header_size = 0x50;
    var cmdnum = base.add(number_of_commands_offset).readU32();
    var cmdoff = 0x20;
    for (var i = 0; i < cmdnum; i++) {
        var cmd = base.add(cmdoff).readU32();
        var cmdsize = base.add(cmdoff + command_size_offset).readU32();
        if (cmd === 0x19) {
            var segname = base.add(cmdoff + segment_name_offset).readUtf8String();
            var nsects = base.add(cmdoff + number_of_sections_offset).readU8();
            var secbase = base.add(cmdoff + section64_header_base_offset);
            if (base.add(cmdoff + command_size_offset).readU32() >= section64_header_base_offset + nsects * section64_header_size) {
                var TEXT_segment_text_section_index = 0;
                var TEXT_segment_cstring_section_index = 0;
                var DATA_segment_const_section_index = 0;
                for (var j = 0; j < nsects; j++) {
                    var secname = secbase.add(j * section64_header_size).readUtf8String();
                    var section_start_offset = secbase.add(j * section64_header_size + 0x30).readU32();
                    if (segname === '__TEXT' && secname === '__text') {
                        TEXT_segment_text_section_index = j;
                        TEXT_segment_text_section_offset = section_start_offset;
                    } else if (segname === '__TEXT' && j == (TEXT_segment_text_section_index + 1)) {
                        TEXT_segment_text_section_size = section_start_offset - TEXT_segment_text_section_offset;
                    } else if (segname === '__TEXT' && secname === '__cstring') {
                        TEXT_segment_cstring_section_index = j;
                        TEXT_segment_cstring_section_offset = section_start_offset;
                    } else if (segname === '__TEXT' && j == (TEXT_segment_cstring_section_index + 1)) {
                        TEXT_segment_cstring_section_size = section_start_offset - TEXT_segment_cstring_section_offset;
                    } else if (segname === '__DATA' && secname === '__const') {
                        DATA_segment_const_section_index = j;
                        DATA_segment_const_section_offset = section_start_offset;
                    } else if (segname === '__DATA' && j == (DATA_segment_const_section_index + 1)) {
                        DATA_segment_const_section_size = section_start_offset - DATA_segment_const_section_offset;
                    }
                }
            }
        }
        cmdoff += cmdsize;
    }
}

function hook(target) {
    if (target == "GetSockAddr") {
        Interceptor.attach(GetSockAddr_func_addr, {
            onEnter: function(args) { sockaddr = args[1]; },
            onLeave: function(retval) {}
        });
        Interceptor.attach(Module.getGlobalExportByName("socket"), {
            onEnter: function(args) {
                var overwrite = false;
                if (Process.platform === 'darwin' && sockaddr != null && ptr(sockaddr).add(0x1).readU8() == 2) {
                    overwrite = true;
                }
                if (overwrite) {
                    console.log(`[*] Redirecting → ${BURP_PROXY_IP}:${BURP_PROXY_PORT}`);
                    ptr(sockaddr).add(0x2).writeU16(byteFlip(BURP_PROXY_PORT));
                    ptr(sockaddr).add(0x4).writeByteArray(convertIpToByteArray(BURP_PROXY_IP));
                }
            },
            onLeave: function(retval) {}
        });
    }
    else if (target == "verifyPeerCert") {
        Interceptor.replace(verify_peer_cert_func_addr, new NativeCallback((pathPtr, flags) => {
            console.log(`[*] verify_peer_cert bypassed`);
            return 0;
        }, 'int', ['pointer', 'int']));
    }
}

// ── Main ──
var target_flutter_library = "Flutter.framework/Flutter";

var awaitForCondition = function(callback) {
    var module_loaded = 0;
    var int = setInterval(function() {
        Process.enumerateModules()
        .filter(function(m){ return m['path'].indexOf(target_flutter_library) != -1; })
        .forEach(function(m) {
            target_flutter_library = target_flutter_library.split('/').pop();
            console.log(`[*] Flutter loaded!`);
            var base = Process.getModuleByName(target_flutter_library).base;
            module_loaded = 1;
            clearInterval(int);
            callback(+base);
        });
    }, 0);
};

function init(base) {
    flutter_base = ptr(base);
    console.log(`[*] Flutter base: ${flutter_base}`);

    parseMachO(flutter_base);
    console.log(`[*] __text offset: ${TEXT_segment_text_section_offset} size: ${TEXT_segment_text_section_size}`);
    console.log(`[*] __cstring offset: ${TEXT_segment_cstring_section_offset} size: ${TEXT_segment_cstring_section_size}`);

    var handshake_string = '74 68 69 72 64 5f 70 61 72 74 79 2f 62 6f 72 69 6e 67 73 73 6c 2f 73 72 63 2f 73 73 6c 2f 68 61 6e 64 73 68 61 6b 65 2e 63 63';
    var Socket_CreateConnect_string = '53 6f 63 6b 65 74 5f 43 72 65 61 74 65 43 6f 6e 6e 65 63 74 00';

    scanMemory(flutter_base.add(TEXT_segment_cstring_section_offset), TEXT_segment_cstring_section_size, handshake_string, "handshake");
    scanMemory(flutter_base.add(TEXT_segment_cstring_section_offset), TEXT_segment_cstring_section_size, Socket_CreateConnect_string, "Socket_CreateConnect");

    var int_getSockAddr = setInterval(() => {
        if (GetSockAddr_func_addr != null) {
            console.log("[*] Hooking GetSockAddr...");
            hook("GetSockAddr");
            clearInterval(int_getSockAddr);
        }
    }, 0);

    var int_verifyPeerCert = setInterval(() => {
        if (verify_peer_cert_func_addr != null) {
            console.log("[*] Hooking verifyPeerCert...");
            hook("verifyPeerCert");
            clearInterval(int_verifyPeerCert);
        }
    }, 0);
}

awaitForCondition(init);