"""Knowledge base: API semantics, crypto constants, UEFI GUIDs.

This is what turns "5000 unnamed functions" into a ranked list worth reading.
"""
from __future__ import annotations

import re
import struct

# ---------------------------------------------------------------- APIs ---
# category -> list of substrings matched case-insensitively against api names
API_CATEGORIES: dict[str, list[str]] = {
    "process": ["createprocess", "openprocess", "terminateprocess", "shellexecute",
                "winexec", "ntopenprocess", "ntterminateprocess", "exitprocess",
                "createtoolhelp32snapshot", "process32", "enumprocess", "getcurrentprocess",
                "ntresumeprocess", "ntsuspendprocess"],
    "thread": ["createthread", "createremotethread", "ntcreatethread", "resumethread",
               "suspendthread", "setthreadcontext", "getthreadcontext", "queueuserapc",
               "ntqueueapcthread", "thread32", "switchtothread", "rtlcreateuserthread"],
    "memory": ["virtualalloc", "virtualprotect", "virtualfree", "virtualquery",
               "writeprocessmemory", "readprocessmemory", "heapalloc", "heapcreate",
               "ntallocatevirtualmemory", "ntprotectvirtualmemory", "ntwritevirtualmemory",
               "ntreadvirtualmemory", "mapviewoffile", "createfilemapping",
               "ntmapviewofsection", "rtlmovememory", "globalalloc", "localalloc"],
    "file": ["createfile", "readfile", "writefile", "deletefile", "copyfile", "movefile",
             "findfirstfile", "findnextfile", "setfileattributes", "getfileattributes",
             "gettemppath", "getmodulefilename", "setfilepointer", "getfilesize",
             "ntcreatefile", "ntwritefile", "ntreadfile", "fopen", "fwrite", "_wfopen",
             "createdirectory", "removedirectory", "getsystemdirectory", "getwindowsdirectory"],
    "registry": ["regopenkey", "regsetvalue", "regqueryvalue", "regcreatekey",
                 "regdeletekey", "regdeletevalue", "regenumkey", "regenumvalue",
                 "regclosekey", "ntopenkey", "ntsetvaluekey", "ntquerye", "regsavekey",
                 "shregget", "shgetvalue"],
    "network": ["socket", "connect", "wsastartup", "wsaconnect", "recv", "send",
                "gethostbyname", "getaddrinfo", "inet_addr", "htons", "bind", "listen",
                "accept", "internetopen", "internetconnect", "internetreadfile",
                "httpopenrequest", "httpsendrequest", "winhttp", "urldownloadtofile",
                "dnsquery", "ftpputfile", "ftpgetfile", "icmpsendecho", "closesocket"],
    "crypto": ["cryptacquirecontext", "cryptcreatehash", "crypthashdata", "cryptderivekey",
               "cryptencrypt", "cryptdecrypt", "cryptgenkey", "cryptgenrandom",
               "cryptimportkey", "cryptexportkey", "bcrypt", "ncrypt",
               "cryptprotectdata", "cryptunprotectdata", "cryptstringtobinary",
               "cryptbinarytostring", "systemfunction032", "rtlencryptmemory"],
    "service": ["openscmanager", "createservice", "startservice", "openservice",
                "changeserviceconfig", "deleteservice", "controlservice",
                "queryservicestatus", "setservicestatus",
                "registerservicectrlhandler", "startservicectrldispatcher"],
    "injection": ["setwindowshookex", "createremotethread", "queueuserapc",
                  "ntqueueapcthread", "setthreadcontext", "ntmapviewofsection",
                  "writeprocessmemory", "ntcreatethreadex", "rtlcreateuserthread",
                  "ntunmapviewofsection", "setpropa", "setpropw"],
    "antidebug": ["isdebuggerpresent", "checkremotedebuggerpresent",
                  "ntqueryinformationprocess", "outputdebugstring",
                  "ntsetinformationthread", "debugactiveprocess",
                  "queryperformancecounter", "gettickcount", "ntclose",
                  "ntqueryobject", "ntquerysysteminformation", "unhandledexceptionfilter",
                  "setunhandledexceptionfilter", "rtladdvectoredexceptionhandler"],
    "dynamic": ["loadlibrary", "getprocaddress", "ldrloaddll", "ldrgetprocedureaddress",
                "getmodulehandle", "ldrgetdllhandle", "freelibrary"],
    "privilege": ["adjusttokenprivileges", "openprocesstoken", "lookupprivilegevalue",
                  "impersonateloggedonuser", "duplicatetokenex", "setthreadtoken",
                  "createprocessasuser", "logonuser", "reverttoself",
                  "ntadjustprivilegestoken"],
    "credential": ["credread", "credenumerate", "lsaopenpolicy", "lsaretrieveprivatedata",
                   "netuseradd", "netuserenum", "samconnect", "wnetaddconnection"],
    "keylog": ["getasynckeystate", "getkeystate", "getkeyboardstate", "setwindowshookex",
               "getforegroundwindow", "getwindowtext", "mapvirtualkey", "registerhotkey",
               "getrawinputdata", "blockinput"],
    "screen": ["bitblt", "createcompatiblebitmap", "getdc", "getwindowdc",
               "createdibsection", "printwindow", "getdibits"],
    "gui": ["createwindow", "messagebox", "showwindow", "dialogbox", "registerclass",
            "defwindowproc", "getmessage", "dispatchmessage", "sendmessage", "postmessage"],
    "com": ["coinitialize", "cocreateinstance", "clsidfromstring", "cogetobject",
            "couninitialize", "oleinitialize", "iidfromstring", "cocreateinstanceex"],
    "wmi": ["iwbem", "connectserver", "execquery", "execmethod"],
    "string": ["strcpy", "strcat", "strlen", "strcmp", "sprintf", "snprintf", "memcpy",
               "memmove", "memset", "memcmp", "wcscpy", "wcscat", "lstrcpy", "lstrcat",
               "lstrlen", "multibytetowidechar", "widechartomultibyte", "strstr",
               "strtok", "wsprintf", "_vsnprintf", "strchr", "atoi", "_wcsicmp"],
    "time": ["sleep", "getsystemtime", "getlocaltime", "queryperformancefrequency",
             "settimer", "waitforsingleobject", "waitformultipleobjects",
             "getsystemtimeasfiletime", "ntdelayexecution"],
    "sync": ["createmutex", "createevent", "createsemaphore", "openmutex",
             "enterciriticalsection", "entercriticalsection", "initializecriticalsection",
             "releasemutex", "setevent"],
    "env": ["getenvironmentvariable", "setenvironmentvariable", "getcomputername",
            "getusername", "getversionex", "getnativesysteminfo", "getsysteminfo",
            "getcommandline", "isWow64process", "getlogicalDrives", "globalmemorystatus"],
    "driver": ["iocreatedevice", "iodeleteDevice", "iocreatesymboliclink", "deviceiocontrol",
               "mmgetsystemroutineaddress", "zwopenfile", "obreferenceobject",
               "psCreateSystemThread", "iocalldriver", "mmmapiospace",
               "mdl", "kesetevent", "psLookupProcessByProcessId"],
}

# a weighting used to rank functions for triage. higher = look here first.
CATEGORY_WEIGHT = {
    "injection": 10, "antidebug": 8, "credential": 9, "keylog": 9, "privilege": 7,
    "crypto": 6, "memory": 5, "network": 6, "process": 5, "thread": 4, "registry": 4,
    "service": 5, "dynamic": 6, "screen": 5, "driver": 5, "wmi": 4, "file": 2,
    "com": 2, "gui": 1, "string": 0, "time": 1, "sync": 0, "env": 2,
}

_API_LOOKUP: dict[str, list[str]] = {}
for _cat, _pats in API_CATEGORIES.items():
    for _p in _pats:
        _API_LOOKUP.setdefault(_p, []).append(_cat)


def categorize_api(name: str) -> list[str]:
    """Return the categories an imported api belongs to."""
    n = name.lower().lstrip("_")
    # strip common decorations: Nt/Zw pairs, A/W suffix, stdcall @N
    n = re.sub(r"@\d+$", "", n)
    cats: set[str] = set()
    for pat, cs in _API_LOOKUP.items():
        if pat in n:
            cats.update(cs)
    return sorted(cats)


def api_risk(cats: list[str]) -> int:
    return sum(CATEGORY_WEIGHT.get(c, 0) for c in cats)


# ---------------------------------------------------- magic constants ---
CONSTANTS: dict[int, str] = {
    0x67452301: "MD5/SHA1 init h0",
    0xEFCDAB89: "MD5/SHA1 init h1",
    0x98BADCFE: "MD5/SHA1 init h2",
    0x10325476: "MD5/SHA1 init h3",
    0xC3D2E1F0: "SHA1 init h4",
    0x6A09E667: "SHA256/BLAKE init h0",
    0xBB67AE85: "SHA256 init h1",
    0x3C6EF372: "SHA256 init h2",
    0xA54FF53A: "SHA256 init h3",
    0x510E527F: "SHA256 init h4",
    0x9B05688C: "SHA256 init h5",
    0x1F83D9AB: "SHA256 init h6",
    0x5BE0CD19: "SHA256 init h7",
    0x428A2F98: "SHA256 K[0]",
    0xEDB88320: "CRC32 reflected poly",
    0x04C11DB7: "CRC32 poly",
    0x82F63B78: "CRC32C (Castagnoli) poly",
    0x9E3779B9: "TEA/XXTEA delta (golden ratio 32)",
    0x9E3779B97F4A7C15: "golden ratio 64 (splitmix/xxhash)",
    0x811C9DC5: "FNV-1a 32 offset basis",
    0x01000193: "FNV-1a 32 prime",
    0xCBF29CE484222325: "FNV-1a 64 offset basis",
    0x00000100000001B3: "FNV-1a 64 prime",
    0x243F6A88: "Blowfish P-array[0] / pi",
    0xB7E15163: "RC5/RC6 P32",
    0x61707865: "ChaCha/Salsa sigma[0] 'expa'",
    0x3320646E: "ChaCha/Salsa sigma[1] 'nd 3'",
    0x79622D32: "ChaCha/Salsa sigma[2] '2-by'",
    0x6B206574: "ChaCha/Salsa sigma[3] 'te k'",
    0xA3B1BAC6: "SM4 FK[0]",
    0x5A827999: "SHA1 K[0]",
    0x6ED9EBA1: "SHA1 K[1]",
    0x8F1BBCDC: "SHA1 K[2]",
    0xCA62C1D6: "SHA1 K[3]",
    0x1BD11BDA: "Threefish/Skein constant",
    0xDEADBEEF: "marker 0xdeadbeef",
    0xCAFEBABE: "marker 0xcafebabe / java class",
    0xFEEDFACE: "marker 0xfeedface / mach-o",
    0x8BADF00D: "marker 0x8badf00d",
    0xBAADF00D: "marker 0xbaadf00d (uninit heap)",
    0xC0000005: "STATUS_ACCESS_VIOLATION",
    0x4D5A: "'MZ' dos magic",
    0x5A4D: "'MZ' dos magic (LE word)",
    0x00004550: "'PE\\0\\0' signature",
    0x2E646C6C: "'.dll'",
    0x1F0FF4: "KUSER_SHARED_DATA offset",
    0x7FFE0030: "KUSER_SHARED_DATA (x86 debug flag region)",
    0x60: "PEB offset in TEB (x64)",
    0x2C: "TLS slot offset",
}

# byte tables that identify an algorithm outright
TABLES: list[tuple[str, bytes]] = [
    ("AES S-box", bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")),
    ("AES inverse S-box", bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb")),
    ("AES Rcon", bytes.fromhex("8d01020408102040801b36")),
    ("SHA256 K table", bytes.fromhex("982f8a42914468971428a2d1")),
    ("MD5 T table", bytes.fromhex("78a46ad7566b5ac7db0b70a2")),
    ("CRC32 table", bytes.fromhex("00000000963019607c6ee2ca")),
    ("CRC32 table (reflected)", bytes.fromhex("00000000770730962c610eee")),
    ("Blowfish P-array", bytes.fromhex("886a3f24d308a3852e8a191344737003")),
    ("base64 alphabet",
     b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"),
    ("base64 url alphabet",
     b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"),
    ("base32 alphabet", b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"),
    ("hex alphabet lower", b"0123456789abcdef"),
    ("DES SP table", bytes.fromhex("00808200000002080080820200000002")),
    ("ChaCha sigma", b"expand 32-byte k"),
    ("Salsa20 sigma", b"expand 16-byte k"),
    ("RC4 identity init", bytes(range(16))),
    ("Camellia sigma", bytes.fromhex("a09e667f3bcc908b")),
]


def lookup_constant(v: int) -> str | None:
    if v < 0:
        v &= 0xFFFFFFFFFFFFFFFF
    if v in CONSTANTS:
        return CONSTANTS[v]
    v32 = v & 0xFFFFFFFF
    if v32 in CONSTANTS and v32 > 0xFFFF:
        return CONSTANTS[v32]
    return None


# --------------------------------------------------------- UEFI GUIDs ---
_EFI_GUIDS_STR = {
    "5B1B31A1-9562-11D2-8E3F-00A0C969723B": "EFI_LOADED_IMAGE_PROTOCOL",
    "BC62157E-3E33-4FEC-9920-2D3B36D750DF": "EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL",
    "09576E91-6D3F-11D2-8E39-00A0C969723B": "EFI_DEVICE_PATH_PROTOCOL",
    "964E5B22-6459-11D2-8E39-00A0C969723B": "EFI_SIMPLE_FILE_SYSTEM_PROTOCOL",
    "964E5B21-6459-11D2-8E39-00A0C969723B": "EFI_BLOCK_IO_PROTOCOL",
    "A77B2472-E282-4E9F-A245-C2C0E27BBCC1": "EFI_BLOCK_IO2_PROTOCOL",
    "CE345171-BA0B-11D2-8E4F-00A0C969723B": "EFI_DISK_IO_PROTOCOL",
    "9042A9DE-23DC-4A38-96FB-7ADED080516A": "EFI_GRAPHICS_OUTPUT_PROTOCOL",
    "387477C2-69C7-11D2-8E39-00A0C969723B": "EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL",
    "387477C1-69C7-11D2-8E39-00A0C969723B": "EFI_SIMPLE_TEXT_INPUT_PROTOCOL",
    "DD9E7534-7762-4698-8C14-F58517A625AA": "EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL",
    "BB25CF6F-F1D4-11D2-9A0C-0090273FC1FD": "EFI_SERIAL_IO_PROTOCOL",
    "A19832B9-AC25-11D3-9A2D-0090273FC14D": "EFI_SIMPLE_NETWORK_PROTOCOL",
    "4CF5B200-68B8-4CA5-9EEC-B23E3F50029A": "EFI_PCI_IO_PROTOCOL",
    "2F707EBB-4A1A-11D4-9A38-0090273FC14D": "EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL",
    "3E745226-9818-45B6-A2AC-D7CD0E8BA2BC": "EFI_USB2_HC_PROTOCOL",
    "220E73B6-6BDB-4413-8405-B974B108619A": "EFI_FIRMWARE_VOLUME2_PROTOCOL",
    "8F644FA9-E850-4DB1-9CE2-0B44698E8DA4": "EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL",
    "F4CCBFB7-F6E0-47FD-9DD4-10A8F150C191": "EFI_SMM_BASE2_PROTOCOL",
    "C2702B74-800C-4131-8746-8FB5B89CE4AC": "EFI_SMM_ACCESS2_PROTOCOL",
    "18A3C6DC-5EEA-48C8-A1C1-B53389F98999": "EFI_SMM_SW_DISPATCH2_PROTOCOL",
    "EB346B97-975F-4A9F-8B22-F8E92BB3D569": "EFI_SMM_CPU_PROTOCOL",
    "ED32D533-99E6-4209-9CC0-2D72CDD998A7": "EFI_SMM_VARIABLE_PROTOCOL",
    "C68ED8E2-9DC6-4CBD-9D94-DB65ACC5C332": "EFI_SMM_COMMUNICATION_PROTOCOL",
    "3FDDA605-A76E-4F46-AD29-12F4531B3D08": "EFI_MP_SERVICES_PROTOCOL",
    "EF9FC172-A1B2-4693-B327-6D32FC416042": "EFI_HII_DATABASE_PROTOCOL",
    "A46423E3-4617-49F1-B9FF-D1BFA9115839": "EFI_SECURITY_ARCH_PROTOCOL",
    "94AB2F58-1438-4EF1-9152-18941A3A0E68": "EFI_SECURITY2_ARCH_PROTOCOL",
    "8BE4DF61-93CA-11D2-AA0D-00E098032B8C": "EFI_GLOBAL_VARIABLE",
    "D719B2CB-3D3A-4596-A3BC-DAD00E67656F": "EFI_IMAGE_SECURITY_DATABASE",
    "05AD34BA-6F02-4214-952E-4DA0398E2BB9": "EFI_DXE_SERVICES_TABLE_GUID",
    "7739F24C-93D7-11D4-9A3A-0090273FC14D": "EFI_HOB_LIST_GUID",
    "EB9D2D31-2D88-11D3-9A16-0090273FC14D": "SMBIOS_TABLE_GUID",
    "EB9D2D30-2D88-11D3-9A16-0090273FC14D": "ACPI_10_TABLE_GUID",
    "8868E871-E4F1-11D3-BC22-0080C73C8881": "EFI_ACPI_20_TABLE_GUID",
    "DCFA911D-26EB-469F-A220-38B7DC461220": "EFI_MEMORY_ATTRIBUTE_PROTOCOL",
    "6A7A5CFF-E8D9-4F70-BADA-75AB3025CE14": "EFI_COMPONENT_NAME2_PROTOCOL",
    "107A772C-D5E1-11D4-9A46-0090273FC14D": "EFI_COMPONENT_NAME_PROTOCOL",
    "18A031AB-B443-4D1A-A5C0-0C09261E9F71": "EFI_DRIVER_BINDING_PROTOCOL",
    "B9D4C360-BCFB-4F9B-9298-53C136982258": "EFI_FORM_BROWSER2_PROTOCOL",
    "330D4706-F2A0-4E4F-A369-B66FA8D54385": "EFI_HII_CONFIG_ACCESS_PROTOCOL",
    "587E72D7-CC50-4F79-8209-CA291FC1A10F": "EFI_HII_CONFIG_ROUTING_PROTOCOL",
    "D8117CFE-94A6-11D4-9A3A-0090273FC14D": "EFI_DECOMPRESS_PROTOCOL",
    "1E2ACC41-E26A-483D-AFC7-A056C34E087B": "EFI_VARIABLE_WRITE_ARCH_PROTOCOL",
    "1A1241E6-8F19-41A9-BC0E-E8EF39E06546": "EFI_HII_IMAGE_PROTOCOL",
    "31878C87-0B75-11D5-9A4F-0090273FC14D": "EFI_SIMPLE_POINTER_PROTOCOL",
    "8D59D32B-C655-4AE9-9B15-F25904992A43": "EFI_ABSOLUTE_POINTER_PROTOCOL",
    "0379BE4E-D706-437D-B037-EDB82FB772A4": "EFI_DEVICE_PATH_UTILITIES_PROTOCOL",
    "9576E91-6D3F-11D2-8E39-00A0C969723B": "EFI_DEVICE_PATH_PROTOCOL",
    "CCCB0C28-4B24-11D5-9A5A-0090273FC14D": "EFI_PCI_PLATFORM_PROTOCOL",
    "F541796D-A62E-4954-A775-9584F61B9CDD": "EFI_TCG_PROTOCOL",
    "607F766C-7455-42BE-930B-E4D76DB2720F": "EFI_TCG2_PROTOCOL",
    "0FD96974-23AA-4CDC-B9CB-98D17750322A": "EFI_HII_STRING_PROTOCOL",
    "D3B36F2C-D551-11D4-9A46-0090273FC14D": "EFI_DEBUG_SUPPORT_PROTOCOL",
    "2755590C-6F3C-42FA-9EA4-A3BA543CDA25": "EFI_DEBUG_PORT_PROTOCOL",
    "E5DD1403-D622-C24E-8488-C71B17F5E802": "EFI_ADAPTER_INFORMATION_PROTOCOL",
}


def _guid_to_bytes(s: str) -> bytes:
    """Canonical GUID string -> little-endian in-memory layout (EFI_GUID)."""
    p = s.split("-")
    if len(p) != 5:
        raise ValueError(s)
    d1 = int(p[0], 16)
    d2 = int(p[1], 16)
    d3 = int(p[2], 16)
    d4 = bytes.fromhex(p[3] + p[4])
    return struct.pack("<IHH", d1, d2, d3) + d4


def bytes_to_guid(b: bytes) -> str:
    d1, d2, d3 = struct.unpack_from("<IHH", b, 0)
    rest = b[8:16]
    return (f"{d1:08X}-{d2:04X}-{d3:04X}-"
            f"{rest[:2].hex().upper()}-{rest[2:].hex().upper()}")


EFI_GUIDS: dict[bytes, str] = {}
for _s, _n in _EFI_GUIDS_STR.items():
    try:
        EFI_GUIDS[_guid_to_bytes(_s)] = _n
    except ValueError:
        pass


# ----------------------------------------- EFI service table offsets ---
# offsets into EFI_BOOT_SERVICES / EFI_RUNTIME_SERVICES for x64 (8-byte slots)
EFI_BOOT_SERVICES = {
    0x18: "RaiseTPL", 0x20: "RestoreTPL", 0x28: "AllocatePages",
    0x30: "FreePages", 0x38: "GetMemoryMap", 0x40: "AllocatePool",
    0x48: "FreePool", 0x50: "CreateEvent", 0x58: "SetTimer",
    0x60: "WaitForEvent", 0x68: "SignalEvent", 0x70: "CloseEvent",
    0x78: "CheckEvent", 0x80: "InstallProtocolInterface",
    0x88: "ReinstallProtocolInterface", 0x90: "UninstallProtocolInterface",
    0x98: "HandleProtocol", 0xA0: "Reserved", 0xA8: "RegisterProtocolNotify",
    0xB0: "LocateHandle", 0xB8: "LocateDevicePath",
    0xC0: "InstallConfigurationTable", 0xC8: "LoadImage", 0xD0: "StartImage",
    0xD8: "Exit", 0xE0: "UnloadImage", 0xE8: "ExitBootServices",
    0xF0: "GetNextMonotonicCount", 0xF8: "Stall", 0x100: "SetWatchdogTimer",
    0x108: "ConnectController", 0x110: "DisconnectController",
    0x118: "OpenProtocol", 0x120: "CloseProtocol",
    0x128: "OpenProtocolInformation", 0x130: "ProtocolsPerHandle",
    0x138: "LocateHandleBuffer", 0x140: "LocateProtocol",
    0x148: "InstallMultipleProtocolInterfaces",
    0x150: "UninstallMultipleProtocolInterfaces", 0x158: "CalculateCrc32",
    0x160: "CopyMem", 0x168: "SetMem", 0x170: "CreateEventEx",
}

EFI_RUNTIME_SERVICES = {
    0x18: "GetTime", 0x20: "SetTime", 0x28: "GetWakeupTime",
    0x30: "SetWakeupTime", 0x38: "SetVirtualAddressMap", 0x40: "ConvertPointer",
    0x48: "GetVariable", 0x50: "GetNextVariableName", 0x58: "SetVariable",
    0x60: "GetNextHighMonotonicCount", 0x68: "ResetSystem",
    0x70: "UpdateCapsule", 0x78: "QueryCapsuleCapabilities",
    0x80: "QueryVariableInfo",
}

EFI_SYSTEM_TABLE = {
    0x18: "FirmwareVendor", 0x20: "FirmwareRevision", 0x28: "ConsoleInHandle",
    0x30: "ConIn", 0x38: "ConsoleOutHandle", 0x40: "ConOut",
    0x48: "StandardErrorHandle", 0x50: "StdErr", 0x58: "RuntimeServices",
    0x60: "BootServices", 0x68: "NumberOfTableEntries", 0x70: "ConfigurationTable",
}
