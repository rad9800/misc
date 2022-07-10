import sys
import os 
import hashlib      # Generating hashes 
import pefile

# https://github.com/erocarrera/pefile/blob/0d5ce5e0193c878cd57636b438b3746ffc3ae7e3/pefile.py#L1324
def getEntropy(data):
    import math
    from collections import Counter
    
    if not data:
        return 0.0

    occurences = Counter(bytearray(data))

    entropy = 0
    for x in occurences.values():
        p_x = float(x) / len(data)
        entropy -= p_x * math.log(p_x, 2)

    return entropy

def printImports(pe):
    for imports in pe.DIRECTORY_ENTRY_IMPORT:
        print(imports.dll.decode().lower())
        for i in imports.imports:
            print("\t", hex(i.address), i.name.decode())

def getArch(pe):
    if hex(pe.OPTIONAL_HEADER.Magic) == '0x10b':
        return "x86"
    elif hex(pe.OPTIONAL_HEADER.Magic) == '0x20b': 
        return "x64_86"            
        
def getTimestamp(pe):
    import datetime
    epoch_time = pe.FILE_HEADER.TimeDateStamp
    date_time = datetime.datetime.fromtimestamp(epoch_time)
    return date_time
    
def checkImports(pe):
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        print("NO IMPORTS")

if __name__ == "__main__":
    try:
        pe = pefile.PE(sys.argv[1])
        # Architecture is worth noting
        print("File\t\t:", sys.argv[1].split("\\")[-1])
        print("MD5 hash\t:", hashlib.md5(pe.__data__).hexdigest())
        print("SHA256 hash\t:", hashlib.sha256(pe.__data__).hexdigest())
        print("Architecture\t:", getArch(pe))
        print("Timestamp \t:", getTimestamp(pe))
        print("Total Entropy \t:",getEntropy(pe.__data__))
        print("Size \t\t: {:.1f}".format(len(pe.__data__)/1000), "KB")
        print("Sections\t:")
        for section in pe.sections:
            print("\tName\t", section.Name.decode('UTF-8'))
            print("\tSize\t", section.SizeOfRawData, "bytes")
            print("\tEntropy\t", getEntropy(section.get_data()), "\n")
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            print("Imports \t: NONE!")
        else:
            print("Imports \t:")
            printImports(pe)
        strings = "\\\\live.sysinternals.com@SSL\\DavWWWRoot\\strings.exe -accepteula -n 7 " + sys.argv[1]
        os.system(strings)
    except:
        print("python3 measure.py <path to executable>")
