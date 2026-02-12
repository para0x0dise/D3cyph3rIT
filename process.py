import subprocess
import re
from Crypto.Cipher import ARC4
from hashlib import sha256
from pathlib import Path
import lznt1

def decompileAutoitScript(compiledScriptPath, autoitBinDir) -> None:
    """Decompile Autoit script to au3 file"""

    # To force the process to quit, we need to set a timeout (GUI doesn't quit after the process is done)
    # 30 seconds could be changed to a higher value if needed
    try:
        result = subprocess.run(
            [str(autoitBinDir) + "/myAutToExe.exe", str(compiledScriptPath),'/q', '/s'],
            cwd=str(autoitBinDir), # To avoid any dependencies issues
            timeout=30
        )
    except Exception as e:
        return

def extractEncryptedPayload(autoitScriptFilePath) -> bytes:
    """Extract encrypted payload concatenated from Autoit script"""
    
    hexStrings = {}
    currentVar = None
    
    with open(autoitScriptFilePath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            
            # Pattern 1: $VAR = "0xHEX"
            match = re.match(r'\$(\w+)\s*=\s*"(0x[0-9A-Fa-f]+)"', line)
            if match:
                varName = match.group(1)
                hexData = match.group(2)
                hexStrings[varName] = hexData
                currentVar = varName
                continue
            
            # Pattern 2: $VAR = $VAR & "HEX"
            match = re.match(r'\$(\w+)\s*=\s*\$\1\s*&\s*"([0-9A-Fa-f]+)"', line)
            if match:
                varName = match.group(1)
                hexData = match.group(2)
                if varName in hexStrings:
                    hexStrings[varName] += hexData
                else:
                    hexStrings[varName] = hexData
                currentVar = varName
    
    return currentVar, _convertHexToBytes(list(hexStrings.values())[0])

def _convertHexToBytes(hexString):
    """
    Convert hex string to bytes
    """
    # Remove 0x prefix if present
    if hexString.startswith('0x') or hexString.startswith('0X'):
        hexString = hexString[2:]
    
    # Remove any whitespace
    hexString = hexString.replace(' ', '').replace('\n', '').replace('\r', '')
    
    # Convert to bytes
    return bytes.fromhex(hexString)


def findAutoitDeobfuscationFunction(autoitScriptPath) -> dict:
    """
    Get deobfuscation function and delimiter used
    """
    function = {}
    
    # Pattern to find the StringSplit call
    splitPattern = re.compile(
        r'Call\(StringReverse\("tilpSgnirtS"\),\s*\$\w+,\s*"(.+?)",\s*2\)',
        re.IGNORECASE
    )
    
    # Pattern to find function definition
    funcPattern = re.compile(r'Func\s+(\w+)\(', re.IGNORECASE)
    
    currentFunction = ''
    
    with open(autoitScriptPath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # Track current function
            funcMatch = funcPattern.search(line)
            if funcMatch:
                currentFunction = funcMatch.group(1)
            
            # Look for StringSplit pattern
            splitMatch = splitPattern.search(line)
            if splitMatch and currentFunction:
                delimiter = splitMatch.group(1)
                
                function["functionName"] = currentFunction
                function["delimiter"] = delimiter
                
    return function

def findBinaryEncodedStrings(autoitScriptPath, deobfFunction:str):
    """
    Find all Binary(FUNCNAME("string", key)) patterns
    """    
    rc4Keys = {}
    
    # Pattern: Binary(FUNCNAME("string", number))
    # Handles: key, key-number, number-number, etc.
    pattern = re.compile(
        rf'Binary\(({deobfFunction})\("([^"]+)",\s*([^)]+)\)\)',
        re.IGNORECASE
    )
    
    with open(autoitScriptPath, 'r', encoding='utf-8', errors='ignore') as f:
        for lineNum, line in enumerate(f, 1):
            matches = pattern.finditer(line)
            
            for match in matches:
                functionName = match.group(1)
                encodedString = match.group(2)
                keyExpression = match.group(3).strip()
                
                # Evaluate simple expressions like "9 - 2" or "7 - 1"
                try:
                    key = eval(keyExpression)
                except:
                    key = keyExpression  # Keep as string if can't evaluate
                
                rc4Keys[functionName] = {
                    'encodedString': encodedString,
                    'key': key
                }
    
    return rc4Keys


def decodeString(encoded_str, key, delimiter):
    """
    Decode encoded string
    """
    # Split by delimiter and convert to integers
    numbers = [int(x) for x in encoded_str.split(delimiter) if x.strip()]
    # Subtract key and convert to characters
    decoded = ''.join(chr(num - key) for num in numbers)
    return decoded


def decryptPayload(encryptedPayload:bytes, key:str):
    """
    Decrypt RC4 encoded string
    """
    decryptedPayload = ARC4.new(key.encode()).decrypt(encryptedPayload)
    decompressedPayload = lznt1.decompress(decryptedPayload)
    return decompressedPayload


def savePayload(payload:bytes, payloadDir:str) -> str:
    """
    Save payload to file with its sha256 hash as name
    """
    with open(payloadDir / Path(sha256(payload).hexdigest() + '.bin'), 'wb') as f:
        f.write(payload)
    return payloadDir / Path(sha256(payload).hexdigest() + '.bin')


def saveAutoitScript(autoitScript:bytes, autoitDir:str) -> str:
    """
    Save autoit script to file with its sha256 hash as name
    """
    with open(autoitDir / Path(sha256(autoitScript).hexdigest() + '.au3'), 'wb') as f:
        f.write(autoitScript)
    return autoitDir / Path(sha256(autoitScript).hexdigest() + '.au3')