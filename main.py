import parser as Parser
import deobfuscator as Deobfuscator
import analyzer as Analyzer
import process as Process
import argparse
import os
import sys
from cleanup import cleanup

def runDeobfuscation(filepath):
    """
    Execute full deobfuscation pipeline using pure functions
    Returns: context with all results
    """
    try:
        print(f"[+] Running functional parser on {filepath}\n")
        
        # Step 1: Locate and extract archive contents (NSIS, CAB)
        print(f"[+] Step 1: Locating Archive....")
        
        # Create initial context
        ctx = Parser.createContext(filepath)
        
        # Identify archive type (NSIS, CAB)
        archiveType = Parser.defineArchiveFileType(ctx['filepath'])
        print(f"[*] Archive file type: {archiveType}")
        
        # Extract archive
        ctx = Parser.locateArchiveFile(ctx, archiveType)
        print(f"[*] Extracted to: {ctx['finalDir']}")
        
        # Find batch script (Which one is concatenating files?)
        ctx['batchScriptPath'] = Parser.locateBatchScript(ctx['finalDir'])
        print(f"[*] Found batch script: {ctx['batchScriptPath']}")
        
        # Step 2: Parse batch script (Extract variables and commands)
        print(f"\n[+] Step 2: Parsing Batch Script....")
        ctx = Parser.parseBatchScript(ctx)
        print(f"[*] Found {len(ctx['variables'])} variables")
        print(f"[*] Found {len(ctx['commands'])} commands")
        
        # Step 3: Deobfuscate (with dynamic variable tracking) - Find out concatenated files
        print(f"\n[+] Step 3: Deobfuscating (tracking dynamic variables)...")
        initialVarCount = len(ctx['variables'])
        
        ctx['commands'], finalVariables = Deobfuscator.multiPassDeobfuscation(
            ctx['commands'],
            ctx['variables'],
            maxPasses=5
        )

        finalVarCount = len(finalVariables)
        print(f"[*] Deobfuscation complete")
        print(f"[*] Initial variables: {initialVarCount}")
        print(f"[*] Final variables: {finalVarCount}")
        print(f"[*] New variables defined during execution: {finalVarCount - initialVarCount}")
        
        # Step 4: Analyze commands - Start concatenating files
        print(f"\n[+] Step 4: Analyzing commands...")
        analysis = Analyzer.analyzeCommands(ctx)
        print(f"[*] Analysis complete")

        print(f"\n[+] Step 5: Decompiling Autoit script...")
        Process.decompileAutoitScript(analysis['autoitOutputFile'], ctx['autoitBinDir'])

        autoitScriptPath = str(ctx['autoitOutputFile']) + '.au3'
        if os.path.exists(autoitScriptPath):
            print(f"[*] Autoit script is decompiled successfully")
            autoitScriptContents = open(autoitScriptPath, 'rb').read()
            autoitScript = Process.saveAutoitScript(autoitScriptContents, ctx['payloadDir'])
            print(f"[*] {autoitScript} is saved successfully")
            deobfuscationFunction = Process.findAutoitDeobfuscationFunction(autoitScript)
            print(f"[*] Deobfuscation function: {deobfuscationFunction['functionName']}")
            print(f"[*] Deobfuscation delimiter: {deobfuscationFunction['delimiter']}")

            variableName, encryptedPayload = Process.extractEncryptedPayload(autoitScript)
            print(f"[*] Variable name: {variableName}")
            print(f"[*] Payload starts with: {encryptedPayload[0:10]}")

            rc4EncodingStrings = Process.findBinaryEncodedStrings(autoitScript, deobfuscationFunction['functionName'])
            print(f"[*] RC4 encoding strings: {rc4EncodingStrings.get(deobfuscationFunction['functionName']).get('encodedString')}")

            rc4Key = Process.decodeString(rc4EncodingStrings[deobfuscationFunction['functionName']].get('encodedString'), rc4EncodingStrings[deobfuscationFunction['functionName']].get('key'), deobfuscationFunction['delimiter'])
            print(f"[*] RC4 key: {rc4Key}")

            decryptedPayload = Process.decryptPayload(encryptedPayload, rc4Key)
            payloadPath = Process.savePayload(decryptedPayload, ctx['payloadDir'])
            print(f"[*] Payload saved to: {payloadPath}")

    except Exception as e:
        print(f"[x] Error: {e}")

    finally:
        cleanup(ctx['finalDir'])
        cleanup(ctx['extractedDir'])
        cleanup(ctx['autoitDir'])

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Malware Deobfuscation Pipeline')
    parser.add_argument('-f', type=str, help='Path to the malware obfuscated file')
    parser.add_argument('-d', type=str, help='Directory of malware obfuscated files')
    args = parser.parse_args()
    filepath = args.f
    fileDirectory = args.d
    
    if args.d:
        for file in os.listdir(fileDirectory):
            filepath = os.path.join(fileDirectory, file)
            context = runDeobfuscation(filepath)
    elif args.f:
        context = runDeobfuscation(filepath)
    else:
        print(f"[x] Error: No filepath or file directory provided")
        sys.exit(1)