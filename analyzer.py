from pathlib import Path
import re

def analyzeCommands(context) -> dict:
    """Analyze all commands and return analysis result"""
    pattern = r'(?i)copy\s+.*?/b.*?\+.*?'
    
    for cmd in context['commands']:
        if re.search(pattern, cmd['deobfuscated']) and '..\\' in cmd['deobfuscated']:
            context['autoitOutputFile'] = _executeCopyCommand(cmd['deobfuscated'], context['finalDir'], context['autoitDir'])
            break

    return context

def _parseCopyCommand(commandText) -> dict:
    """
    Parse copy command to extract source files and destination
    """
    # Remove 'copy' keyword and flags
    text = commandText.lower().replace('copy', '', 1).replace('cmd', '', 1).strip()
    
    # Remove common flags
    flags = ['/b', '/y', '/c']
    for flag in flags:
        text = text.replace(flag, '').replace(flag.upper(), '')
    
    text = text.strip()
    
    # Split by '+' to get all parts
    parts = [p.strip() for p in text.split('+')]
    
    if len(parts) == 0:
        return {'sourceFiles': [], 'destination': None}
    
    # Last part might be "file1 file2 destination" or just "destination"
    # Need to handle: "..\\file7.eml R" -> source: ..\\file7.eml, dest: R
    lastPart = parts[-1].strip()
    lastPartTokens = lastPart.split()
    
    if len(lastPartTokens) > 1:
        # Last part has multiple tokens: "..\\file7.eml R"
        sourceFiles = parts[:-1]  # All previous parts
        sourceFiles.append(lastPartTokens[0])  # First token of last part
        destination = lastPartTokens[-1]  # Last token is destination
    else:
        # All parts are sources, no explicit destination (overwrites first file)
        sourceFiles = parts
        destination = parts[0] if parts else None
    
    # Clean up source files
    sourceFiles = [f.strip() for f in sourceFiles if f.strip()]
    
    return {
        'sourceFiles': sourceFiles,
        'destination': destination
    }

def _concatenateFiles(sourceFiles, destination, finalDir, autoitDir) -> Path:
    """
    Physically concatenate multiple files into one destination file
    """
    baseDir = Path(finalDir)
    destPath = autoitDir / destination
    
    print(f"[*] Concatenating {len(sourceFiles)} files into {destPath.name}")
    
    # Open destination in binary write mode
    with open(destPath, 'wb') as outFile:
        for sourceFile in sourceFiles:
            # Resolve relative paths
            if sourceFile.startswith('..'):
                # Parent directory reference
                sourcePath = baseDir / sourceFile.replace('..\\', '').replace('../', '')
            elif sourceFile.startswith('.'):
                # Current directory reference
                sourcePath = baseDir / sourceFile.replace('.\\', '').replace('./', '')
            else:
                # Assume it's in base directory
                sourcePath = baseDir / sourceFile
            
            # Read and append source file
            if sourcePath.exists():
                print(f"    + Adding {sourcePath.name} ({sourcePath.stat().st_size} bytes)")
                with open(sourcePath, 'rb') as inFile:
                    outFile.write(inFile.read())
            else:
                print(f"    ! Warning: {sourcePath} not found, skipping")
    
    print(f"[+] Created {destPath} ({destPath.stat().st_size} bytes)")
    return destPath


def _executeCopyCommand(commandText, finalDir, autoitDir) -> Path:
    """
    Parse and execute a copy concatenation command
    """
    parsed = _parseCopyCommand(commandText)
    
    if not parsed['sourceFiles']:
        raise Exception(f"No source files found in command: {commandText}")
    
    return _concatenateFiles(
        parsed['sourceFiles'],
        parsed['destination'],
        finalDir,
        autoitDir
    )