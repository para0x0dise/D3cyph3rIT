import subprocess
import shutil
import os
import pefile
import magic
from pathlib import Path

def createContext(filepath):
    """Create initial parsing context"""
    baseDir = Path(__file__).resolve().parent
    extractedDir = baseDir / 'collected'
    finalDir = baseDir / 'final'
    autoitDir = baseDir / 'scripts'
    autoitBinDir = baseDir / 'bin' / 'myAutToExe'
    payloadDir = baseDir / 'payload'
    
    os.makedirs(extractedDir, exist_ok=True)
    os.makedirs(finalDir, exist_ok=True)
    os.makedirs(autoitDir, exist_ok=True)
    os.makedirs(payloadDir, exist_ok=True)
    
    return {
        'filepath': filepath,
        'baseDir': baseDir,
        'extractedDir': extractedDir,
        'finalDir': finalDir,
        'autoitDir': autoitDir,
        'autoitBinDir': autoitBinDir,
        'payloadDir': payloadDir,
        'batchScriptPath': None,
        'lines': [],
        'variables': {},
        'commands': []
    }

def defineArchiveFileType(filePath):
    """Identify the archive file type"""
    with open(filePath, "rb") as f:
        data = f.read()

    if b"MSCF" in data:
        return "cab"

    if b"Nullsoft" in data:
        return "nsis"

    raise Exception(f"Unknown archive file type: {filePath}")

def extractNsisArchive(filepath, extractedDir, finalDir):
    """Unpack NSIS archive and move files to final directory"""
    result = subprocess.run(
        ["7z", "x", str(filepath), f"-o{extractedDir}", "-y"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    if result.returncode != 0:
        raise Exception(f"Failed to extract archive: {result.returncode}")

    counter = 0
    for root, _, files in os.walk(extractedDir):
        for f in files:
            src = Path(root) / f
            dst = Path(finalDir) / f

            if dst.exists():
                continue

            shutil.copy2(src, dst)
            counter += 1
    
    return counter


def extractCabFromResources(filepath, extractedDir):
    """Extract the CAB file from PE resources"""
    pe = pefile.PE(filepath)

    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        raise Exception("PE file does not have a resource directory")

    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for e in entry.directory.entries:
            for res in e.directory.entries:
                dataRVA = res.data.struct.OffsetToData
                size = res.data.struct.Size

                data = pe.get_memory_mapped_image()[dataRVA:dataRVA+size]

                if data.startswith(b"MSCF"):
                    fname = Path(extractedDir) / f"extractedCABFile"
                    with open(fname, "wb") as f:
                        f.write(data)
                    return fname
    
    raise Exception("CAB file not found in PE resources")


def decompressCabFile(cabFilepath, finalDir):
    """Decompress the CAB file"""
    result = subprocess.run(
        ["expand", Path(cabFilepath), "-F:*", finalDir],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    if result.returncode != 0:
        raise Exception(f"Failed to decompress CAB file: {result.returncode}")


def locateArchiveFile(context, archiveType):
    """Locate and extract the archive file"""
    if archiveType == "nsis":
        extractNsisArchive(context['filepath'], context['extractedDir'], context['finalDir'])
        return context

    if archiveType == "cab":
        cabFile = extractCabFromResources(context['filepath'], context['extractedDir'])
        decompressCabFile(cabFile, context['finalDir'])
        return context

    raise Exception(f"Unknown archive file type: {archiveType}")


def locateBatchScript(finalDir):
    """Locate the batch script in the final directory"""
    for root, _, files in os.walk(finalDir):
        for f in files:
            filePath = Path(root) / f

            try:
                if "text" in magic.from_file(str(filePath), mime=True):
                    return filePath
            except:
                continue

    raise Exception("Batch script not found in the final directory")


def readBatchScript(batchScriptPath):
    """Read batch script into lines"""
    with open(batchScriptPath, 'r', encoding='utf-8', errors='ignore') as file:
        return file.readlines()


def extractVariables(lines):
    """Extract all Set commands from lines"""
    variables = {}
    for line in lines:
        if line.strip().startswith('Set '):
            assignment = line.strip()[4:]
            if '=' in assignment:
                name, value = assignment.split('=', 1)
                # Handle empty values as space
                variables[name] = value if value else ' '
    return variables


def extractCommands(lines):
    """Extract lines with %variable% syntax"""
    commands = []
    for lineNum, line in enumerate(lines, 1):
        if '%' in line and line.count('%') >= 2:
            commands.append({
                'line': lineNum,
                'text': line.strip(),
                'deobfuscated': None
            })
    return commands


def parseBatchScript(context):
    """Parse the batch script and extract variables and commands"""
    if not context['batchScriptPath']:
        raise Exception("batchScriptPath not set")
    
    context['lines'] = readBatchScript(context['batchScriptPath'])
    context['variables'] = extractVariables(context['lines'])
    context['commands'] = extractCommands(context['lines'])
    
    return context
