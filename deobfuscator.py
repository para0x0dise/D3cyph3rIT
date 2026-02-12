import re

def createDeobfuscatorContext(variables, maxIterations=100) -> dict:
    """Create deobfuscator context with initial variables"""
    return {
        'variables': variables.copy(),
        'maxIterations': maxIterations,
        'pattern': re.compile(r'%([^%]+)%'),
        'setPattern': re.compile(r'^Set\s+(.+?)=(.*)$', re.IGNORECASE)
    }


def deobfuscateText(text, variables, pattern, maxIterations) -> str:
    """Replace all %var% in text with their values"""
    result = text
    
    for _ in range(maxIterations):
        match = pattern.search(result)
        if not match:
            break
        
        varName = match.group(1)
        if varName in variables:
            varValue = variables[varName]
            result = result.replace(f'%{varName}%', varValue, 1)
        else:
            break  # Unknown variable, stop replacement
    
    return result


def extractNewVariable(deobfuscatedText, setPattern) -> tuple[str, str]:
    """Extract variable definition from Set command"""
    match = setPattern.match(deobfuscatedText.strip())
    if match:
        varName = match.group(1).strip()
        varValue = match.group(2).strip()
        return (varName, varValue)
    return None


def deobfuscateSingleCommand(cmd, deobCtx) -> tuple[dict, dict]:
    """Deobfuscate a single command and update context"""
    # Step 1: Deobfuscate with current variables
    deobfuscated = deobfuscateText(
        cmd['text'],
        deobCtx['variables'],
        deobCtx['pattern'],
        deobCtx['maxIterations']
    )
    cmd['deobfuscated'] = deobfuscated
    
    # Step 2: Check if this command defines a new variable
    newVar = extractNewVariable(deobfuscated, deobCtx['setPattern'])
    if newVar:
        varName, varValue = newVar
        
        # Step 3: If value contains variables, deobfuscate it too
        if '%' in varValue:
            varValue = deobfuscateText(
                varValue,
                deobCtx['variables'],
                deobCtx['pattern'],
                deobCtx['maxIterations']
            )
            cmd['deobfuscated'] = f"Set {varName}={varValue}"
        
        # Step 4: Add to variable map for subsequent commands
        deobCtx['variables'][varName] = varValue
        cmd['newVariable'] = varName
    
    return cmd, deobCtx


def deobfuscateCommands(commands, initialVariables, maxIterations=100) -> tuple[list, dict]:
    """
    Deobfuscate commands sequentially and track new variables
    Returns: (deobfuscatedCommands, finalVariables)
    """
    deobCtx = createDeobfuscatorContext(initialVariables, maxIterations)
    
    deobfuscatedCommands = []
    for cmd in commands:
        deobCmd, deobCtx = deobfuscateSingleCommand(cmd, deobCtx)
        deobfuscatedCommands.append(deobCmd)
    
    return deobfuscatedCommands, deobCtx['variables']


def multiPassDeobfuscation(commands, initialVariables, maxPasses=5) -> tuple[list, dict]:
    """
    Run multiple deobfuscation passes until no more variables are resolved
    The concatenation command might be still obfuscated, so we need to run multiple passes to deobfuscate it.
    """
    currentCommands = commands
    currentVariables = initialVariables.copy()
    passCount = 0
    
    for passNum in range(1, maxPasses + 1):
        print(f"[*] Deobfuscation pass {passNum}...")
        
        # Track if anything changed in this pass
        changedCount = 0
        
        # Deobfuscate with current variables
        deobfuscatedCommands, newVariables = deobfuscateCommands(
            currentCommands,
            currentVariables
        )
        
        # Check each command to see if it still has variables
        for cmd in deobfuscatedCommands:
            deob = cmd.get('deobfuscated', '')
            
            # Count remaining variables
            remainingVars = deob.count('%')
            if remainingVars > 0:
                changedCount += 1
                # Store for next pass
                cmd['text'] = deob  # Use deobfuscated as new input
        
        currentCommands = deobfuscatedCommands
        currentVariables = newVariables
        
        print(f"    Commands with remaining variables: {changedCount}")
        
        # Stop if no more variables to resolve
        if changedCount == 0:
            print(f"[+] Deobfuscation converged after {passNum} passes")
            break
    else:
        print(f"[!] Warning: Maximum passes ({maxPasses}) reached, may still have unresolved variables")
    
    return currentCommands, currentVariables