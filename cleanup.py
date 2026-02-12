import shutil
import os

def cleanup(directoryPath):
    if os.path.exists(directoryPath):
        try:
            shutil.rmtree(directoryPath)
            print(f"[+] Directory tree '{directoryPath}' and all its contents removed successfully.")
        except OSError as e:
            print(f"[x] Error removing directory tree '{directoryPath}': {e}")
    else:
        print(f"[x] Directory '{directoryPath}' does not exist.")