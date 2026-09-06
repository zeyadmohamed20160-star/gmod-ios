import os
import glob
import subprocess
import pefile
import json

output_dir = "extracted_analysis"
os.makedirs(output_dir, exist_ok=True)

print("==================================================")
print("   STARTING AUTOMATED BINARY CODE EXTRACTION      ")
print("==================================================")

# Find all PE binaries (.exe and .dll) recursively in the repo
binaries = glob.glob("**/*.exe", recursive=True) + glob.glob("**/*.dll", recursive=True)
# Filter out output directories or hidden git folders
binaries = [b for b in binaries if not b.startswith("extracted_analysis") and not ".git" in b]

print(f"[+] Found {len(binaries)} target binary files to analyze.")

for bin_path in binaries:
    print(f"\n--------------------------------------------------")
    print(f"[-] Analyzing: {bin_path}")
    print(f"--------------------------------------------------")
    
    safe_name = bin_path.replace(os.sep, "_")
    bin_out_dir = os.path.join(output_dir, safe_name)
    os.makedirs(bin_out_dir, exist_ok=True)
    
    # 1. Parse PE Headers & Imports/Exports using 'pefile'
    try:
        pe = pefile.PE(bin_path)
        pe_info = {
            "Machine": hex(pe.FILE_HEADER.Machine),
            "TimeDateStamp": pe.FILE_HEADER.TimeDateStamp,
            "Sections": [s.Name.decode('utf-8', errors='ignore').strip('\x00') for s in pe.sections],
            "Imports": [],
            "Exports": []
        }
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                imp_dll = entry.dll.decode('utf-8', errors='ignore')
                for imp in entry.imports:
                    if imp.name:
                        pe_info["Imports"].append(f"{imp_dll} -> {imp.name.decode('utf-8', errors='ignore')}")
                        
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    pe_info["Exports"].append(exp.name.decode('utf-8', errors='ignore'))
                    
        with open(os.path.join(bin_out_dir, "pe_structure.json"), "w") as f:
            json.dump(pe_info, f, indent=4)
        print("    [OK] Extracted PE headers, imports, and exports.")
    except Exception as e:
        print(f"    [ERROR] PE parsing failed: {e}")

    # 2. Extract All Raw Strings using Unix 'strings'
    try:
        strings_path = os.path.join(bin_out_dir, "all_strings.txt")
        with open(strings_path, "w") as sf:
            subprocess.run(["strings", "-n", "5", bin_path], stdout=sf, check=True)
        print("    [OK] Extracted all static text and strings (min length 5).")
    except Exception as e:
        print(f"    [ERROR] Strings extraction failed: {e}")

    # 3. Deep Disassembly & Function Analysis using Radare2 (Batch Mode)
    try:
        r2_functions_path = os.path.join(bin_out_dir, "disassembled_functions.txt")
        # Run radare2 to analyze all functions and output pseudo-code / assembly dumps
        r2_cmd = f"aaa; afl"
        result = subprocess.run(["r2", "-qc", r2_cmd, bin_path], capture_output=True, text=True, check=True)
        with open(r2_functions_path, "w") as rf:
            rf.write(result.stdout)
        print("    [OK] Mapped functions and generated disassembly dumps via Radare2.")
    except Exception as e:
        print(f"    [ERROR] Radare2 analysis failed: {e}")

print("\n==================================================")
print("   EXTRACTION COMPLETE. SAVED TO: /extracted_analysis")
print("==================================================")