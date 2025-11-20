import json
import re

def parse_confusables_summary(input_file, output_file, ascii_output_file):
    """
    Parses confusablesSummary.txt to create:
    1. A full inverse map (codepoint -> list of lookalikes)
    2. An auto-generated set of ASCII chars that have homoglyphs.
    """
    
    clusters = []
    current_cluster = set()

    print(f"Reading {input_file}...")
    
    with open(input_file, 'r', encoding='utf-8') as f:
        for line_idx, line in enumerate(f):
            line = line.strip()
            
            # --- 1. Block Detection (Headers start with #) ---
            # If we hit a header line (e.g., "#	!	ǃ	ⵑ	！"), we flush the previous cluster.
            if not line or line.startswith('#'):
                if current_cluster:
                    clusters.append(list(current_cluster))
                    current_cluster = set()
                continue
            
            # --- 2. Robust Data Extraction ---
            # Format is usually:   ( visual )   HEX_CODE   NAME
            # Strategy: Split by ANY whitespace, find the ')', take the next item.
            
            # Clean invisible chars (LTR/RTL markers) that confuse splitting
            clean_line = line.replace('\u200e', '').replace('\u200f', '')
            parts = clean_line.split()
            
            hex_str = None
            
            # Iterate to find the token with ')'
            for i, part in enumerate(parts):
                if ')' in part and i + 1 < len(parts):
                    candidate = parts[i+1]
                    # Validation: Must be Hex characters (0-9, A-F) and at least 4 chars
                    if all(c in '0123456789ABCDEF' for c in candidate) and len(candidate) >= 4:
                        hex_str = candidate
                        break
            
            # Fallback: Sometimes the hex is separated by spaces (e.g. "0021 0021")
            # If we found a start, check if next tokens are also hex
            if hex_str:
                # (Optional logic for sequences could go here, but for now we take the primary CP)
                pass
            
            if hex_str:
                # We only want Single Code Points for the Inspector (ignore sequences like "0021 0021" for now)
                # If you want sequences, remove the length check.
                current_cluster.add(hex_str)
            else:
                # Debugging: Print first few failures to understand why
                if line_idx < 20 and line: 
                    print(f"Skipped line {line_idx}: {line}")

    # Final flush
    if current_cluster:
        clusters.append(list(current_cluster))

    # --- 3. Pivot Data ---
    inverse_map = {}
    ascii_confusables = []

    for cluster in clusters:
        cluster.sort()
        
        # Analyze Cluster Risk (Does it mix ASCII and Non-ASCII?)
        has_ascii = False
        has_non_ascii = False
        
        valid_members = []
        
        for hex_code in cluster:
            try:
                val = int(hex_code, 16)
                valid_members.append(val)
                if val < 128: has_ascii = True
                else: has_non_ascii = True
            except:
                continue

        # Only flag ASCII chars as "Confusable" if they are in a mixed-script cluster
        # (e.g. 'A' is confusable with Cyrillic 'A'. But 'v' vs 'u' (both ASCII) is just a note.)
        is_risky_cluster = has_ascii and has_non_ascii

        for cp in valid_members:
            # Map this CP to all OTHERS in the cluster
            others = [f"U+{x:04X}" for x in valid_members if x != cp]
            if others:
                inverse_map[cp] = others # Store as Integer Key -> List of Hex Strings
            
            # If this is an ASCII char in a risky cluster, add to the Set
            if is_risky_cluster and cp < 128:
                ascii_confusables.append(cp)

    # Save Inverse Map (inverse_confusables.json)
    # Key: Integer Codepoint, Value: List of strings "U+XXXX"
    # We use string keys for JSON compatibility
    json_map = {str(k): v for k, v in inverse_map.items()}
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(json_map, f) # Minimal JSON
        
    # Save ASCII Auto-Set (ascii_confusables.json)
    with open(ascii_output_file, 'w', encoding='utf-8') as f:
        json.dump(sorted(list(set(ascii_confusables))), f)

    print(f"------------------------------------------------")
    print(f"SUCCESS: Processed {len(clusters)} clusters.")
    print(f"Generated {len(inverse_map)} inverse lookalike entries.")
    print(f"Identified {len(ascii_confusables)} ASCII characters with homoglyphs.")
    print(f"Files saved: {output_file}, {ascii_output_file}")

# TRIGGER THE FUNCTION
if __name__ == "__main__":
    parse_confusables_summary('confusablesSummary.txt', 'inverse_confusables.json', 'ascii_confusables.json')
