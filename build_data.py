import json
import re

def parse_confusables_summary(input_file, output_file, ascii_output_file):
    """
    Parses confusablesSummary.txt to create:
    1. A full inverse map (codepoint -> list of lookalikes)
    2. An auto-generated set of ASCII chars that have homoglyphs.
    """
    
    # This regex captures the Hex code(s) between the visual (...) and the Name
    # Example line: "	(‎ ! ‎)	0021	 EXCLAMATION MARK"
    # We look for the tabs and the hex codes.
    line_pattern = re.compile(r"\)\t([0-9A-F ]+)\t")

    clusters = []
    current_cluster = set()

    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            
            # Skip empty lines or headers that don't start a block
            if not line or line.startswith('#'):
                # If we hit a separator and have data, save the cluster
                if current_cluster:
                    clusters.append(list(current_cluster))
                    current_cluster = set()
                continue
            
            # Extract hex codes
            match = line_pattern.search(line)
            # Also try matching lines starting with arrow "←"
            if not match:
                # Formatting in file is strictly tab-separated
                # 0: Arrow/Empty, 1: (Visual), 2: Hex, 3: Name
                parts = line.split('\t')
                if len(parts) >= 4:
                    # The hex codes are in column 2 (0-indexed)
                    hex_str = parts[2].strip()
                    # Only accept valid hex strings
                    if all(c in '0123456789ABCDEF ' for c in hex_str):
                         # Handle sequences "0021 0021" -> Keep as string or skip?
                         # For the Inspector, we want Single Chars mostly.
                         # Let's only keep Single Codepoints for the "Identity" map for now.
                         if ' ' not in hex_str: 
                             current_cluster.add(hex_str)

    # Final flush
    if current_cluster:
        clusters.append(list(current_cluster))

    # --- PIVOT DATA ---
    inverse_map = {}
    ascii_confusables = []

    for cluster in clusters:
        # Sort for consistency
        cluster.sort()
        
        # Check if this cluster mixes ASCII and Non-ASCII (The Danger Zone)
        has_ascii = False
        has_non_ascii = False
        
        for hex_code in cluster:
            val = int(hex_code, 16)
            if val < 128: has_ascii = True
            else: has_non_ascii = True
            
        is_risky_cluster = has_ascii and has_non_ascii

        for cp in cluster:
            # Create the list of "Others"
            others = [x for x in cluster if x != cp]
            if others:
                inverse_map[cp] = others
            
            # If this is an ASCII char in a risky cluster, add to the Set
            if is_risky_cluster and int(cp, 16) < 128:
                ascii_confusables.append(int(cp, 16))

    # Save Inverse Map
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(inverse_map, f, separators=(',', ':'))
        
    # Save ASCII Auto-Set (as a simple list)
    with open(ascii_output_file, 'w', encoding='utf-8') as f:
        json.dump(sorted(list(set(ascii_confusables))), f)

    print(f"Processed {len(clusters)} clusters.")
    print(f"Generated {len(inverse_map)} inverse lookalike entries.")
    print(f"Identified {len(ascii_confusables)} ASCII characters with homoglyphs.")

# Run it
parse_confusables_summary('confusablesSummary.txt', 'inverse_confusables.json', 'ascii_confusables.json')
