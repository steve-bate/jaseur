#!/usr/bin/env python3

import argparse
import json
import os
import re
import hashlib
from pathlib import Path
from urllib.parse import urlparse

def compute_hash(uri):
    """Compute SHA256 hash of a URI."""
    return hashlib.sha256(uri.encode('utf-8')).hexdigest()

def extract_domain_info(uri):
    """Extract domain information from URI, handling different schemes and ports."""
    try:
        parsed = urlparse(uri)
        if not parsed.scheme:
            parsed = urlparse("https://" + uri)
        
        # Extract domain and port
        netloc = parsed.netloc
        domain = netloc
        port = ""
        
        if ":" in netloc:
            domain, port = netloc.split(":")
            
            # Only include port in path if it's non-standard
            if ((parsed.scheme == "https" and port != "443") or 
                (parsed.scheme == "http" and port != "80")):
                return f"{parsed.scheme}_{domain}_{port}"
        
        # For https with default port, just use domain
        if parsed.scheme == "https":
            return domain
            
        # For other schemes, prefix with scheme
        return f"{parsed.scheme}_{domain}"
    except Exception as e:
        print(f"Error parsing URI {uri}: {e}")
        return None

def migrate_storage(input_dir, output_dir):
    """Migrate from old SHA256-based storage to new domain-organized SHA256 storage."""
    input_path = Path(input_dir)
    output_path = Path(output_dir)
    
    # Create base output directories
    (output_path / "public").mkdir(parents=True, exist_ok=True)
    (output_path / "private").mkdir(parents=True, exist_ok=True)
    
    # Process all JSON files in the input directory
    for file_path in input_path.glob("*.json"):
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            if "id" not in data:
                print(f"Warning: File {file_path} has no 'id' field, skipping")
                continue
                
            uri = data["id"]
            domain = extract_domain_info(uri)
            
            if not domain:
                print(f"Warning: Could not extract domain from URI: {uri}")
                continue
            
            # Determine if this is public or private data
            visibility = "private" if ("/inbox" in uri or 
                                    (data.get("type") == "Key")) else "public"
            
            # Create domain directory
            domain_dir = output_path / visibility / domain
            domain_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate SHA256 hash for the filename
            new_filename = f"{compute_hash(uri)}.json"
            
            # Write to new location
            with open(domain_dir / new_filename, 'w') as f:
                json.dump(data, f, indent=2)
            
            print(f"Migrated: {uri}")
            print(f"  From: {file_path.name}")
            print(f"  To: {visibility}/{domain}/{new_filename}")
            
        except Exception as e:
            print(f"Error processing {file_path}: {e}")

def main():
    parser = argparse.ArgumentParser(description='Migrate ActivityPub resource store to domain-based UUID storage')
    parser.add_argument('input_dir', help='Input directory containing old storage')
    parser.add_argument('output_dir', help='Output directory for new storage')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input_dir):
        print(f"Error: Input directory '{args.input_dir}' does not exist")
        return 1
        
    migrate_storage(args.input_dir, args.output_dir)
    return 0

if __name__ == "__main__":
    exit(main())