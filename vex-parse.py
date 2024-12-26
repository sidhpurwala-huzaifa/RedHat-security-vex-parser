#!/usr/bin/env python3

import json
import sys
from datetime import datetime
from typing import Dict, Any, List
import requests
import os
from bs4 import BeautifulSoup
import tarfile
import zstandard as zstd
import datasets
from tqdm import tqdm

class VexParser:
    def __init__(self, base_url: str = "https://security.access.redhat.com/data/csaf/v2/vex/"):
        self.base_url = base_url
        self.download_dir = "vex_data"
        self.processed_data = []

    def download_latest_vex(self) -> str:
        """Download the latest VEX archive file."""
        # Create download directory if it doesn't exist
        os.makedirs(self.download_dir, exist_ok=True)

        # Get the main page content
        response = requests.get(self.base_url)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find the latest .tar.zst file
        archives = [link.get('href') for link in soup.find_all('a') 
                   if link.get('href', '').endswith('.tar.zst') 
                   and not link.get('href', '').endswith('.asc')
                   and not link.get('href', '').endswith('.sha256')]
        
        if not archives:
            raise Exception("No VEX archive found")
        
        latest_archive = archives[0]
        archive_path = os.path.join(self.download_dir, latest_archive)
        
        # Download the file
        print(f"Downloading {latest_archive}...")
        response = requests.get(f"{self.base_url}{latest_archive}", stream=True)
        with open(archive_path, 'wb') as f:
            for chunk in tqdm(response.iter_content(chunk_size=8192)):
                f.write(chunk)
        
        return archive_path

    def extract_archive(self, archive_path: str) -> str:
        """Extract the downloaded zstd compressed tar archive."""
        extract_dir = os.path.join(self.download_dir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)

        print("Extracting archive...")
        with open(archive_path, 'rb') as compressed:
            dctx = zstd.ZstdDecompressor()
            with dctx.stream_reader(compressed) as reader:
                with tarfile.open(fileobj=reader, mode='r|*') as tar:
                    tar.extractall(extract_dir)

        return extract_dir

    def process_vex_file(self, file_path: str) -> Dict[str, Any]:
        """Process a single VEX file and return structured data."""
        with open(file_path, 'r') as f:
            data = json.load(f)
            
        doc = data.get('document', {})
        vulnerabilities = data.get('vulnerabilities', [])
        
        processed = {
            'title': doc.get('title', ''),
            'release_date': doc.get('tracking', {}).get('current_release_date', ''),
            'severity': doc.get('aggregate_severity', {}).get('text', ''),
            'vulnerabilities': []
        }
        
        for vuln in vulnerabilities:
            vuln_data = {
                'cve': vuln.get('cve', ''),
                'product_status': vuln.get('product_status', {}),
                'threats': vuln.get('threats', []),
            }
            processed['vulnerabilities'].append(vuln_data)
            
        return processed

    def create_dataset(self) -> None:
        """Create and save a HuggingFace dataset."""
        # Download and extract the archive
        archive_path = self.download_latest_vex()
        extract_dir = self.extract_archive(archive_path)
        
        # Process all VEX files
        processed_data = []
        for root, _, files in os.walk(extract_dir):
            for file in tqdm(files, desc="Processing VEX files"):
                if file.endswith('.json'):
                    file_path = os.path.join(root, file)
                    try:
                        processed = self.process_vex_file(file_path)
                        processed_data.append(processed)
                    except Exception as e:
                        print(f"Error processing {file}: {str(e)}")

        # Create HuggingFace dataset
        dataset = datasets.Dataset.from_list(processed_data)
        
        # Push to HuggingFace Hub
        # Note: Requires huggingface-cli login first
        dataset.push_to_hub("RedHat-security-VeX")

def main():
    parser = VexParser()
    parser.create_dataset()

if __name__ == "__main__":
    main()
