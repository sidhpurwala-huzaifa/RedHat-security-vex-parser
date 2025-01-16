# Copyright (c) 2024 Huzaifa Sidhpurwala <huzaifas@redhat.com>
# License: GPLv3+
#
# vex-parse.py  
#
# This script downloads the latest VEX archive file, extracts it, and processes each VEX file to create a HuggingFace dataset.
# It includes functions to download the latest VEX archive, extract the archive, process each VEX file, and create a dataset.
# The processed data is stored in a JSON format and can be used for further analysis or machine learning tasks.
#
# Usage: python vex-parse.py
#
# Dependencies:
# - requests
# - beautifulsoup4
# - tarfile
# - zstandard
# - datasets
# - tqdm

#!/usr/bin/env python3

import json
import sys
from datetime import datetime
from typing import Dict, Any, List, Tuple
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

    def calculate_cvss2_score(self, vector: str) -> float:
        """Calculate CVSS v2 base score from vector string."""
        if not vector or not vector.startswith('AV:'):
            return 0.0

        # Parse vector string into components
        components = dict(item.split(':') for item in vector.split('/'))
        
        # Impact metrics
        conf_impact = {'N': 0.0, 'P': 0.275, 'C': 0.660}[components.get('C', 'N')]
        integ_impact = {'N': 0.0, 'P': 0.275, 'C': 0.660}[components.get('I', 'N')]
        avail_impact = {'N': 0.0, 'P': 0.275, 'C': 0.660}[components.get('A', 'N')]
        
        # Exploitability metrics
        access_vector = {'L': 0.395, 'A': 0.646, 'N': 1.0}[components.get('AV', 'L')]
        access_complexity = {'H': 0.35, 'M': 0.61, 'L': 0.71}[components.get('AC', 'L')]
        authentication = {'M': 0.45, 'S': 0.56, 'N': 0.704}[components.get('Au', 'N')]
        
        # Calculate impact and exploitability
        impact = 10.41 * (1 - (1 - conf_impact) * (1 - integ_impact) * (1 - avail_impact))
        exploitability = 20 * access_vector * access_complexity * authentication
        
        # Calculate base score
        if impact == 0:
            base_score = 0
        else:
            base_score = round(((0.6 * impact) + (0.4 * exploitability) - 1.5) * 1.176, 1)
        
        return base_score

    def calculate_cvss3_score(self, vector: str) -> float:
        """Calculate CVSS v3 base score from vector string."""
        if not vector or not vector.startswith('CVSS:3'):
            return 0.0

        # Parse vector string into components
        components = dict(item.split(':') for item in vector.split('/'))
        
        # Impact metrics
        conf_impact = {'N': 0, 'L': 0.22, 'H': 0.56}[components.get('C', 'N')]
        integ_impact = {'N': 0, 'L': 0.22, 'H': 0.56}[components.get('I', 'N')]
        avail_impact = {'N': 0, 'L': 0.22, 'H': 0.56}[components.get('A', 'N')]
        
        # Exploitability metrics
        attack_vector = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}[components.get('AV', 'N')]
        attack_complexity = {'L': 0.77, 'H': 0.44}[components.get('AC', 'L')]
        privileges_required = {
            'N': 0.85,
            'L': 0.62 if components.get('S', 'U') == 'C' else 0.68,
            'H': 0.27 if components.get('S', 'U') == 'C' else 0.50
        }[components.get('PR', 'N')]
        user_interaction = {'N': 0.85, 'R': 0.62}[components.get('UI', 'N')]
        
        # Calculate base metrics
        exploitability = 8.22 * attack_vector * attack_complexity * privileges_required * user_interaction
        
        impact_sub_score = 1 - ((1 - conf_impact) * (1 - integ_impact) * (1 - avail_impact))
        
        # Determine scope and calculate impact
        if components.get('S', 'U') == 'C':
            impact = 7.52 * (impact_sub_score - 0.029) - 3.25 * pow(impact_sub_score - 0.02, 15)
        else:
            impact = 6.42 * impact_sub_score
            
        if impact <= 0:
            return 0
            
        if components.get('S', 'U') == 'C':
            base_score = min(1.08 * (exploitability + impact), 10)
        else:
            base_score = min(exploitability + impact, 10)
            
        return round(base_score, 1)

    def extract_product_status(self, product_status: Dict) -> Dict[str, List[str]]:
        """Extract product status information."""
        vendor_fixes = []
        if 'vendor_fix' in product_status:
            for fix in product_status['vendor_fix']:
                if 'url' in fix:
                    url = fix['url']
                    # Extract the last bits of the URL that match the pattern "RHSA-<number>:<number>"
                    if "RHSA-" in url:
                        parts = url.split("RHSA-")
                        if len(parts) > 1:
                            vendor_fixes.append("RHSA-" + parts[-1].split(':')[0])  # Get the part before the colon

        return {
            'fixed_products': product_status.get('fixed', []),
            'known_affected_products': product_status.get('known_affected', []),
            'known_not_affected_products': product_status.get('known_not_affected', []),
            'under_investigation_products': product_status.get('under_investigation', []),
            'vendor_fix': vendor_fixes  # New field for vendor fixes
        }

    def extract_threats_or_remediations(self, items: List[Dict], is_threat: bool) -> Tuple[List[str], List[str], List[str]]:
        """Extract threats or remediations information."""
        categories, details, dates = [], [], []
        for item in items:
            if is_threat:
                categories.append(item.get('category', '') or None)
                details.append(item.get('details', '') or None)
                dates.append(item.get('date', '') or None)
            else:
                categories.append(item.get('category', '') or None)
                details.append(item.get('details', '') or None)
                dates.append(item.get('date', '') or None)
        return categories, details, dates

    def process_vex_file(self, file_path: str) -> Dict[str, Any]:
        """Process a single VEX file and return structured data."""
        with open(file_path, 'r') as f:
            data = json.load(f)
            
        doc = data.get('document', {})
        vulnerabilities = data.get('vulnerabilities', [])
        
        # Split title into component and description
        title = doc.get('title', '') or ''
        component, *description_parts = title.split(':', 1)
        description = description_parts[0].strip() if description_parts else ''
        
        processed = {
            'cve': '' or None,
            'cwe': '' or None,
            'affected_component': component.strip(),
            'summary': description,
            'severity': doc.get('aggregate_severity', {}).get('text', '') or None,
            'scores': [],
            'cvss_v2': '' or None,
            'cvss_v3': '' or None,
            'description': None,
            'statement': None,
            'release_date': doc.get('tracking', {}).get('current_release_date', '') or None,
            # New fields for product status
            'fixed_products': [],
            'known_affected_products': [],
            'known_not_affected_products': [],
            'under_investigation_products': [],
            # New fields for threats and remediations
            'threat_categories': [],
            'threat_details': [],
            'threat_dates': [],
            'remediation_categories': [],
            'remediation_details': [],
            'remediation_dates': []
        }

        for vuln in vulnerabilities:
            # Extract notes by category
            for note in vuln.get('notes', []):
                category = note.get('category')
                if category == 'description':
                    processed['description'] = note.get('text')
                elif category == 'other':
                    processed['statement'] = note.get('text')
                    
            # Extract CWE if found
            if cwe_data := vuln.get('cwe'):
                processed['cwe'] = cwe_data.get('id')
            
            # Store CVE if found
            if cve := vuln.get('cve'):
                processed['cve'] = cve
            
            # Extract scores and CVSS vectors
            scores = vuln.get('scores', [])
            processed['scores'].extend(scores)
            
            # Extract CVSS v2 and v3 vector strings
            for score in scores:
                if score.get('products'):
                    if score.get('cvss_v2'):
                        vector_string = score.get('cvss_v2', {}).get('vectorString', '')
                        if vector_string:
                            cvss_score = self.calculate_cvss2_score(vector_string)
                            processed['cvss_v2'] = f"{cvss_score}/{vector_string}"
                    if score.get('cvss_v3'):
                        vector_string = score.get('cvss_v3', {}).get('vectorString', '')
                        if vector_string:
                            # Remove "CVSS:3.1/" from the vector string
                            #vector_string = vector_string.replace("CVSS:3.1/", "")
                            cvss_score = self.calculate_cvss3_score(vector_string)
                            vector_string = vector_string.replace("CVSS:3.1/", "")
                            processed['cvss_v3'] = f"{cvss_score}/{vector_string}"
                    break
            
            # Extract product status
            product_status = self.extract_product_status(vuln.get('product_status', {}))
            product_status.pop('vendor_fix', None)  # Remove the 'vendor_fix' field
            processed.update(product_status)

            # Extract threats
            threat_categories, threat_details, threat_dates = self.extract_threats_or_remediations(vuln.get('threats', []), True)
            processed['threat_categories'].extend(threat_categories)
            processed['threat_details'].extend(threat_details)
            processed['threat_dates'].extend(threat_dates)

            # Extract remediations
            remediation_categories, remediation_details, remediation_dates = self.extract_threats_or_remediations(vuln.get('remediations', []), False)
            processed['remediation_categories'].extend(remediation_categories)
            processed['remediation_details'].extend(remediation_details)
            processed['remediation_dates'].extend(remediation_dates)
            
        # Replace empty scores list with "None"
        #if not processed['scores']:
        #    processed['scores'] = "None"
        
        # After collecting all data, remove duplicates from list fields
        processed['fixed_products'] = list(dict.fromkeys(processed['fixed_products']))
        processed['known_affected_products'] = list(dict.fromkeys(processed['known_affected_products']))
        processed['known_not_affected_products'] = list(dict.fromkeys(processed['known_not_affected_products']))
        processed['under_investigation_products'] = list(dict.fromkeys(processed['under_investigation_products']))
        
        # Remove duplicates from threat information while preserving order
        unique_threats = {}
        for cat, detail, date in zip(processed['threat_categories'], 
                                    processed['threat_details'], 
                                    processed['threat_dates']):
            unique_threats[(cat, detail, date)] = None
        processed['threat_categories'], processed['threat_details'], processed['threat_dates'] = zip(*unique_threats.keys()) if unique_threats else ([], [], [])
        
        # Remove duplicates from remediation information while preserving order
        unique_remediations = {}
        for cat, detail, date in zip(processed['remediation_categories'], 
                                    processed['remediation_details'], 
                                    processed['remediation_dates']):
            unique_remediations[(cat, detail, date)] = None
        processed['remediation_categories'], processed['remediation_details'], processed['remediation_dates'] = zip(*unique_remediations.keys()) if unique_remediations else ([], [], [])
        
        # Convert tuples back to lists for JSON serialization
        processed['threat_categories'] = list(processed['threat_categories'])
        processed['threat_details'] = list(processed['threat_details'])
        processed['threat_dates'] = list(processed['threat_dates'])
        processed['remediation_categories'] = list(processed['remediation_categories'])
        processed['remediation_details'] = list(processed['remediation_details'])
        processed['remediation_dates'] = list(processed['remediation_dates'])
        
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
                        # Remove the scores field before adding to dataset
                        processed.pop('scores', None)
                        processed_data.append(processed)
                    except Exception as e:
                        print(f"Error processing {file}: {str(e)}")

        # Sort the processed data by CVE year in descending order
        processed_data.sort(key=lambda x: int(x['cve'].split('-')[1]) if x['cve'] and x['cve'].startswith('CVE-') else 0, 
                          reverse=True)

        # Create HuggingFace dataset
        dataset = datasets.Dataset.from_list(processed_data)
        
        # Push to HuggingFace Hub
        dataset.push_to_hub("RedHat-security-VeX")

def main():
    parser = VexParser()
    parser.create_dataset()

if __name__ == "__main__":
    main()
