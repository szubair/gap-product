# app/db_processor.py

import pandas as pd
from mongoengine import Q
from datetime import datetime
#from app.models import Asset, VulnerabilityScan, RemediationRecord
from app.models import Asset, VulnerabilityScan
from werkzeug.utils import secure_filename
import os

# Helper function to read uploaded file types
def read_uploaded_file(file_path):
    """Reads a CSV or Excel file into a pandas DataFrame."""
    try:
        if file_path.lower().endswith('.csv'):
            df = pd.read_csv(file_path)
        elif file_path.lower().endswith(('.xlsx', '.xls')):
            df = pd.read_excel(file_path)
        else:
            raise ValueError("Unsupported file type. Must be CSV or Excel.")
        
        # Ensure all column headers are strings and strip whitespace
        df.columns = df.columns.astype(str).str.strip()
        return df
    except Exception as e:
        # Re-raise with a specific message about file reading
        raise Exception(f"Error reading file {os.path.basename(file_path)}: {e}")

## --- Asset Ingestion Functions ---

def upload_asset_list(file_path):
    """
    Parses asset report and inserts/updates records into the MongoDB Asset collection.
    Uses the new, cleaner headers defined by the user.
    """
    df = read_uploaded_file(file_path)
    inserted_count = 0
    updated_count = 0
    skipped_count = 0
    
    # Define the mapping from the new file columns to the Asset model fields
    COLUMN_MAP = {
        'hostname': 'Hostname',              
        'ip_address': 'Private_IP',          # UPDATED
        'description': 'Description',
        'status': 'Status',
        'role': 'Role',
        'env': 'ENV',
        'location': 'Location',
        'platform': 'Platform',
        'infra_owner': 'Infra_Owner',        # UPDATED
        'app_owner': 'App_Owner',            # UPDATED
        'vendor_availability': 'Vendor_Availability' 
    }

    # Verify all required columns are present in the dataframe
    required_cols = list(COLUMN_MAP.values())
    if not all(col in df.columns for col in required_cols):
        missing_cols = [col for col in required_cols if col not in df.columns]
        raise KeyError(f"Missing required column in report: {', '.join(missing_cols)}")

    for index, row in df.iterrows():
        try:
            # Use the Private_IP as the unique identifier for update/upsert
            asset_ip = str(row[COLUMN_MAP['ip_address']]).strip()
            
            if not asset_ip:
                skipped_count += 1
                continue

            asset_data = {
                'hostname': row[COLUMN_MAP['hostname']],
                'ip_address': asset_ip,
                'description': row[COLUMN_MAP['description']],
                'status': row[COLUMN_MAP['status']],
                'role': row[COLUMN_MAP['role']],
                'env': row[COLUMN_MAP['env']],
                'location': row[COLUMN_MAP['location']],
                'platform': row[COLUMN_MAP['platform']],
                'infra_owner': row[COLUMN_MAP['infra_owner']],
                'app_owner': row[COLUMN_MAP['app_owner']],
                'vendor_availability': row[COLUMN_MAP['vendor_availability']],
            }
            
            # Use upsert=True to insert if the IP doesn't exist, or update if it does
            result = Asset.objects(ip_address=asset_ip).update_one(
                set__hostname=asset_data['hostname'],
                set__description=asset_data['description'],
                set__status=asset_data['status'],
                set__role=asset_data['role'],
                set__env=asset_data['env'],
                set__location=asset_data['location'],
                set__platform=asset_data['platform'],
                set__infra_owner=asset_data['infra_owner'],
                set__app_owner=asset_data['app_owner'],
                set__vendor_availability=asset_data['vendor_availability'],
                upsert=True
            )
            
            # Check if a new document was created (inserted) or an existing one updated
            if result.upserted_id:
                inserted_count += 1
            elif result.modified_count > 0:
                updated_count += 1
            
        except KeyError as e:
            # This is already checked above, but kept for safety on iteration
            raise Exception(f"Missing column or error on row {index}: {e}")
        except Exception as e:
            print(f"An error occurred on row {index}: {e}")
            skipped_count += 1
            
    return f"Asset upload complete. New: {inserted_count}, Updated: {updated_count}, Skipped/Error: {skipped_count}"

## --- Scan Ingestion Functions ---

def upload_vulnerability_scan(file_path):
    """
    Parses scan report, links to assets, and inserts vulnerability findings.
    """
    df = read_uploaded_file(file_path)
    inserted_count = 0
    skipped_count = 0
    
    # Define mapping for the Vulnerability Scan report columns
    SCAN_COLUMNS = {
        'host': 'Host',
        'name': 'Name',
        'risk': 'Risk',
        'cve': 'CVE',
        'cvss_score': 'CVSS v2.0 Base Score',
        'plugin_id': 'Plugin ID',
        'description': 'Description',
        'solution': 'Solution'
    }

    # Verify all required columns are present in the dataframe
    required_cols = list(SCAN_COLUMNS.values())
    if not all(col in df.columns for col in required_cols):
        missing_cols = [col for col in required_cols if col not in df.columns]
        raise KeyError(f"Missing required column in scan report: {', '.join(missing_cols)}")


    for index, row in df.iterrows():
        try:
            # 1. Use the 'Host' column (IP) to find the corresponding Asset document
            asset_ip = str(row[SCAN_COLUMNS['host']]).strip()
            asset_doc = Asset.objects(ip_address=asset_ip).first()

            if not asset_doc:
                # Skip if the asset doesn't exist in your inventory
                skipped_count += 1
                continue
                
            # 2. Prepare the data for insertion
            # Handle potential NaN values for optional fields like CVE/CVSS
            cve_id = row[SCAN_COLUMNS['cve']] if pd.notna(row[SCAN_COLUMNS['cve']]) else None
            cvss_score = float(row[SCAN_COLUMNS['cvss_score']]) if pd.notna(row[SCAN_COLUMNS['cvss_score']]) else None

            scan_data = VulnerabilityScan(
                asset=asset_doc, # The ReferenceField linking to the Asset
                vulnerability_name=row[SCAN_COLUMNS['name']],
                severity=row[SCAN_COLUMNS['risk']],
                plugin_id=str(row[SCAN_COLUMNS['plugin_id']]),
                cve_id=cve_id,
                cvss_score=cvss_score,
                description=row[SCAN_COLUMNS['description']],
                solution=row[SCAN_COLUMNS['solution']]
            )
            
            # 3. Save the new scan finding document
            scan_data.save()
            inserted_count += 1
            
        except Exception as e:
            # Catch errors during type conversion or database saving
            print(f"An error occurred on row {index} (IP {asset_ip}): {e}")
            skipped_count += 1
            
    return f"Vulnerability scan upload complete. Findings processed: {inserted_count}, Skipped/Error: {skipped_count}"

## --- GAP Reporting and Remediation ---

def get_vulnerability_gap():
    """
    Identifies the GAP: all existing vulnerability scans that have NO corresponding
    remediation record.
    """
    
    # 1. Get the list of scan IDs that HAVE been fixed (Remediated)
    remediated_scan_ids = RemediationRecord.objects.distinct('scan')

    # 2. Query the VulnerabilityScan collection for documents whose ID is NOT in the remediated list
    # The id__nin operator means 'ID Not In' the list
    gap_findings = VulnerabilityScan.objects(id__nin=remediated_scan_ids).order_by('-severity', 'asset.hostname')
    
    # 3. Prepare the data for display
    gap_data = []
    for finding in gap_findings:
        # Fetch the linked Asset document to get hostname/IP/owner
        asset = finding.asset.fetch()
        
        gap_data.append({
            'scan_id': str(finding.id), # MongoDB ObjectIds need to be converted to string for display
            'hostname': asset.hostname,
            'ip_address': asset.ip_address,
            'owner_team': asset.infra_owner or asset.app_owner, # Show relevant owner
            'vulnerability_name': finding.vulnerability_name,
            'severity': finding.severity,
            'cvss_score': finding.cvss_score,
            'scan_date': finding.scan_date.strftime('%Y-%m-%d'),
        })
        
    return gap_data


def create_remediation_record(scan_object_id, action, status):
    """
    Creates a new RemediationRecord, effectively removing the linked
    VulnerabilityScan from the GAP report.
    """
    
    # 1. Find the target VulnerabilityScan document using the ObjectId
    scan_doc = VulnerabilityScan.objects(id=scan_object_id).first()
    
    if not scan_doc:
        raise ValueError(f"Scan ID {scan_object_id} not found.")

    # 2. Check if it's already remediated (prevent duplicates)
    if RemediationRecord.objects(scan=scan_doc).first():
        # Prevent insertion of duplicates, but don't error out completely
        return True 
        
    # 3. Create and save the RemediationRecord
    remediation = RemediationRecord(
        scan=scan_doc, # ReferenceField link
        action_taken=action,
        verified_status=status
    )
    remediation.save()
    
    return True
