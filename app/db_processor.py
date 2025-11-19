import pandas as pd
from mongoengine import Q
from mongoengine.errors import NotUniqueError
from datetime import datetime
# CRITICAL IMPORT: Include the new UnknownVulnerabilityScan model
from app.models import Asset, VulnerabilityScan, RemediationRecord, UnknownAsset, UnknownVulnerabilityScan 
import os

# --- Helper function to read uploaded file types ---
def read_uploaded_file(file_path):
    """Reads a CSV or Excel file into a pandas DataFrame."""
    try:
        if not os.path.exists(file_path):
             raise FileNotFoundError(f"File not found at path: {file_path}")

        if file_path.lower().endswith('.csv'):
            # Use 'dtype=str' to prevent pandas from auto-casting IDs/IPs to numbers
            df = pd.read_csv(file_path, dtype=str)
        elif file_path.lower().endswith(('.xlsx', '.xls')):
            # Using str conversion later for Excel for cleaner handling
            df = pd.read_excel(file_path, sheet_name=0) 
        else:
            raise ValueError("Unsupported file type. Must be CSV or Excel.")
        
        df.columns = df.columns.astype(str).str.strip()
        return df
    except Exception as e:
        raise Exception(f"Error reading file {os.path.basename(file_path)}: {e}")

# --- Asset Calculated Fields Updater (Main Asset Table) ---

def update_asset_calculated_fields(asset_doc):
    """
    Recalculates VA count, last scan date, and last remediation date 
    for a specific Asset document.
    """
    
    # 1. Calculate VA Count (Total UNREMEDIATED findings)
    # Get the IDs of all scan findings that have a remediation record
    remediated_scan_ids = RemediationRecord.objects(
        scan__in=VulnerabilityScan.objects(asset=asset_doc)
    ).distinct('scan')
    
    # Count all vulnerability scans linked to this asset, excluding those that are remediated
    va_count = VulnerabilityScan.objects(
        Q(asset=asset_doc) & Q(id__nin=remediated_scan_ids)
    ).count()

    # 2. Find Last Scan Date
    last_scan = VulnerabilityScan.objects(asset=asset_doc).order_by('-scan_date').first()
    last_scan_date = last_scan.scan_date if last_scan else None

    # 3. Find Last Remediated Date
    last_remediated = RemediationRecord.objects(
        scan__in=VulnerabilityScan.objects(asset=asset_doc)
    ).order_by('-remediation_date').first()
    last_remediated_date = last_remediated.remediation_date if last_remediated else None

    # 4. Update the Asset Document
    asset_doc.update(
        set__va_count=va_count,
        set__last_scan_date=last_scan_date,
        set__last_remediated_date=last_remediated_date,
        set__last_updated=datetime.utcnow()
    )
    
    return va_count

# --- Unknown Host/Finding Updater ---

def calculate_unknown_asset_va_count(ip_address):
    """Calculates the unique finding count for an unknown host."""
    return UnknownVulnerabilityScan.objects(private_ip=ip_address).count()

def update_unknown_asset_host(ip_address, hostname, scan_date):
    """
    Updates the main UnknownAsset host record with the latest calculated VA count and scan date.
    """
    va_count = calculate_unknown_asset_va_count(ip_address)
    
    # Upsert the UnknownAsset record
    result = UnknownAsset.objects(private_ip=ip_address).update_one(
        set__hostname=hostname,
        set__va_count=va_count,
        set__last_scan_date=scan_date,
        upsert=True
    )
    # The return value from update_one is complex; we just assume success for now.
    return va_count

# --- Asset Ingestion Functions ---

def upload_asset_list(file_path):
    """
    Parses asset report, inserts/updates records, AND REMOVES new assets from 
    the UnknownAsset staging area AND removes all associated unknown findings.
    """
    df = read_uploaded_file(file_path)
    inserted_count = 0
    updated_count = 0
    unknown_removed_count = 0
    
    COLUMN_MAP = {
        'hostname': 'Hostname', 'private_ip': 'Private_IP', 'description': 'Description',
        'status': 'Status', 'role': 'Role', 'env': 'ENV', 'location': 'Location',
        'platform': 'Platform', 'infra_owner': 'Infra_Owner', 'app_owner': 'App_Owner',
        'vendor_availability': 'Vendor_Availability'
    }

    required_cols = list(COLUMN_MAP.values())
    if not all(col in df.columns for col in required_cols):
        missing_cols = [col for col in required_cols if col not in df.columns]
        raise KeyError(f"Missing required column in report: {', '.join(missing_cols)}")

    for index, row in df.iterrows():
        try:
            asset_ip = str(row[COLUMN_MAP['private_ip']]).strip()
            if not asset_ip: continue
            
            # --- Cleanup: Remove from UnknownAsset and UnknownVulnerabilityScan staging ---
            removal_result_host = UnknownAsset.objects(private_ip=asset_ip).delete()
            if removal_result_host > 0:
                unknown_removed_count += removal_result_host
                # Also delete all associated staged findings for this IP
                UnknownVulnerabilityScan.objects(private_ip=asset_ip).delete()
            
            # --- Main Asset Upsert Logic ---
            update_fields = {
                'hostname': row[COLUMN_MAP['hostname']], 'description': row[COLUMN_MAP['description']],
                'status': row[COLUMN_MAP['status']], 'role': row[COLUMN_MAP['role']],
                'env': row[COLUMN_MAP['env']], 'location': row[COLUMN_MAP['location']],
                'platform': row[COLUMN_MAP['platform']], 'infra_owner': row[COLUMN_MAP['infra_owner']],
                'app_owner': row[COLUMN_MAP['app_owner']], 'vendor_availability': row[COLUMN_MAP['vendor_availability']],
            }
            
            result = Asset.objects(private_ip=asset_ip).update_one(
                set__hostname=update_fields['hostname'], set__description=update_fields['description'],
                set__status=update_fields['status'], set__role=update_fields['role'],
                set__env=update_fields['env'], set__location=update_fields['location'],
                set__platform=update_fields['platform'], set__infra_owner=update_fields['infra_owner'],
                set__app_owner=update_fields['app_owner'], set__vendor_availability=update_fields['vendor_availability'],
                set__last_updated=datetime.utcnow(),
                upsert=True
            )
            
            if result.upserted_id:
                inserted_count += 1
            elif result.modified_count > 0:
                updated_count += 1
            
        except KeyError as e:
            raise Exception(f"Missing column or error on row {index}: {e}")
        except Exception as e:
            print(f"An error occurred on row {index}: {e}")
            
    return (f"Asset upload complete. New: {inserted_count}, Updated: {updated_count}. "
            f"Hosts promoted from unknown list: {unknown_removed_count}")

# --- Scan Ingestion Functions ---

def upload_vulnerability_scan(file_path):
    """
    Parses scan report, links to assets, or stores as UnknownAsset if not found.
    Uses an explicit check and NotUniqueError handling to prevent duplicates.
    """
    df = read_uploaded_file(file_path)
    inserted_count = 0
    duplicate_count = 0
    unknown_finding_count = 0
    
    SCAN_COLUMNS = {
        'host': 'Host', 'name': 'Name', 'risk': 'Risk', 'cve': 'CVE',
        'cvss_score': 'CVSS v2.0 Base Score', 'plugin_id': 'Plugin ID',
        'description': 'Description', 'solution': 'Solution'
    }

    required_cols = list(SCAN_COLUMNS.values())
    if not all(col in df.columns for col in required_cols):
        missing_cols = [col for col in required_cols if col not in df.columns]
        raise KeyError(f"Missing required column in scan report: {', '.join(missing_cols)}")


    for index, row in df.iterrows():
        asset_ip = ""
        try:
            # --- Data Cleaning (CRITICAL FOR DUPLICATE CHECK) ---
            asset_ip = str(row[SCAN_COLUMNS['host']]).strip()
            if not asset_ip: continue
            
            asset_hostname_col = [col for col in df.columns if col.lower() == 'hostname']
            asset_hostname = str(row[asset_hostname_col[0]]).strip() if asset_hostname_col and pd.notna(row[asset_hostname_col[0]]) else "Unknown Hostname"
            
            asset_doc = Asset.objects(private_ip=asset_ip).first()
            
            # --- ULTRA-ROBUST PLUGIN ID CLEANING ---
            plugin_id_raw = row[SCAN_COLUMNS['plugin_id']]
            if pd.isna(plugin_id_raw):
                continue

            if isinstance(plugin_id_raw, (int, float)):
                plugin_id_str = str(int(plugin_id_raw)) 
            else:
                plugin_id_str = str(plugin_id_raw).strip()
            # --- END ROBUST CLEANING ---
            
            # Strip other fields for consistent storage
            vuln_name = str(row[SCAN_COLUMNS['name']]).strip()
            vuln_severity = str(row[SCAN_COLUMNS['risk']]).strip()
            
            # Diagnostic Log: What we are checking
            print(f"DEBUG CHECKING: IP={asset_ip}, PluginID={plugin_id_str}")

            if not asset_doc:
                # --- ASSET IS UNKNOWN: Store the finding in the staging area ---
                
                # 1. Attempt to insert unique finding into UnknownVulnerabilityScan
                try:
                    UnknownVulnerabilityScan(
                        private_ip=asset_ip,
                        plugin_id=plugin_id_str,
                        vulnerability_name=vuln_name,
                        severity=vuln_severity,
                        scan_date=datetime.utcnow()
                    ).save()
                    
                    # If save is successful, it was a new unique finding
                    unknown_finding_count += 1
                    
                    # 2. Update the parent UnknownAsset host record with the new count
                    update_unknown_asset_host(asset_ip, asset_hostname, datetime.utcnow())
                    
                except NotUniqueError:
                    # Duplicate finding on an unknown host, skip it, but update the host's last scan date
                    update_unknown_asset_host(asset_ip, asset_hostname, datetime.utcnow())
                    duplicate_count += 1
                    print(f"DEBUG SKIPPED (Unknown): Duplicate finding for IP={asset_ip}, PluginID={plugin_id_str}")
                    continue
                
                except Exception as e:
                    print(f"Error saving unknown scan finding for {asset_ip}: {e}")
                    continue

                continue # Continue to next row in the Excel file
            
            # --- ASSET IS KNOWN & NOT DUPLICATE: Insert the finding ---
            
            # CRITICAL DUPLICATE CHECK (Layer 2 - Python Check)
            existing_scan = VulnerabilityScan.objects(asset=asset_doc, plugin_id=plugin_id_str).first()
            
            if existing_scan:
                print(f"DEBUG SKIPPED (Known): Duplicate found for IP={asset_ip}, PluginID={plugin_id_str}")
                duplicate_count += 1
                continue
                
            # If we reach here, it's a new unique finding on a known host.
            
            vuln_description = str(row[SCAN_COLUMNS['description']]).strip()
            vuln_solution = str(row[SCAN_COLUMNS['solution']]).strip()
            vuln_cve = str(row[SCAN_COLUMNS['cve']]).strip() if pd.notna(row[SCAN_COLUMNS['cve']]) else None 
            cvss_score = float(row[SCAN_COLUMNS['cvss_score']]) if pd.notna(row[SCAN_COLUMNS['cvss_score']]) else None

            scan_data = VulnerabilityScan(
                asset=asset_doc, vulnerability_name=vuln_name,
                severity=vuln_severity, plugin_id=plugin_id_str,
                cve_id=vuln_cve, cvss_score=cvss_score, 
                description=vuln_description, solution=vuln_solution
            )
            
            try:
                # Layer 1 - DB-Level enforcement occurs here
                scan_data.save()
                inserted_count += 1
                
                # Update the parent Asset's calculated fields ONLY if insertion was successful
                update_asset_calculated_fields(asset_doc) 
            except NotUniqueError:
                # Should not be reached if Layer 2 is working, but acts as a fail-safe
                print(f"DEBUG DB-ERROR: NotUniqueError hit for IP={asset_ip}, PluginID={plugin_id_str}")
                duplicate_count += 1
                continue
            
        except Exception as e:
            print(f"An error occurred on row {index} (IP {asset_ip}): {e}")
            
    # The unknown_finding_count is the total number of unique findings added to the staging area.
    return (f"Vulnerability scan upload complete. Known Findings added: {inserted_count}, "
            f"Unknown Findings added: {unknown_finding_count}. "
            f"Duplicates skipped: {duplicate_count}")

# --- Reporting and Display Functions ---

def get_asset_list_for_display():
    """Fetches all known assets with their calculated fields for the display page."""
    
    asset_docs = Asset.objects.order_by('hostname')
    asset_data = []
    
    for asset in asset_docs:
        
        asset_data.append({
            'asset_id': str(asset.id),
            'hostname': asset.hostname,
            'description': asset.description,
            'role': asset.role,
            'private_ip': asset.private_ip,
            'env': asset.env,
            'location': asset.location,
            'platform': asset.platform,
            'va_count': asset.va_count,
            'last_scan_date': asset.last_scan_date.strftime('%Y-%m-%d') if asset.last_scan_date else 'N/A',
            'last_remediated_date': asset.last_remediated_date.strftime('%Y-%m-%d') if asset.last_remediated_date else 'N/A',
            'feedback': asset.feedback or 'Click to add feedback',
        })
        
    return asset_data

def get_unknown_hosts_for_display():
    """Fetches all unknown assets for the new display page."""
    
    unknown_docs = UnknownAsset.objects.order_by('-va_count') # Order by highest risk
    unknown_data = []
    
    for host in unknown_docs:
        unknown_data.append({
            'private_ip': host.private_ip,
            'hostname': host.hostname,
            'va_count': host.va_count,
            'last_scan_date': host.last_scan_date.strftime('%Y-%m-%d %H:%M') if host.last_scan_date else 'N/A',
            'feedback': host.feedback or 'N/A',
            'host_id': str(host.id)
        })
        
    return unknown_data

def get_vulnerability_gap():
    """
    Identifies the GAP: all existing vulnerability scans that have NO corresponding
    remediation record.
    """
    
    remediated_scan_ids = RemediationRecord.objects.distinct('scan')

    gap_findings = VulnerabilityScan.objects(id__nin=remediated_scan_ids).order_by('-severity', 'asset.hostname')
    
    gap_data = []
    for finding in gap_findings:
        try:
            asset = finding.asset.fetch()
        except Exception:
            continue 
            
        gap_data.append({
            'scan_id': str(finding.id), 
            'hostname': asset.hostname,
            'ip_address': asset.private_ip,
            'owner_team': asset.infra_owner or asset.app_owner, 
            'vulnerability_name': finding.vulnerability_name,
            'severity': finding.severity,
            'cvss_score': finding.cvss_score,
            'scan_date': finding.scan_date.strftime('%Y-%m-%d'),
        })
        
    return gap_data


def create_remediation_record(scan_object_id, action, status):
    """
    Creates a new RemediationRecord and updates the associated asset's calculated fields.
    """
    
    scan_doc = VulnerabilityScan.objects(id=scan_object_id).first()
    
    if not scan_doc:
        raise ValueError(f"Scan ID {scan_object_id} not found.")

    # Check if it's already remediated (prevent duplicates)
    if RemediationRecord.objects(scan=scan_doc).first():
        return True 
        
    # 1. Create and save the RemediationRecord
    remediation = RemediationRecord(
        scan=scan_doc, 
        action_taken=action,
        verified_status=status
    )
    remediation.save()
    
    # 2. CRITICAL: Update the asset's calculated fields (VA count and last remediated date)
    asset_doc = scan_doc.asset.fetch()
    if asset_doc:
        update_asset_calculated_fields(asset_doc)
    
    return True
