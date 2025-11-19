from datetime import datetime
import pandas as pd
from mongoengine.errors import NotUniqueError
from app.models import Asset, VulnerabilityScan, RemediationRecord, UnknownAsset, UnknownVulnerabilityScan # Import all models

# --- Helper Function for VA Count Calculation ---
def update_asset_calculated_fields(asset_doc: Asset):
    """
    Calculates the current VA count, last scan date, and last remediated date 
    for a given Asset based on linked VulnerabilityScan and RemediationRecord data.
    """
    
    # 1. Find all scans for this asset that have a remediation record
    # We collect the IDs of the scans that are remediated
    remediated_scan_ids = [
        rr.scan.id for rr in RemediationRecord.objects(scan__in=VulnerabilityScan.objects(asset=asset_doc))
    ]
    
    # 2. Find all scans that are NOT remediated (i.e., open findings)
    # Exclude scans where the ID is in the remediated_scan_ids list
    open_scans = VulnerabilityScan.objects(asset=asset_doc).filter(id__nin=remediated_scan_ids)
    
    # 3. Calculate VA Count (Number of open, unique findings)
    va_count = open_scans.count()
    
    # DEBUG VA COUNT: Check the number calculated
    print(f"DEBUG VA COUNT for IP {asset_doc.private_ip}: {va_count} open findings.")

    # 4. Determine Last Scan Date
    last_scan = VulnerabilityScan.objects(asset=asset_doc).order_by('-scan_date').first()
    last_scan_date = last_scan.scan_date if last_scan else None

    # 5. Determine Last Remediated Date
    last_remediation = RemediationRecord.objects(scan__in=VulnerabilityScan.objects(asset=asset_doc)).order_by('-remediation_date').first()
    last_remediated_date = last_remediation.remediation_date if last_remediation else None

    # 6. Update the Asset Document
    asset_doc.update(
        set__va_count=va_count,
        set__last_scan_date=last_scan_date,
        set__last_remediated_date=last_remediated_date,
        set__last_updated=datetime.utcnow()
    )

# --- NEW HELPER: Migrate Findings on Promotion ---
def migrate_unknown_findings_to_asset(asset_doc: Asset):
    """
    MIGRATION FIX: Moves findings from UnknownVulnerabilityScan to VulnerabilityScan 
    when the UnknownAsset is promoted to a formal Asset.
    """
    
    ip_address = asset_doc.private_ip
    
    # 1. Find all unknown findings for this IP
    unknown_findings = UnknownVulnerabilityScan.objects(private_ip=ip_address)
    
    # 2. Loop through and create formal VulnerabilityScan records
    for uf in unknown_findings:
        try:
            VulnerabilityScan(
                asset=asset_doc, # Link to the new Asset document
                plugin_id=uf.plugin_id,
                vulnerability_name=uf.vulnerability_name,
                severity=uf.severity,
                scan_date=uf.scan_date
                # Note: cve_id, cvss_score, description, solution are not in the UnknownVulnerabilityScan model
            ).save()
        except NotUniqueError:
            # This should not happen if the UnknownVulnerabilityScan was unique, 
            # but we catch it just in case of race conditions.
            print(f"DEBUG: Skipped duplicate finding during migration for IP {ip_address}, Plugin {uf.plugin_id}")
            pass
        except Exception as e:
            print(f"ERROR migrating unknown finding: {e}")
            pass

    # 3. Clean up staging tables after successful migration
    UnknownVulnerabilityScan.objects(private_ip=ip_address).delete()
    UnknownAsset.objects(private_ip=ip_address).delete()

    print(f"DEBUG MIGRATION: {unknown_findings.count()} findings migrated and staging records cleaned for IP {ip_address}")


# --- Main Ingestion Functions ---

def upload_asset_list(file_path):
    """
    Uploads asset inventory data from an Excel file, using private_ip for upserting.
    Also handles promotion of unknown hosts into the Asset table.
    """
    try:
        df = pd.read_excel(file_path).fillna('')
        inserted_count = 0
        updated_count = 0
        
        # Track IPs that were promoted/updated to clean up staging tables later
        promoted_ips = []

        for index, row in df.iterrows():
            asset_ip = str(row['private_ip']).strip()
            asset_hostname = str(row['hostname']).strip()
            
            if not asset_ip:
                print(f"Skipping row {index}: private_ip is missing.")
                continue

            # Upsert the Asset document
            result = Asset.objects(private_ip=asset_ip).update_one(
                set__hostname=asset_hostname,
                set__description=row['description'],
                set__status=row['status'],
                set__role=row['role'],
                set__env=row['env'],
                set__location=row['location'],
                set__platform=row['platform'],
                set__infra_owner=row['infra_owner'],
                set__app_owner=row['app_owner'],
                set__vendor_availability=row['vendor_availability'],
                set__last_updated=datetime.utcnow(),
                upsert=True
            )

            # Robust Check for inserted/updated count
            is_new_insert = False
            
            if hasattr(result, 'raw_result') and result.raw_result.get('upserted'):
                inserted_count += 1
                is_new_insert = True
            elif hasattr(result, 'modified_count') and result.modified_count > 0:
                updated_count += 1
            elif isinstance(result, int) and result > 0:
                updated_count += 1

            # --- CRITICAL FIX: Asset Promotion and VA Count Calculation ---
            if is_new_insert or updated_count > 0:
                # Fetch the newly created/updated Asset document
                asset_doc = Asset.objects(private_ip=asset_ip).first()
                if asset_doc:
                    # 1. Migrate any staged findings from the unknown collection
                    migrate_unknown_findings_to_asset(asset_doc)
                    
                    # 2. Update the VA count immediately after migration
                    update_asset_calculated_fields(asset_doc)
                    
                    promoted_ips.append(asset_ip) # Track for final cleanup if needed
                    
        return f"Asset list upload complete. Inserted: {inserted_count}, Updated: {updated_count}. Promoted/Processed: {len(promoted_ips)} hosts."

    except Exception as e:
        return f"An error occurred during asset list upload: {e}"


def upload_vulnerability_scan(file_path):
    """
    Uploads vulnerability scan data. Links findings to Assets or stages them as UnknownAssets.
    """
    try:
        df = pd.read_excel(file_path).fillna('')
        inserted_count = 0
        updated_count = 0
        duplicate_count = 0
        unknown_count = 0
        
        # Set scan date once for the entire batch
        scan_date = datetime.utcnow()

        for index, row in df.iterrows():
            asset_ip_raw = row['private_ip']
            plugin_id_raw = row['plugin_id']
            
            if not asset_ip_raw or not plugin_id_raw:
                print(f"Skipping row {index}: Missing IP or Plugin ID.")
                continue

            # --- ULTRA-ROBUST CLEANING AND DATA CONVERSION ---
            # Ensure IP is a clean string
            asset_ip = str(asset_ip_raw).strip()
            # Ensure Plugin ID is a consistent integer string (handling 90001 vs 90001.0)
            if isinstance(plugin_id_raw, (int, float)):
                plugin_id_str = str(int(plugin_id_raw))
            else:
                plugin_id_str = str(plugin_id_raw).strip()

            asset_hostname = str(row['hostname']).strip()
            
            # 1. Try to find the host in the main Asset inventory
            asset_doc = Asset.objects(private_ip=asset_ip).first()
            
            # --- HOST IS UNKNOWN (Staging Logic) ---
            if not asset_doc:
                # 1. Ensure the UnknownHost itself exists/is updated
                unknown_host_doc = UnknownAsset.objects(private_ip=asset_ip).first()
                if not unknown_host_doc:
                    # Insert new unknown host placeholder
                    UnknownAsset(
                        private_ip=asset_ip,
                        hostname=asset_hostname,
                        va_count=0, # Count is calculated from UnknownVulnerabilityScan
                        last_scan_date=scan_date
                    ).save()
                    unknown_host_doc = UnknownAsset.objects(private_ip=asset_ip).first() # Fetch for ID/Ref
                    
                else:
                    # Host exists, update scan date
                    unknown_host_doc.update(
                        set__last_scan_date=scan_date
                    )
                
                # 2. Insert/Upsert the finding into the UnknownVulnerabilityScan staging table
                try:
                    # We only need the key fields to maintain a count
                    UnknownVulnerabilityScan(
                        private_ip=asset_ip,
                        plugin_id=plugin_id_str,
                        vulnerability_name=row['vulnerability_name'],
                        severity=row['severity'],
                        scan_date=scan_date
                    ).save()
                    
                    # 3. Recalculate VA count for the UnknownAsset host placeholder
                    # Count distinct plugin IDs in the staging table for this IP
                    new_va_count = UnknownVulnerabilityScan.objects(private_ip=asset_ip).distinct('plugin_id').count()
                    unknown_host_doc.update(set__va_count=new_va_count)
                    
                    unknown_count += 1
                except NotUniqueError:
                    # Finding already exists in staging table, silently skip
                    duplicate_count += 1
                except Exception as e:
                    print(f"DEBUG DB-ERROR on row {index} (Unknown Host): {e}")

                continue # Move to next row
                
            # --- HOST IS KNOWN (Main VulnerabilityScan Logic) ---
            
            # Get other fields
            vulnerability_name = str(row['vulnerability_name']).strip()
            severity = str(row['severity']).strip()
            
            # CRITICAL DUPLICATE CHECK: Explicitly check for existence before saving
            print(f"DEBUG CHECKING: IP={asset_ip}, Plugin={plugin_id_str}")
            if VulnerabilityScan.objects(asset=asset_doc, plugin_id=plugin_id_str).first():
                duplicate_count += 1
                print(f"DEBUG SKIPPED: Duplicate found for IP={asset_ip}, Plugin={plugin_id_str}")
                continue

            # Attempt to insert the unique finding
            try:
                VulnerabilityScan(
                    asset=asset_doc,
                    plugin_id=plugin_id_str,
                    vulnerability_name=vulnerability_name,
                    severity=severity,
                    cve_id=row['cve_id'],
                    cvss_score=row['cvss_score'],
                    description=row['description'],
                    solution=row['solution'],
                    scan_date=scan_date
                ).save()
                inserted_count += 1
                
                # Call helper to update calculated fields for the asset immediately after successful insert
                update_asset_calculated_fields(asset_doc)

            except NotUniqueError:
                # Fallback check: If the explicit check failed (e.g., race condition), MongoDB catches it
                duplicate_count += 1
                print(f"DEBUG DB-ERROR on row {index}: NotUniqueError caught (fallback).")
            except Exception as e:
                print(f"An error occurred on row {index}: {e}")

        return f"Vulnerability scan upload complete. Known Findings Inserted: {inserted_count}, Unknown Findings Staged: {unknown_count}, Duplicates Skipped: {duplicate_count}."

    except Exception as e:
        return f"An error occurred during scan upload: {e}"


# --- NEW: Function to get all known assets for display ---
def get_asset_list_for_display():
    """Fetches all known assets for the main inventory display."""
    try:
        # Fetch assets, sorted by private_ip for consistency
        assets = Asset.objects().order_by('private_ip')
        
        return [{
            'id': str(a.id),
            'private_ip': a.private_ip,
            'hostname': a.hostname,
            'va_count': a.va_count,
            'status': a.status,
            'role': a.role,
            'env': a.env,
            'location': a.location,
            'platform': a.platform,
            'infra_owner': a.infra_owner,
            'app_owner': a.app_owner,
            'last_scan_date': a.last_scan_date.strftime('%Y-%m-%d %H:%M:%S') if a.last_scan_date else 'N/A',
            'last_updated': a.last_updated.strftime('%Y-%m-%d %H:%M:%S') if a.last_updated else 'N/A',
        } for a in assets]
    except Exception as e:
        print(f"Error fetching asset list: {e}")
        return []


def get_unknown_hosts_for_display():
    """Fetches all unknown hosts and their finding counts for reporting."""
    try:
        hosts = UnknownAsset.objects().order_by('-last_scan_date')
        
        # We don't need to manually calculate the VA count here as it's updated 
        # when the UnknownVulnerabilityScan collection is populated.

        return [{
            'private_ip': h.private_ip,
            'hostname': h.hostname,
            'va_count': h.va_count,
            'last_scan_date': h.last_scan_date.strftime('%Y-%m-%d %H:%M:%S') if h.last_scan_date else 'N/A',
            'feedback': h.feedback
        } for h in hosts]
    except Exception as e:
        print(f"Error fetching unknown hosts: {e}")
        return []
