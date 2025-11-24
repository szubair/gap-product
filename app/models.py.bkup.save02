from datetime import datetime
from mongoengine import Document, ReferenceField, StringField, IntField, FloatField, DateTimeField, ListField

# --- 1. Asset Model (The main inventory) ---

class Asset(Document):
    """
    Represents an inventory asset (server, device, etc.). 
    This is the central entity for tracking security posture.
    """
    
    # Required Fields
    private_ip = StringField(required=True, unique=True)
    hostname = StringField(required=True)
    
    # Static Inventory Fields
    description = StringField(default='')
    status = StringField(default='Active')
    role = StringField(default='')
    env = StringField(default='')
    location = StringField(default='')
    platform = StringField(default='')
    
    # Ownership Fields
    infra_owner = StringField(default='N/A')
    app_owner = StringField(default='N/A')
    vendor_availability = StringField(default='N/A')

    # Calculated Fields (Updated by db_processor.py)
    va_count = IntField(default=0)
    last_scan_date = DateTimeField(default=None)
    last_remediated_date = DateTimeField(default=None)
    
    # Metadata
    last_updated = DateTimeField(default=datetime.utcnow)
    feedback = StringField(default='') # For analyst notes

    meta = {
        'collection': 'assets',
        'indexes': [
            'private_ip',
            'hostname'
        ]
    }

# --- 2. VulnerabilityScan Model (The Finding) ---

class VulnerabilityScan(Document):
    """
    Represents a single vulnerability finding on a specific asset from a scan report.
    """
    
    # Link to the Asset
    asset = ReferenceField(Asset, required=True)
    
    # Unique Identifier for the vulnerability type
    plugin_id = StringField(required=True) 

    # Finding Details
    vulnerability_name = StringField(required=True)
    severity = StringField(required=True) # e.g., Critical, High, Medium, Low
    cve_id = StringField(default=None) # Can be None/Blank
    cvss_score = FloatField(default=0.0)
    description = StringField(default='')
    solution = StringField(default='')

    # Metadata
    scan_date = DateTimeField(default=datetime.utcnow)
    
    meta = {
        'collection': 'vulnerability_scans',
        # CRITICAL FIX: Ensures only one finding per asset and plugin ID exists.
        'indexes': [
            {'fields': ('asset', 'plugin_id'), 'unique': True}
        ]
    }

# --- 3. RemediationRecord Model (The Fix) ---

class RemediationRecord(Document):
    """
    Tracks when a specific vulnerability finding was resolved/remediated.
    """
    
    # Link to the specific finding that was fixed
    scan = ReferenceField(VulnerabilityScan, required=True, unique=True) # Ensure only one remediation per scan

    # Remediation Details
    remediation_date = DateTimeField(default=datetime.utcnow)
    action_taken = StringField(default='') # e.g., Patched, Decommissioned, Mitigated
    verified_status = StringField(default='Verified') # e.g., Verified, Pending Re-scan

    meta = {
        'collection': 'remediation_records',
        'indexes': [
            'scan'
        ]
    }
    
# --- 4. UnknownAsset Model (The Host Staging Area) ---

class UnknownAsset(Document):
    """
    Temporary collection for assets found in scans but not in the main Asset inventory.
    """
    private_ip = StringField(required=True, unique=True)
    hostname = StringField(default='Unknown Hostname')
    
    # Calculated fields based on UnknownVulnerabilityScan (new logic)
    va_count = IntField(default=0) # Must be calculated from the new finding collection
    last_scan_date = DateTimeField(default=datetime.utcnow)
    
    # Metadata
    feedback = StringField(default='') # For analyst notes

    meta = {
        'collection': 'unknown_assets',
        'indexes': [
            'private_ip'
        ]
    }

# --- 5. NEW: UnknownVulnerabilityScan Model (The Finding Staging Area) ---

class UnknownVulnerabilityScan(Document):
    """
    Tracks unique vulnerability findings on assets not yet in the main inventory.
    This is necessary to maintain a correct 'va_count' for UnknownAsset.
    """
    
    # Link to the Unknown Asset (via IP, since it's the unique key)
    private_ip = StringField(required=True)
    
    # Unique Identifier for the vulnerability type
    plugin_id = StringField(required=True) 
    
    # Finding Details (Optional, but good for context if the host is promoted later)
    vulnerability_name = StringField(required=True)
    severity = StringField(required=True)

    # Metadata
    scan_date = DateTimeField(default=datetime.utcnow)

    meta = {
        'collection': 'unknown_vulnerability_scans',
        # CRITICAL: Unique constraint on IP + Plugin ID for unknown findings
        'indexes': [
            {'fields': ('private_ip', 'plugin_id'), 'unique': True}
        ]
    }
