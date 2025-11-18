from flask_mongoengine import MongoEngine
from mongoengine import Document, StringField, IntField, FloatField, DateTimeField, ReferenceField
from datetime import datetime

db = MongoEngine()

class Asset(Document):
    """
    Represents an asset in the inventory.
    Updated to include calculated fields for reporting.
    """
    # Core Asset Data (from assets file)
    hostname = StringField(required=True)
    private_ip = StringField(required=True, unique=True)
    description = StringField()
    status = StringField()
    role = StringField()
    env = StringField()
    location = StringField()
    platform = StringField()
    infra_owner = StringField()
    app_owner = StringField()
    vendor_availability = StringField()
    
    # --- CALCULATED FIELDS FOR DISPLAY ---
    # VA Count: Total current vulnerabilities (not remediated)
    va_count = IntField(default=0)
    
    # Last Scan Date: Date of the most recent vulnerability scan finding for this asset
    last_scan_date = DateTimeField(default=None)
    
    # Last Remediated Date: Date of the most recent remediation record for this asset
    last_remediated_date = DateTimeField(default=None)
    
    # Feedback: User-added note from the portal
    feedback = StringField(default=None)
    
    # Metadata
    last_updated = DateTimeField(default=datetime.utcnow)
    
    meta = {'collection': 'assets'} 

class VulnerabilityScan(Document):
    """
    Represents a specific vulnerability finding from a scan report.
    It links back to the Asset that owns the vulnerability.
    """
    asset = ReferenceField(Asset, reverse_delete_rule=2, required=True) # 2=CASCADE
    
    # Scan Finding Details
    vulnerability_name = StringField(required=True)
    severity = StringField()
    plugin_id = StringField()
    cve_id = StringField()
    cvss_score = FloatField()
    description = StringField()
    solution = StringField()
    
    # Metadata
    scan_date = DateTimeField(default=datetime.utcnow)
    
    meta = {'collection': 'vulnerability_scans'}

class RemediationRecord(Document):
    """
    Tracks that a specific vulnerability (VulnerabilityScan) has been remediated.
    This removes the finding from the active GAP report.
    """
    scan = ReferenceField(VulnerabilityScan, reverse_delete_rule=2, required=True, unique=True)
    action_taken = StringField(required=True)
    verified_status = StringField(required=True) # e.g., 'Fixed', 'Accepted Risk'
    remediation_date = DateTimeField(default=datetime.utcnow)
    
    meta = {'collection': 'remediation_records'}
