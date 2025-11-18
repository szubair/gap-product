from flask_mongoengine import MongoEngine
# CRITICAL FIX: Only import classes defined in the mongoengine library.
from mongoengine import Document, StringField, IntField, FloatField, DateTimeField, ReferenceField
from datetime import datetime

db = MongoEngine()

# --- MODEL 1: Asset Inventory ---
class Asset(Document):
    """
    Main asset inventory document, stores core information and calculated metrics.
    """
    hostname = StringField(required=True)
    private_ip = StringField(required=True, unique=True)
    description = StringField(default=None)
    status = StringField(default="Active") # Active, Decommissioned, etc.
    role = StringField(default=None) # e.g., Frontend, Database, Firewall
    env = StringField(default=None) # e.g., Production, Staging, Dev
    location = StringField(default=None)
    platform = StringField(default=None)
    infra_owner = StringField(default=None) # Infrastructure owner team
    app_owner = StringField(default=None) # Application owner team
    vendor_availability = StringField(default=None) # e.g., 99.99%

    # Calculated fields (updated by db_processor.py)
    va_count = IntField(default=0)
    last_scan_date = DateTimeField(default=None)
    last_remediated_date = DateTimeField(default=None)
    last_updated = DateTimeField(default=datetime.utcnow) # When the document itself was last modified
    feedback = StringField(default=None) # For manual notes or overrides

    meta = {'collection': 'assets'}

# --- MODEL 2: Vulnerability Scan Findings ---
class VulnerabilityScan(Document):
    """
    Stores individual vulnerability findings linked to a specific Asset.
    """
    asset = ReferenceField(Asset, required=True, reverse_delete_rule=2) # Cascade delete if Asset is removed
    vulnerability_name = StringField(required=True)
    severity = StringField(required=True) # e.g., Critical, High, Medium, Low
    plugin_id = StringField(required=True)
    cve_id = StringField(default=None)
    cvss_score = FloatField(default=0.0)
    description = StringField(default=None)
    solution = StringField(default=None)
    
    # Store the date of the scan event itself
    scan_date = DateTimeField(default=datetime.utcnow) 

    meta = {'collection': 'vulnerability_scans'}

# --- MODEL 3: Remediation Records ---
class RemediationRecord(Document):
    """
    Records a completed remediation action for a specific VulnerabilityScan finding.
    """
    scan = ReferenceField(VulnerabilityScan, required=True, unique=True, reverse_delete_rule=2) 
    action_taken = StringField(required=True) # e.g., Patch Applied, Configuration Change, Mitigation
    remediation_date = DateTimeField(default=datetime.utcnow)
    verified_status = StringField(required=True) # e.g., Verified, Accepted Risk, False Positive

    meta = {'collection': 'remediation_records'}
    
# --- MODEL 4: UNKNOWN HOSTS (The new required model) ---
class UnknownAsset(Document):
    """
    Temporary staging area for assets found in scan reports but not in the main asset inventory.
    """
    private_ip = StringField(required=True, unique=True)
    hostname = StringField(default="Unknown Hostname")
    
    # Calculated fields for immediate reporting
    va_count = IntField(default=0)
    last_scan_date = DateTimeField(default=datetime.utcnow)
    feedback = StringField(default=None) 

    meta = {'collection': 'unknown_assets'}
