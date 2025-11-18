# app/models.py (Updated Asset Model)

from app import mongo
from datetime import datetime
from mongoengine import Document, StringField, DateTimeField, ReferenceField, FloatField

class Asset(Document):
    # Core unique fields for linking
    hostname = StringField(max_length=120, required=True)
    ip_address = StringField(max_length=15, unique=True, required=True) # Mapped from 'Private IP'

    # Descriptive and ownership fields
    description = StringField(max_length=256)
    status = StringField(max_length=50) # Mapped from 'STATUS'
    role = StringField(max_length=50)
    env = StringField(max_length=50) # Mapped from 'ENV'
    location = StringField(max_length=50)
    platform = StringField(max_length=50)
    infra_owner = StringField(max_length=64) # Mapped from 'Infra - Owner'
    app_owner = StringField(max_length=64) # Mapped from 'App - Owner'
    vendor_availability = StringField(max_length=50) # Mapped from 'Vendor Availability'

# app/models.py (Updated VulnerabilityScan Model)
class VulnerabilityScan(Document):
    # Core linkage
    asset = ReferenceField('Asset', required=True) # Links to the Asset document
    scan_date = DateTimeField(default=datetime.utcnow)
    
    # Core vulnerability info
    vulnerability_name = StringField(max_length=256, required=True)
    severity = StringField(max_length=32) # Mapped from 'Risk'
    
    # New fields from the report
    plugin_id = StringField(max_length=20)
    cve_id = StringField(max_length=256) # Can store multiple CVEs separated by commas
    cvss_score = FloatField() # Mapped from 'CVSS v2.0 Base Score'
    description = StringField() # Mapped from 'Description'
    solution = StringField() # Mapped from 'Solution'
    
    meta = {'collection': 'scans'}

# ... (Asset and RemediationRecord models follow)
