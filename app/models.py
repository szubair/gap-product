# app/models.py (Updated Asset Model)

from app import mongo
from mongoengine import Document, StringField, ListField

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

    # ... (other models like VulnerabilityScan and RemediationRecord remain the same)
