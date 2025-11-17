# app/db_processor.py
import pandas as pd
import os
from app.models import Asset
from mongoengine.errors import NotUniqueError

def read_uploaded_file(file_path):
    """Reads CSV or Excel files into a Pandas DataFrame."""
    _, file_extension = os.path.splitext(file_path)
    
    if file_extension in ['.csv']:
        return pd.read_csv(file_path)
    elif file_extension in ['.xlsx', '.xls']:
        return pd.read_excel(file_path)
    else:
        raise ValueError(f"Unsupported file type: {file_extension}")

def upload_asset_list(file_path):
    """Parses asset report and inserts/updates records into the MongoDB Asset collection."""
    df = read_uploaded_file(file_path)
    inserted_count = 0
    skipped_count = 0
    
    # 1. Clean up column names for easier access (optional but recommended)
    df.columns = df.columns.str.strip().str.replace(' - ', '_').str.lower()

    # 2. Define the mapping from the file columns to the Asset model fields
    COLUMN_MAP = {
        'hostname': 'HostName',
        'ip_address': 'Private IP',
        'description': 'Description',
        'status': 'STATUS',
        'role': 'Role',
        'env': 'ENV',
        'location': 'Location',
        'platform': 'Platform',
        'infra_owner': 'Infra_Owner', # Use the cleaned name
        'app_owner': 'App_Owner',     # Use the cleaned name
        'vendor_availability': 'Vendor Availability'
    }

    for index, row in df.iterrows():
        try:
            # Create a dictionary of data to insert, using the required column mapping
            asset_data = {
                'hostname': row[COLUMN_MAP['hostname']],
                'ip_address': row[COLUMN_MAP['ip_address']],
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
            
            # Use update_one with upsert=True to either insert a new record or update an existing one
            # We use 'ip_address' (Private IP) as the unique query key
            Asset.objects(ip_address=asset_data['ip_address']).update_one(
                set__hostname=asset_data['hostname'], # Example of updating existing fields
                upsert=True, 
                full_result=False, 
                **asset_data
            )
            inserted_count += 1
            
        except NotUniqueError:
            # This should be handled by update_one, but good for general error catching
            skipped_count += 1
            print(f"Skipping row {index}: IP Address already exists.")
        except KeyError as e:
            # Handle case where a required column is missing from the report
            raise Exception(f"Missing required column in report: {e}")
        except Exception as e:
            print(f"An error occurred on row {index}: {e}")
            skipped_count += 1
            
    return f"Asset list upload complete. Successfully processed: {inserted_count}, Skipped/Error: {skipped_count}"
