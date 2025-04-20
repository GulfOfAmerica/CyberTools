import sqlite3
import requests
import time
import logging
from typing import Optional

# Configure logging
logging.basicConfig(filename='virustotal_update_log.txt', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# VirusTotal API configuration
VT_API_KEY = "your_virustotal_api_key_here"  # Replace with your API key
VT_API_URL = "https://www.virustotal.com/api/v3/files/"

def init_db(db_path: str) -> None:
    """Initialize SQLite database for malware signatures."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS malware_signatures (
                hash TEXT PRIMARY KEY,
                threat_name TEXT,
                threat_type TEXT,
                last_updated TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
        logging.info("Database initialized successfully.")
    except sqlite3.Error as e:
        logging.error(f"Database initialization error: {e}")
        raise

def query_virustotal(file_hash: str) -> Optional[dict]:
    """Query VirusTotal for a file hash."""
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(f"{VT_API_URL}{file_hash}", headers=headers)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            logging.info(f"Hash {file_hash} not found in VirusTotal.")
            return None
        else:
            logging.error(f"VirusTotal API error: {response.status_code} - {response.text}")
            return None
    except requests.RequestException as e:
        logging.error(f"Error querying VirusTotal: {e}")
        return None

def update_signature_db(db_path: str, file_hash: str) -> bool:
    """Update the signature database with VirusTotal data."""
    vt_data = query_virustotal(file_hash)
    if not vt_data:
        return False

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        threat_name = vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 'Unknown')
        threat_type = vt_data.get('data', {}).get('attributes', {}).get('type_description', 'Unknown')
        last_updated = time.strftime('%Y-%m-%d %H:%M:%S')

        cursor.execute('''
            INSERT OR REPLACE INTO malware_signatures (hash, threat_name, threat_type, last_updated)
            VALUES (?, ?, ?, ?)
        ''', (file_hash, threat_name, threat_type, last_updated))

        conn.commit()
        conn.close()
        logging.info(f"Updated signature for hash {file_hash}")
        return True
    except sqlite3.Error as e:
        logging.error(f"Database update error: {e}")
        return False

def main():
    """Main function to test VirusTotal integration."""
    db_path = "malware_signatures.db"
    test_hash = "d41d8cd98f00b204e9800998ecf8427e"  # Example hash (empty file)

    try:
        init_db(db_path)
        if update_signature_db(db_path, test_hash):
            print(f"Successfully updated signature for hash {test_hash}")
        else:
            print(f"Failed to update signature for hash {test_hash}")
    except Exception as e:
        print(f"An error occurred: {e}")
        logging.error(f"Main function error: {e}")

if __name__ == "__main__":
    main()
