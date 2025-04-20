import os
import sqlite3
import hashlib
import shutil
import datetime
import logging
import yara
import tensorflow as tf
import numpy as np
from sklearn.preprocessing import StandardScaler

# Configure logging
logging.basicConfig(filename='antivirus_log.txt', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Database and model paths
DB_PATH = "malware_signatures.db"
MODEL_PATH = "malware_detector.h5"
YARA_RULES_PATH = "rules.yar"
QUARANTINE_DIR = "quarantine"

# Load ML model and scaler (for heuristic analysis)
scaler = StandardScaler()
model = tf.keras.models.load_model(MODEL_PATH) if os.path.exists(MODEL_PATH) else None

# Load YARA rules
yara_rules = yara.compile(filepath=YARA_RULES_PATH) if os.path.exists(YARA_RULES_PATH) else None

def calculate_md5(file_path):
    """Calculate MD5 hash of a file."""
    try:
        hash_md5 = hashlib.md5()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception as e:
        logging.error(f"Error calculating MD5 for {file_path}: {e}")
        return None

def calculate_features(file_path):
    """Calculate synthetic features for ML (replace with real feature extraction)."""
    # Example: [file_size, entropy, number_of_strings]
    file_size = os.path.getsize(file_path) / 1024  # Size in KB
    entropy = 6.0  # Placeholder (implement entropy calculation)
    num_strings = 50  # Placeholder
    return np.array([[file_size, entropy, num_strings]])

def check_signature_db(file_hash):
    """Check if a hash exists in the signature database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT threat_name FROM malware_signatures WHERE hash = ?", (file_hash,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None
    except sqlite3.Error as e:
        logging.error(f"Database query error: {e}")
        return None

def quarantine_file(file_path):
    """Move a suspicious file to quarantine."""
    try:
        if not os.path.exists(QUARANTINE_DIR):
            os.makedirs(QUARANTINE_DIR)
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        quarantine_path = os.path.join(QUARANTINE_DIR, f"{timestamp}_{os.path.basename(file_path)}")
        shutil.move(file_path, quarantine_path)
        logging.info(f"Quarantined {file_path} to {quarantine_path}")
        return True
    except Exception as e:
        logging.error(f"Error quarantining {file_path}: {e}")
        return False

def scan_directory(directory):
    """Scan all files in a directory for malware."""
    detected_threats = 0
    scanned_files = 0

    logging.info(f"Starting scan of directory: {directory}")
    print(f"Scanning directory: {directory}")

    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            scanned_files += 1

            # Step 1: Signature-based detection
            file_hash = calculate_md5(file_path)
            if file_hash:
                threat_name = check_signature_db(file_hash)
                if threat_name:
                    print(f"Threat detected (Signature): {file_path} ({threat_name})")
                    logging.warning(f"Threat detected (Signature): {file_path} ({threat_name})")
                    if quarantine_file(file_path):
                        print(f"File quarantined: {file_path}")
                    detected_threats += 1
                    continue

            # Step 2: Heuristic analysis (ML)
            if model:
                try:
                    features = calculate_features(file_path)
                    features = scaler.transform(features)
                    prediction = model.predict(features)[0][0]
                    if prediction > 0.8:  # Confidence threshold
                        print(f"Threat detected (Heuristic): {file_path} (Confidence: {prediction:.2f})")
                        logging.warning(f"Threat detected (Heuristic): {file_path} (Confidence: {prediction:.2f})")
                        if quarantine_file(file_path):
                            print(f"File quarantined: {file_path}")
                        detected_threats += 1
                        continue
                except Exception as e:
                    logging.error(f"ML prediction error for {file_path}: {e}")

            # Step 3: YARA rule-based detection
            if yara_rules:
                try:
                    matches = yara_rules.match(file_path)
                    if matches:
                        for match in matches:
                            print(f"Threat detected (YARA): {file_path} (Rule: {match.rule})")
                            logging.warning(f"Threat detected (YARA): {file_path} (Rule: {match.rule})")
                            if quarantine_file(file_path):
                                print(f"File quarantined: {file_path}")
                            detected_threats += 1
                            break
                except yara.Error as e:
                    logging.error(f"YARA scan error for {file_path}: {e}")

    print(f"Scan complete. Scanned {scanned_files} files, detected {detected_threats} threats.")
    logging.info(f"Scan complete. Scanned {scanned_files} files, detected {detected_threats} threats.")

def main():
    """Main function to run the antivirus scanner."""
    try:
        directory = input("Enter directory to scan (e.g., C:\\Test): ")
        if not os.path.isdir(directory):
            print("Invalid directory!")
            logging.error(f"Invalid directory: {directory}")
            return
        scan_directory(directory)
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        logging.info("Scan interrupted by user.")
    except Exception as e:
        print(f"An error occurred: {e}")
        logging.error(f"Main function error: {e}")

if __name__ == "__main__":
    main()
