import yara
import os
import shutil
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(filename='yara_scan_log.txt', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Quarantine directory
QUARANTINE_DIR = 'quarantine'
if not os.path.exists(QUARANTINE_DIR):
    os.makedirs(QUARANTINE_DIR)

def compile_yara_rules(rule_path: str) -> yara.Rules:
    """Compile YARA rules from a file."""
    try:
        rules = yara.compile(filepath=rule_path)
        logging.info(f"YARA rules compiled from {rule_path}")
        return rules
    except yara.Error as e:
        logging.error(f"Error compiling YARA rules: {e}")
        raise

def quarantine_file(file_path: str) -> bool:
    """Move a suspicious file to quarantine."""
    try:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        quarantine_path = os.path.join(QUARANTINE_DIR, f"{timestamp}_{os.path.basename(file_path)}")
        shutil.move(file_path, quarantine_path)
        logging.info(f"Quarantined {file_path} to {quarantine_path}")
        return True
    except Exception as e:
        logging.error(f"Error quarantining {file_path}: {e}")
        return False

def scan_with_yara(directory: str, rules: yara.Rules) -> None:
    """Scan a directory using YARA rules."""
    detected_threats = 0
    scanned_files = 0

    logging.info(f"Starting YARA scan of directory: {directory}")
    print(f"Scanning directory with YARA: {directory}")

    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            scanned_files += 1

            try:
                matches = rules.match(file_path)
                if matches:
                    for match in matches:
                        print(f"Threat detected: {file_path} (Rule: {match.rule})")
                        logging.warning(f"Threat detected: {file_path} (Rule: {match.rule})")
                        if quarantine_file(file_path):
                            print(f"File quarantined: {file_path}")
                        else:
                            print(f"Failed to quarantine: {file_path}")
                        detected_threats += 1
                else:
                    logging.info(f"Clean: {file_path}")
            except yara.Error as e:
                logging.error(f"Error scanning {file_path}: {e}")

    print(f"YARA scan complete. Scanned {scanned_files} files, detected {detected_threats} threats.")
    logging.info(f"YARA scan complete. Scanned {scanned_files} files, detected {detected_threats} threats.")

def main():
    """Main function to run YARA-based scanning."""
    rule_path = "rules.yar"  # Path to YARA rules file
    directory = input("Enter directory to scan (e.g., C:\\Test): ")

    try:
        if not os.path.isdir(directory):
            print("Invalid directory!")
            logging.error(f"Invalid directory: {directory}")
            return

        rules = compile_yara_rules(rule_path)
        scan_with_yara(directory, rules)
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        logging.info("Scan interrupted by user.")
    except Exception as e:
        print(f"An error occurred: {e}")
        logging.error(f"Main function error: {e}")

if __name__ == "__main__":
    main()
