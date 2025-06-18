import subprocess
import time
import os
import csv
import requests
from datetime import datetime
from threading import Thread
from queue import Queue
import logging

# Configuration
INTERFACE = "Wi-Fi"  # Update to your network interface
DURATION = 15  # Packet capture duration in seconds
ENDPOINT = "http://127.0.0.1:8000/predict/"
CFM_BAT = "cfm.bat"
OUTPUT_DIR = "captures"
CSV_DIR = "csv_output"

# Ensure directories exist
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(CSV_DIR, exist_ok=True)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_capture.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Queue for processing
pcap_queue = Queue()

def get_timestamp():
    """Generate timestamp for file naming"""
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def safe_remove_file(file_path, max_retries=5, delay=1):
    """Safely remove a file with error handling and retry logic"""
    for attempt in range(max_retries):
        try:
            if os.path.exists(file_path):
                # Try to release any file handles by waiting a bit
                time.sleep(delay * attempt)
                os.remove(file_path)
                logger.info(f"[✓] Removed file: {file_path}")
                return True
            return True  # File doesn't exist, consider it removed
        except PermissionError as e:
            if attempt < max_retries - 1:
                logger.warning(f"[!] File in use, retrying removal of {file_path} (attempt {attempt + 1}/{max_retries})")
                time.sleep(delay * (attempt + 1))
            else:
                logger.error(f"[X] Failed to remove {file_path} after {max_retries} attempts: {e}")
        except Exception as e:
            logger.error(f"[X] Failed to remove {file_path}: {e}")
            break
    return False

def capture_worker():
    """Continuously capture network traffic"""
    logger.info("[*] Starting capture worker thread")
    
    while True:
        timestamp = get_timestamp()
        pcap_file = os.path.join(OUTPUT_DIR, f"{timestamp}.pcap")
        logger.info(f"[*] Capturing traffic to {pcap_file} for {DURATION} seconds...")
        
        try:
            # Capture packets using tshark
            result = subprocess.run([
                "tshark", "-i", INTERFACE,
                "-a", f"duration:{DURATION}",
                "-w", pcap_file
            ], check=True, capture_output=True, text=True, encoding='utf-8', errors='ignore')
            
            # Check if file was created and has content
            if os.path.exists(pcap_file) and os.path.getsize(pcap_file) > 0:
                logger.info(f"[✓] Capture completed: {pcap_file}")
                pcap_queue.put(pcap_file)
            else:
                logger.warning(f"[!] Empty capture file: {pcap_file}")
                safe_remove_file(pcap_file)
                
        except subprocess.CalledProcessError as e:
            logger.error(f"[X] Capture failed: {e}")
            # Clean up failed capture file
            safe_remove_file(pcap_file)
        except Exception as e:
            logger.error(f"[X] Unexpected error during capture: {e}")
            safe_remove_file(pcap_file)

def is_pcapng(file_path):
    """Check if file is in pcapng format"""
    try:
        with open(file_path, 'rb') as f:
            return f.read(4) == b'\x0A\x0D\x0D\x0A'
    except Exception as e:
        logger.error(f"[X] Error checking file format: {e}")
        return False

def convert_and_send_worker():
    """Process captured files: convert to CSV and send data"""
    logger.info("[*] Starting conversion and sending worker thread")
    
    while True:
        try:
            pcap_file = pcap_queue.get()
            if not pcap_file:
                continue

            logger.info(f"[*] Processing file: {pcap_file}")
            original_pcap = pcap_file
            converted_pcap = None
            csv_file = None

            # Convert pcapng to pcap if needed
            if is_pcapng(pcap_file):
                converted_pcap = pcap_file.replace(".pcap", "_converted.pcap")
                try:
                    subprocess.run(['editcap', '-F', 'libpcap', pcap_file, converted_pcap], 
                                 check=True, capture_output=True, text=True, encoding='utf-8', errors='ignore')
                    logger.info(f"[✓] Converted to libpcap: {converted_pcap}")
                    pcap_file = converted_pcap
                    # Add small delay to ensure file handles are released
                    time.sleep(0.5)
                except subprocess.CalledProcessError as e:
                    logger.error(f"[X] editcap failed: {e}")
                    # Clean up files and continue
                    safe_remove_file(original_pcap)
                    if converted_pcap:
                        safe_remove_file(converted_pcap)
                    continue

            # Convert to CSV using cfm.bat
            try:
                logger.info(f"[*] Converting {pcap_file} to CSV using CICFlowMeter...")
                result = subprocess.run([CFM_BAT, pcap_file, CSV_DIR], 
                                      shell=True, check=True, capture_output=True, text=True, 
                                      encoding='utf-8', errors='ignore')
                logger.info("[✓] CSV conversion completed")
                # Add delay to ensure file handles are released
                time.sleep(1)
                
            except subprocess.CalledProcessError as e:
                logger.error(f"[X] Failed to convert with CICFlowMeter: {e}")
                # Clean up files and continue
                safe_remove_file(original_pcap)
                if converted_pcap:
                    safe_remove_file(converted_pcap)
                continue

            # Find generated CSV file
            base_name = os.path.splitext(os.path.basename(pcap_file))[0]
            csv_file = None
            
            # Look for CSV files that match the pattern
            for file in os.listdir(CSV_DIR):
                if file.startswith(base_name) and file.endswith("_Flow.csv"):
                    csv_file = os.path.join(CSV_DIR, file)
                    break
            
            # If not found, try alternative naming patterns
            if not csv_file:
                for file in os.listdir(CSV_DIR):
                    if base_name in file and file.endswith(".csv"):
                        csv_file = os.path.join(CSV_DIR, file)
                        break

            if not csv_file or not os.path.exists(csv_file):
                logger.warning(f"[!] CSV file not found for {pcap_file}")
                # Clean up PCAP files
                safe_remove_file(original_pcap)
                if converted_pcap:
                    safe_remove_file(converted_pcap)
                continue

            logger.info(f"[✓] Found CSV file: {csv_file}")

            # Send CSV rows as JSON POST requests
            try:
                # Add delay before opening CSV to ensure it's fully written
                time.sleep(0.5)
                
                with open(csv_file, 'r', newline='', encoding='utf-8', errors='ignore') as file:
                    reader = csv.DictReader(file)
                    row_count = 0
                    success_count = 0
                    
                    for row in reader:
                        row_count += 1
                        try:
                            # Clean the row data (remove empty strings, handle NaN values)
                            clean_row = {}
                            for key, value in row.items():
                                if key and value and str(value).strip() and str(value).lower() not in ['nan', 'inf', '-inf', 'null']:
                                    # Ensure all values are JSON serializable
                                    try:
                                        clean_row[str(key)] = str(value)
                                    except UnicodeEncodeError:
                                        clean_row[str(key)] = str(value).encode('utf-8', errors='ignore').decode('utf-8')
                                else:
                                    clean_row[str(key)] = None
                            
                            response = requests.post(ENDPOINT, json=clean_row, timeout=10)
                            
                            if response.status_code == 200:
                                success_count += 1
                                logger.debug(f"[✓] Row {row_count} sent successfully")
                            else:
                                logger.warning(f"[!] Row {row_count} failed with status: {response.status_code}")
                                
                        except requests.exceptions.RequestException as e:
                            logger.error(f"[X] Failed to send row {row_count}: {e}")
                        except Exception as e:
                            logger.error(f"[X] Unexpected error sending row {row_count}: {e}")
                    
                    logger.info(f"[✓] Sent {success_count}/{row_count} rows successfully")
                    
            except Exception as e:
                logger.error(f"[X] Error reading CSV file {csv_file}: {e}")

            # Clean up all files after processing
            logger.info("[*] Cleaning up processed files...")
            
            # Add delay before cleanup to ensure all processes have finished
            time.sleep(2)
            
            # Close any potential file handles by forcing garbage collection
            import gc
            gc.collect()
            
            safe_remove_file(original_pcap)
            if converted_pcap and converted_pcap != original_pcap:
                safe_remove_file(converted_pcap)
            if csv_file:
                safe_remove_file(csv_file)
            
            logger.info("[✓] File processing and cleanup completed")
            
        except Exception as e:
            logger.error(f"[X] Unexpected error in conversion worker: {e}")
            # Attempt cleanup on error
            try:
                if 'original_pcap' in locals():
                    safe_remove_file(original_pcap)
                if 'converted_pcap' in locals() and converted_pcap:
                    safe_remove_file(converted_pcap)
                if 'csv_file' in locals() and csv_file:
                    safe_remove_file(csv_file)
            except:
                pass

def cleanup_old_files():
    """Clean up any leftover files from previous runs"""
    logger.info("[*] Cleaning up old files...")
    
    # Clean output directory
    for file in os.listdir(OUTPUT_DIR):
        if file.endswith(('.pcap', '.pcapng')):
            file_path = os.path.join(OUTPUT_DIR, file)
            safe_remove_file(file_path)
    
    # Clean CSV directory
    for file in os.listdir(CSV_DIR):
        if file.endswith('.csv'):
            file_path = os.path.join(CSV_DIR, file)
            safe_remove_file(file_path)

def main():
    """Main function to start the network capture and processing system"""
    logger.info("="*50)
    logger.info("[*] Starting Network Traffic Capture System")
    logger.info(f"[*] Interface: {INTERFACE}")
    logger.info(f"[*] Capture Duration: {DURATION} seconds")
    logger.info(f"[*] Endpoint: {ENDPOINT}")
    logger.info("="*50)
    
    # Clean up any old files
    cleanup_old_files()
    
    try:
        # Start capture thread (daemon so it stops when main thread stops)
        capture_thread = Thread(target=capture_worker, daemon=True)
        capture_thread.start()
        logger.info("[✓] Capture thread started")

        # Start processor thread (daemon so it stops when main thread stops)
        processor_thread = Thread(target=convert_and_send_worker, daemon=True)
        processor_thread.start()
        logger.info("[✓] Processing thread started")

        logger.info("[*] System running... Press Ctrl+C to stop")
        
        # Keep main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("[*] Shutdown signal received")
        logger.info("[*] Cleaning up...")
        cleanup_old_files()
        logger.info("[*] System stopped")
    except Exception as e:
        logger.error(f"[X] Fatal error: {e}")
        cleanup_old_files()

if __name__ == "__main__":
    main()