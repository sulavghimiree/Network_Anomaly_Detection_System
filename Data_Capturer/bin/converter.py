import subprocess
import time
import os
import csv
import requests
import threading
import queue
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

# Configuration
INTERFACE = "Wi-Fi"  # Change this to your real network interface
DURATION = 30  # Capture duration in seconds
ENDPOINT = "http://localhost:8000/predict"
ENDPOINT_HOST = "localhost"  # Extract host for filtering
ENDPOINT_PORT = "8080"  # Extract port for filtering
CFM_BAT = "cfm.bat"
OUTPUT_DIR = "captures"
CSV_DIR = "csv_output"
MAX_WORKERS = 8  # Number of parallel workers for HTTP requests
BATCH_SIZE = 50  # Number of rows to process in one batch (for logging purposes)

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Ensure directories exist
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(CSV_DIR, exist_ok=True)

# Queues for coordination
pcap_queue = queue.Queue()
csv_queue = queue.Queue()

def get_timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def capture_pcap_continuous():
    """Continuously capture network traffic, filtering out endpoint traffic"""
    while True:
        timestamp = get_timestamp()
        pcap_file = os.path.join(OUTPUT_DIR, f"{timestamp}.pcap")
        
        logger.info(f"Starting capture to {pcap_file} for {DURATION} seconds...")
        
        # Build tshark command with filter to exclude endpoint traffic
        filter_expr = f"not (host {ENDPOINT_HOST} and port {ENDPOINT_PORT})"
        
        try:
            subprocess.run([
                "tshark", "-i", INTERFACE,
                "-a", f"duration:{DURATION}",
                "-f", filter_expr,  # Capture filter to exclude endpoint traffic
                "-w", pcap_file
            ], check=True)
            
            logger.info(f"Capture completed: {pcap_file}")
            pcap_queue.put(pcap_file)
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to capture traffic: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during capture: {e}")

def process_pcap_to_csv():
    """Process pcap files to CSV in parallel"""
    while True:
        try:
            pcap_file = pcap_queue.get(timeout=5)
            logger.info(f"Converting {pcap_file} to CSV...")
            
            try:
                subprocess.run([CFM_BAT, pcap_file, CSV_DIR], shell=True, check=True)
                
                # Find the generated CSV file
                csv_file = find_csv_file(pcap_file)
                if csv_file:
                    logger.info(f"CSV conversion completed: {csv_file}")
                    csv_queue.put(csv_file)
                else:
                    logger.warning(f"CSV file not found for {pcap_file}")
                
                # Remove PCAP file after conversion
                try:
                    os.remove(pcap_file)
                    logger.info(f"Removed processed PCAP file: {pcap_file}")
                except Exception as e:
                    logger.error(f"Failed to remove PCAP file {pcap_file}: {e}")
                    
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to convert {pcap_file}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error during conversion: {e}")
            finally:
                pcap_queue.task_done()
                
        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f"Error in pcap processing thread: {e}")

def find_csv_file(pcap_file_name):
    """Find the CSV file generated from pcap conversion"""
    base_name = os.path.basename(pcap_file_name)
    expected_csv = f"{base_name}_Flow.csv"
    full_path = os.path.join(CSV_DIR, expected_csv)
    if os.path.exists(full_path):
        return full_path
    return None

def send_row_to_endpoint(row):
    """Send a single row to the prediction endpoint"""
    try:
        # Ensure the row data is properly formatted as JSON
        headers = {'Content-Type': 'application/json'}
        response = requests.post(ENDPOINT, json=row, headers=headers, timeout=10)
        
        if response.status_code == 200:
            return f"Row sent successfully, status: {response.status_code}"
        else:
            return f"Row sent with status: {response.status_code}, response: {response.text[:100]}"
            
    except requests.exceptions.RequestException as e:
        return f"Network error sending row: {e}"
    except Exception as e:
        return f"Unexpected error sending row: {e}"



def debug_csv_content(csv_file, max_rows=3):
    """Debug function to show CSV content"""
    try:
        with open(csv_file, newline='', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            rows = list(reader)
            
        logger.info(f"CSV Debug - File: {csv_file}")
        logger.info(f"CSV Debug - Total rows: {len(rows)}")
        
        if rows:
            logger.info(f"CSV Debug - Headers: {list(rows[0].keys())}")
            for i, row in enumerate(rows[:max_rows]):
                logger.info(f"CSV Debug - Row {i+1}: {dict(row)}")
        else:
            logger.warning("CSV Debug - No rows found")
            
    except Exception as e:
        logger.error(f"CSV Debug error: {e}")

def send_csv_rows_parallel(csv_file):
    """Send CSV rows to endpoint in parallel batches"""
    logger.info(f"Processing rows from {csv_file}")
    
    # Debug CSV content first
    debug_csv_content(csv_file)
    
    try:
        with open(csv_file, newline='', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            rows = list(reader)
            
        if not rows:
            logger.warning(f"No rows found in {csv_file}")
            return
            
        logger.info(f"Sending {len(rows)} rows to {ENDPOINT}")
        
        sent_count = 0
        failed_count = 0
        
        # Process rows in parallel batches
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # Submit all rows at once for better parallelism
            futures = [executor.submit(send_row_to_endpoint, row) for row in rows]
            
            # Wait for all requests to complete
            for i, future in enumerate(as_completed(futures)):
                try:
                    result = future.result()
                    if "successfully" in result or "status: 200" in result:
                        sent_count += 1
                    else:
                        failed_count += 1
                        
                    # Log every 10th result or failures
                    if i % 10 == 0 or "successfully" not in result:
                        logger.info(f"Row {i+1}: {result}")
                        
                except Exception as e:
                    failed_count += 1
                    logger.error(f"Error processing row {i+1}: {e}")
                        
        logger.info(f"Completed processing {csv_file}: {sent_count} sent, {failed_count} failed")
        
        # Remove CSV file after processing
        try:
            os.remove(csv_file)
            logger.info(f"Removed processed CSV file: {csv_file}")
        except Exception as e:
            logger.error(f"Failed to remove CSV file {csv_file}: {e}")
        
    except Exception as e:
        logger.error(f"Error processing CSV file {csv_file}: {e}")

def process_csv_files():
    """Process CSV files and send to endpoint"""
    while True:
        try:
            csv_file = csv_queue.get(timeout=5)
            send_csv_rows_parallel(csv_file)
            csv_queue.task_done()
            
        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f"Error in CSV processing thread: {e}")

def cleanup_old_files():
    """Emergency cleanup in case file removal fails"""
    def cleanup_directory(directory, max_files=10):
        try:
            files = [os.path.join(directory, f) for f in os.listdir(directory) 
                    if os.path.isfile(os.path.join(directory, f))]
            files.sort(key=os.path.getmtime)
            
            if len(files) > max_files:
                files_to_delete = files[:-max_files]
                for file_path in files_to_delete:
                    os.remove(file_path)
                    logger.info(f"Emergency cleanup: removed {file_path}")
                    
        except Exception as e:
            logger.error(f"Error during emergency cleanup of {directory}: {e}")
    
    while True:
        time.sleep(600)  # Check every 10 minutes for emergency cleanup
        cleanup_directory(OUTPUT_DIR, max_files=5)  # Keep only 5 recent pcap files
        cleanup_directory(CSV_DIR, max_files=5)     # Keep only 5 recent csv files

def main():
    """Main function to coordinate all parallel processes"""
    logger.info("Starting optimized network traffic analyzer...")
    logger.info(f"Interface: {INTERFACE}")
    logger.info(f"Capture duration: {DURATION} seconds")
    logger.info(f"Endpoint: {ENDPOINT}")
    logger.info(f"Filtering out traffic to {ENDPOINT_HOST}:{ENDPOINT_PORT}")
    
    
    
    try:
        # Create and start threads
        threads = []
        
        # Capture thread (continuous)
        capture_thread = threading.Thread(target=capture_pcap_continuous, daemon=True)
        capture_thread.start()
        threads.append(capture_thread)
        
        # PCAP to CSV conversion threads
        for i in range(2):  # 2 conversion workers
            convert_thread = threading.Thread(target=process_pcap_to_csv, daemon=True)
            convert_thread.start()
            threads.append(convert_thread)
        
        # CSV processing threads - multiple workers for faster processing
        for i in range(2):  # 2 CSV processing workers
            csv_thread = threading.Thread(target=process_csv_files, daemon=True)
            csv_thread.start()
            threads.append(csv_thread)
        
        # Cleanup thread
        cleanup_thread = threading.Thread(target=cleanup_old_files, daemon=True)
        cleanup_thread.start()
        threads.append(cleanup_thread)
        
        logger.info("All threads started successfully")
        
        # Keep main thread alive
        while True:
            time.sleep(10)
            # Log queue status every 10 seconds
            logger.info(f"Queue status - PCAP: {pcap_queue.qsize()}, CSV: {csv_queue.qsize()}")
            
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
    finally:
        logger.info("Program terminated")

if __name__ == "__main__":
    main()