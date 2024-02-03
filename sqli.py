import argparse
import pyfiglet
import requests
import re
import time

def display_banner():
    banner = pyfiglet.figlet_format("SQL-I")
    description = "CLI tool to test SQL injection vulnerability using time-based attack."
    functions = "-u, --url\t\tURL to test for SQL injection vulnerability\n" \
                "-f, --file\t\tFile containing list of URLs to test\n" \
                "-p, --payload-file\tFile containing the SQL injection payloads"
    print(banner)
    print(description)
    print("Functions and Flags:")
    print(functions)

def extract_sleep_time(payload):
    match = re.search(r'SLEEP\((\d+)\)', payload, re.IGNORECASE)
    if match:
        return int(match.group(1))
    return None

def test_sql_injection(url, vulnerable_param, payload):
    sleep_time = extract_sleep_time(payload)

    params = {
        vulnerable_param: payload
    }

    try:
        start_time = time.time()
        response = requests.get(url, params=params)
        end_time = time.time()

        response_time = end_time - start_time

        threshold = sleep_time * 1.5

        if response_time >= threshold:
            print(f"Potential SQL Injection vulnerability found at: {url} with payload: {payload}")
        else:
            print(f"No SQL Injection vulnerability detected at: {url} with payload: {payload}")
    except requests.RequestException as e:
        print(f"Error occurred while testing {url} with payload: {payload} - {e}")

def main():
    display_banner()
    parser = argparse.ArgumentParser(description="CLI tool to test SQL injection vulnerability using time-based attack.")
    parser.add_argument("-u", "--url", help="URL to test for SQL injection vulnerability")
    parser.add_argument("-f", "--file", help="File containing list of URLs to test")
    parser.add_argument("-p", "--payload-file", help="File containing the SQL injection payloads", required=True)

    args = parser.parse_args()

    if args.url:
        with open(args.payload_file, "r") as payload_file:
            payloads = payload_file.read().strip().split('\n')
            for payload in payloads:
                test_sql_injection(args.url, vulnerable_param="id", payload=payload)
    elif args.file:
        with open(args.payload_file, "r") as payload_file:
            payloads = payload_file.read().strip().split('\n')
            with open(args.file, "r") as file:
                for line in file:
                    url = line.strip()
                    print(f"\nTesting URL: {url}")
                    for payload in payloads:
                        test_sql_injection(url, vulnerable_param="id", payload=payload)

if __name__ == "__main__":
    main()
