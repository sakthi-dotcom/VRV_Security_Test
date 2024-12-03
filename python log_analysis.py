import re
import csv
from collections import defaultdict

def parse_log_file(log_file):
    logs = []
    with open(log_file, 'r') as file:
        for line in file:
            logs.append(line.strip())
    return logs


def count_requests_per_ip(logs):
    ip_requests = defaultdict(int)
    for log in logs:
        # Extracting IP address
        ip = log.split()[0]
        ip_requests[ip] += 1
    return ip_requests


# Function to identify the most frequently accessed endpoint
def most_accessed_endpoint(logs):
    endpoint_count = defaultdict(int)
    for log in logs:
        # Extracting endpoint (URL path)
        match = re.search(r'"(?:GET|POST|PUT|DELETE) (\S+)', log)
        if match:
            endpoint = match.group(1)
            endpoint_count[endpoint] += 1
    most_accessed = max(endpoint_count, key=endpoint_count.get)
    return most_accessed, endpoint_count[most_accessed]


# Function to detect suspicious activity based on failed login attempts
def detect_suspicious_activity(logs, threshold=2):
    failed_logins = defaultdict(int)
    for log in logs:
        # Look for failed login attempts (status 401)
        if "POST /login" in log and '401' in log:
            ip = log.split()[0]
            failed_logins[ip] += 1

    # Flag IPs that exceed the failed login attempts threshold
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count >= threshold}
    return suspicious_ips


# Main function to run the log analysis
def main():
    log_file = 'sample.log'
    try:
        logs = parse_log_file(log_file)
    except FileNotFoundError:
        print(f"Log file '{log_file}' not found. Looking for log file at: {log_file}")
        return

    ip_requests = count_requests_per_ip(logs)
    most_accessed, most_accessed_count = most_accessed_endpoint(logs)
    failed_attempts_threshold = 2
    suspicious_ips = detect_suspicious_activity(logs, threshold=failed_attempts_threshold)

    # Output results to terminal
    print(f"{'IP Address':<20} {'Request Count'}")
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed} (Accessed {most_accessed_count} times)\n")

    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        print(f"{'IP Address':<20} {'Failed Login Attempts'}")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.\n")

    # Save results to CSV
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write IP address request counts
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])

        # Write most accessed endpoint
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed, most_accessed_count])

        # Write suspicious activity
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

    print("\nResults saved to log_analysis_results.csv.")


if __name__ == '__main__':
    main()