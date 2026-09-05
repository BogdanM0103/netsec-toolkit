import re
import argparse
import json

parser = argparse.ArgumentParser(description="Parse auth.log for failed and successful login attempts.")
parser.add_argument("logfile", help="Path to the auth.log file")
parser.add_argument("--json", metavar="FILE", help="Write results to a JSON file")
parser.add_argument("-t", "--threshold", type=int, default=5, help="Threshold for failed attempts (default: 5)")
args = parser.parse_args()

pattern = r"Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+)"
accepted_pattern = r"Accepted \S+ for (\S+) from (\d+\.\d+\.\d+\.\d+)"
accepted_ips = set()
failed_counts = {}
THRESHOLD = args.threshold
def main():
    try:
        with open(args.logfile) as f:
            for line in f:
                match = re.search(pattern, line)
                amatch = re.search(accepted_pattern, line)
                if match:
                    ip = match.group(2)
                    if ip in failed_counts:
                        failed_counts[ip] += 1
                    else:
                        failed_counts[ip] = 1
                if amatch:
                    accepted_ips.add(amatch.group(2))
    except FileNotFoundError:
        print(f"Error: File {args.logfile} not found.")
        exit(1)

    results = {
        "failed_attempts": failed_counts,
        "brute_force": [ip for ip, c in failed_counts.items() if c > THRESHOLD],
        "suspicious": [ip for ip in failed_counts if ip in accepted_ips]
    }

    try:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2)
    except TypeError:
        print("Error: JSON file path not provided. Use --json to specify the output file.")
        exit(1)

if __name__ == "__main__":
    main()