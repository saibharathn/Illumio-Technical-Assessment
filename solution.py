import csv
from collections import defaultdict


def load_lookup_table(lookup_file):
    lookup_table = {}
    with open(lookup_file, 'r', encoding='ISO-8859-1') as csvfile:
        reader = csv.DictReader(csvfile)
        headers = [header.strip().lower() for header in reader.fieldnames]
        
        # Check if required columns are present after normalization
        if 'dstport' not in headers or 'protocol' not in headers or 'tag' not in headers:
            raise KeyError("Expected columns 'dstport', 'protocol', or 'tag' not found in CSV file")

        for row in reader:
            try:
                dstport = int(row['dstport'].strip()) 
                protocol = row['protocol'].strip().lower()
                tag = row['tag'].strip()
                lookup_table[(dstport, protocol)] = tag
            except ValueError as e:
                print(f"Skipping row due to error: {e}, row content: {row}")
    return lookup_table


def parse_flow_logs(flow_log_file, lookup_table):
    tag_counts = defaultdict(int)
    port_protocol_counts = defaultdict(int)
    untagged_count = 0

    with open(flow_log_file, 'r', encoding='ISO-8859-1') as file:
        for line in file:
            parts = line.strip().split()
            if len(parts) < 12:
                continue  # Skip invalid log entries

            dstport = int(parts[5])
            protocol = 'tcp' if parts[7] == '6' else 'udp' if parts[7] == '17' else 'icmp'
            
            tag = lookup_table.get((dstport, protocol), "Untagged")
            
            if tag == "Untagged":
                untagged_count += 1
            else:
                tag_counts[tag] += 1
            
            port_protocol_counts[(dstport, protocol)] += 1

    return tag_counts, port_protocol_counts, untagged_count

def write_tag_counts(tag_counts, untagged_count, output_file):
    with open(output_file, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(['Tag', 'Count'])
        for tag, count in tag_counts.items():
            writer.writerow([tag, count])
        writer.writerow(['Untagged', untagged_count])

def write_port_protocol_counts(port_protocol_counts, output_file):
    with open(output_file, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(['Port', 'Protocol', 'Count'])
        for (port, protocol), count in port_protocol_counts.items():
            writer.writerow([port, protocol, count])

def main():
    lookup_file = 'lookup_table.csv'
    flow_log_file = 'flow_logs.txt'
    output_tag_count_file = 'tag_counts.csv'
    output_port_protocol_file = 'port_protocol_counts.csv'

    # Load lookup table
    lookup_table = load_lookup_table(lookup_file)

    # Parse flow logs and get counts
    tag_counts, port_protocol_counts, untagged_count = parse_flow_logs(flow_log_file, lookup_table)

    # Write results to output files
    write_tag_counts(tag_counts, untagged_count, output_tag_count_file)
    write_port_protocol_counts(port_protocol_counts, output_port_protocol_file)

    print("Output files generated successfully.")

if __name__ == "__main__":
    main()
