import re
import csv

# Regex patterns
ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
url_pattern = r'https?://[^\s]+'
domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'


# ----------- PARSER FUNCTIONS -----------

def parse_txt(file):
    with open(file, 'r') as f:
        data = f.read()

    ips = re.findall(ip_pattern, data)
    urls = re.findall(url_pattern, data)
    domains = re.findall(domain_pattern, data)

    return ips, urls, domains


def parse_csv(file):
    ips, urls, domains = [], [], []

    with open(file, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            row_data = " ".join(row)

            ips += re.findall(ip_pattern, row_data)
            urls += re.findall(url_pattern, row_data)
            domains += re.findall(domain_pattern, row_data)

    return ips, urls, domains


# ----------- NORMALIZATION FUNCTION -----------

def normalize_data(ips, urls, domains, source):
    normalized = []

    for ip in ips:
        normalized.append({
            "type": "IP",
            "value": ip,
            "source": source
        })

    for url in urls:
        normalized.append({
            "type": "URL",
            "value": url,
            "source": source
        })

    for domain in domains:
        normalized.append({
            "type": "DOMAIN",
            "value": domain,
            "source": source
        })

    return normalized


# ----------- CORRELATION FUNCTION -----------

def correlate_iocs(data):
    ioc_count = {}

    # Count occurrences
    for item in data:
        key = item['value']
        if key in ioc_count:
            ioc_count[key] += 1
        else:
            ioc_count[key] = 1

    correlated_data = []

    for item in data:
        count = ioc_count[item['value']]

        if count > 1:
            risk = "HIGH"
        else:
            risk = "LOW"

        new_item = item.copy()
        new_item['count'] = count
        new_item['risk'] = risk

        correlated_data.append(new_item)

    return correlated_data


# ----------- BLOCKLIST GENERATOR -----------

def generate_blocklists(data):
    ip_blocklist = set()
    domain_blocklist = set()
    url_blocklist = set()

    for item in data:
        if item['risk'] == 'HIGH':
            if item['type'] == 'IP':
                ip_blocklist.add(item['value'])
            elif item['type'] == 'DOMAIN':
                domain_blocklist.add(item['value'])
            elif item['type'] == 'URL':
                url_blocklist.add(item['value'])

    return ip_blocklist, domain_blocklist, url_blocklist


def save_blocklist(filename, data):
    with open(filename, 'w') as f:
        for item in data:
            f.write(item + '\n')


# ----------- MAIN -----------

# Parse files
txt_ips, txt_urls, txt_domains = parse_txt("feeds/sample1.txt")
csv_ips, csv_urls, csv_domains = parse_csv("feeds/sample2.csv")

# Normalize data
txt_data = normalize_data(txt_ips, txt_urls, txt_domains, "sample1.txt")
csv_data = normalize_data(csv_ips, csv_urls, csv_domains, "sample2.csv")

# Combine all
all_data = txt_data + csv_data


# ----------- OUTPUT -----------

print("\n🔹 NORMALIZED IOC DATA:\n")
for item in all_data:
    print(item)

print("\n🔹 CORRELATED IOC DATA:\n")

correlated = correlate_iocs(all_data)

for item in correlated:
    print(item)


# ----------- BLOCKLIST OUTPUT -----------

print("\n🔹 GENERATING BLOCKLISTS...\n")

ip_bl, domain_bl, url_bl = generate_blocklists(correlated)

save_blocklist("ip_blocklist.txt", ip_bl)
save_blocklist("domain_blocklist.txt", domain_bl)
save_blocklist("url_blocklist.txt", url_bl)

print("✅ Blocklists Generated Successfully")