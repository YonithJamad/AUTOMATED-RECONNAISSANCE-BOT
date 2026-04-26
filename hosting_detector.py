# Sweety Tool Theharvester

import socket
import requests
import dns.resolver
from urllib.parse import urlparse


class SimpleHostingDetector:
    def __init__(self, domain):
        self.domain = self.extract_domain(domain)
        self.provider = "Unknown"
        
        # Cloud provider
        self.cloud_indicators = {
            'Amazon Web Services (AWS)': {
                'domains': ['amazonaws.com', 'awsdns', 'cloudfront.net', 'elb.amazonaws.com', 'ec2'],
                'headers': ['X-Amz-Cf-Id', 'X-Amz-Request-Id'],
                'server': ['AmazonS3', 'CloudFront'],
                'asn': [16509, 14618, 8987],
                'org_keywords': ['amazon', 'aws']
            },
            'Google Cloud Platform (GCP)': {
                'domains': ['googleusercontent.com', 'googleapis.com', 'appspot.com', 'google'],
                'headers': ['X-Goog-', 'X-Cloud-Trace-Context'],
                'server': ['Google Frontend', 'gws', 'GFE'],
                'asn': [15169, 36040, 139190],
                'org_keywords': ['google', 'gcp']
            },
            'Microsoft Azure': {
                'domains': ['azurewebsites.net', 'azure.com', 'cloudapp.net', 'windows.net'],
                'headers': ['X-Azure-', 'X-MS-'],
                'server': ['Microsoft-IIS', 'Azure'],
                'asn': [8075, 8068, 12076],
                'org_keywords': ['microsoft', 'azure']
            },
            'Cloudflare Inc.': {
                'domains': ['cloudflare.com'],
                'headers': ['CF-RAY', 'cf-cache-status'],
                'server': ['cloudflare'],
                'asn': [13335],
                'org_keywords': ['cloudflare']
            },
            'DigitalOcean LLC': {
                'domains': ['digitalocean.com'],
                'headers': [],
                'server': [],
                'asn': [14061],
                'org_keywords': ['digitalocean']
            },
            'Linode (Akamai Technologies)': {
                'domains': ['linode.com'],
                'headers': [],
                'server': [],
                'asn': [63949],
                'org_keywords': ['linode', 'akamai']
            },
            'Vultr Holdings LLC': {
                'domains': ['vultr.com'],
                'headers': [],
                'server': [],
                'asn': [20473],
                'org_keywords': ['vultr', 'choopa']
            },
            'OVH SAS (OVHcloud)': {
                'domains': ['ovh.net', 'ovh.com'],
                'headers': [],
                'server': [],
                'asn': [16276],
                'org_keywords': ['ovh']
            },
            'Hetzner Online GmbH': {
                'domains': ['hetzner.com'],
                'headers': [],
                'server': [],
                'asn': [24940],
                'org_keywords': ['hetzner']
            },
            'Alibaba Cloud Computing': {
                'domains': ['aliyuncs.com', 'alibabacloud.com'],
                'headers': ['Ali-Swift-Global-Savetime'],
                'server': [],
                'asn': [45102, 37963],
                'org_keywords': ['alibaba', 'aliyun']
            },
            'Oracle Cloud Infrastructure (OCI)': {
                'domains': ['oraclecloud.com'],
                'headers': [],
                'server': [],
                'asn': [31898],
                'org_keywords': ['oracle']
            },
            'IBM Cloud': {
                'domains': ['ibm.com', 'bluemix.net'],
                'headers': [],
                'server': [],
                'asn': [36351],
                'org_keywords': ['ibm', 'softlayer']
            },
            'Rackspace Technology': {
                'domains': ['rackspace.com'],
                'headers': [],
                'server': [],
                'asn': [27357],
                'org_keywords': ['rackspace']
            },
            'Tencent Cloud': {
                'domains': ['tencentcloudapi.com', 'myqcloud.com'],
                'headers': [],
                'server': [],
                'asn': [45090, 132203],
                'org_keywords': ['tencent']
            }
        }
    
    def extract_domain(self, url):
        """Extract clean domain from URL."""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        return domain.replace('www.', '').split(':')[0]
    
    def check_nameservers(self):
        """Check nameservers for provider."""
        try:
            answers = dns.resolver.resolve(self.domain, 'NS')
            ns_string = ' '.join([str(rdata).lower() for rdata in answers])
            
            for provider, indicators in self.cloud_indicators.items():
                for keyword in indicators['domains']:
                    if keyword in ns_string:
                        return provider
        except Exception:
            pass
        return None
    
    def check_cname(self):
        """Check CNAME records."""
        try:
            for prefix in ['', 'www']:
                check_domain = f"{prefix}.{self.domain}" if prefix else self.domain
                try:
                    answers = dns.resolver.resolve(check_domain, 'CNAME')
                    cname = str(answers[0]).lower()
                    
                    for provider, indicators in self.cloud_indicators.items():
                        for keyword in indicators['domains']:
                            if keyword in cname:
                                return provider
                except Exception:
                    pass
        except Exception:
            pass
        return None
    
    def check_reverse_dns(self):
        try:
            ip = socket.gethostbyname(self.domain)
            hostname = socket.gethostbyaddr(ip)[0].lower()
            
            for provider, indicators in self.cloud_indicators.items():
                for keyword in indicators['domains']:
                    if keyword in hostname:
                        return provider
        except Exception:
            pass
        return None
    
    def check_headers(self):
        try:
            for protocol in ['https', 'http']:
                try:
                    response = requests.get(f"{protocol}://{self.domain}", timeout=5, allow_redirects=True)
                    headers = response.headers
                    
                    for provider, indicators in self.cloud_indicators.items():
                        # Check headers
                        for header_keyword in indicators['headers']:
                            for header_name in headers.keys():
                                if header_keyword.lower() in header_name.lower():
                                    return provider
                        
                        # Check server
                        server = headers.get('Server', '').lower()
                        for server_keyword in indicators['server']:
                            if server_keyword.lower() in server:
                                return provider
                    break
                except Exception:
                    continue
        except Exception:
            pass
        return None
    
    def check_ip_info(self):
        try:
            ip = socket.gethostbyname(self.domain)
            response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,isp,org,as", timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    # Extract ASN
                    asn_info = data.get('as', '')
                    asn = None
                    if asn_info:
                        asn = int(asn_info.split()[0].replace('AS', ''))
                    
                    org_lower = data.get('org', '').lower()
                    isp_lower = data.get('isp', '').lower()
                    
                    for provider, indicators in self.cloud_indicators.items():
                        # Check ASN
                        if asn and asn in indicators['asn']:
                            return provider
                        
                        # Check keywords
                        for keyword in indicators['org_keywords']:
                            if keyword in org_lower or keyword in isp_lower:
                                return provider
        except Exception:
            pass
        return None
    
    def detect(self):
        methods = [
            self.check_cname,
            self.check_nameservers,
            self.check_reverse_dns,
            self.check_headers,
            self.check_ip_info
        ]
        
        for method in methods:
            try:
                result = method()
                if result:
                    self.provider = result
                    return self.provider
            except Exception:
                continue
        
        return self.provider



def get_theharvester_data(domain):
    try:
        detector = SimpleHostingDetector(domain)
        provider = detector.detect()
        return {"hosting_provider": provider if provider else "Unknown"}
    except Exception as e:
        return {"hosting_provider": "Error"}


def main():
    domain = input("Enter domain name: ").strip()
    
    if not domain:
        print("Error: Domain required")
        return
    
    detector = SimpleHostingDetector(domain)
    provider = detector.detect()
    
    print(provider)


if __name__ == "__main__":
    main()