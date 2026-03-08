import subprocess
import re
from datetime import datetime


def extract_emails(output: str) -> list:
    email_pattern = r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
    emails = list(set(re.findall(email_pattern, output)))
    return sorted(emails)


def extract_usernames(emails: list, domain: str) -> list:
    usernames = []
    for email in emails:
        local_part = email.split('@')[0]
        usernames.append({
            "username": local_part,
            "source_email": email
        })
    return usernames


def extract_employee_names(output: str) -> list:
    employees = []

    linkedin_pattern = r'([A-Z][a-z]+ [A-Z][a-z]+(?:\s[A-Z][a-z]+)?)\s*[-\u2013|]\s*(.+?)(?:\n|$)'
    matches = re.findall(linkedin_pattern, output)
    for name, title in matches:
        employees.append({
            "name": name.strip(),
            "title": title.strip()
        })

    name_only_pattern = r'^\s*\*?\s*([A-Z][a-z]{2,}\s[A-Z][a-z]{2,})\s*$'
    for line in output.splitlines():
        match = re.match(name_only_pattern, line)
        if match:
            name = match.group(1).strip()
            if not any(e['name'] == name for e in employees):
                employees.append({"name": name, "title": "N/A"})

    return employees


def run_harvester(domain: str, sources: list = None, limit: int = 50000) -> dict:
    if sources is None:
        sources = [
            "google", "bing", "linkedin", "yahoo",
            "baidu", "duckduckgo", "twitter", "github",
            "hunter", "anubis", "certspotter", "crtsh"
        ]

    all_emails = []
    raw_output_combined = ""

    for source in sources:
        cmd = [
            "theHarvester",
            "-d", domain,
            "-b", source,
            "-l", str(limit)
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            output = result.stdout + result.stderr
            raw_output_combined += output

            source_emails = extract_emails(output)

            all_emails.extend(source_emails)

        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            pass

    all_emails = sorted(set(all_emails))

    usernames = extract_usernames(all_emails, domain)
    employees = extract_employee_names(raw_output_combined)

    return {
        "domain": domain,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "emails": all_emails,
        "usernames": usernames,
        "employees": employees,
        "total_emails": len(all_emails),
        "total_usernames": len(usernames),
        "total_employees": len(employees)
    }


def run_email_user_scan(target: str) -> dict:
    domain = target
    domain = re.sub(r'^https?://', '', domain)
    domain = re.sub(r'^www\.', '', domain)
    domain = domain.split('/')[0].strip()

    results = run_harvester(domain)

    return {
        "user_info": {
            "emails": results.get("emails", []),
            "usernames": [u["username"] for u in results.get("usernames", [])],
            "employees": results.get("employees", []),
            "total_emails": results.get("total_emails", 0),
            "total_usernames": results.get("total_usernames", 0),
            "total_employees": results.get("total_employees", 0),
            "scan_time": results.get("scan_time", ""),
            "domain": results.get("domain", domain)
        }
    }


def display_results(results: dict):
    print(f"\n EMAIL ADDRESSES ({results['total_emails']} found)")
    print("-" * 40)
    if results['emails']:
        for email in results['emails']:
            print(f"  {email}")
    else:
        print("  No emails found.")

    print(f"\n USERNAMES ({results['total_usernames']} found)")
    print("-" * 40)
    if results['usernames']:
        for u in results['usernames']:
            print(f"  {u['username']:25s}  (from: {u['source_email']})")
    else:
        print("  No usernames extracted.")

    print(f"\n EMPLOYEE DETAILS ({results['total_employees']} found)")
    print("-" * 40)
    if results['employees']:
        for emp in results['employees']:
            print(f"  {emp['name']:30s} | {emp['title']}")
    else:
        print("  No employee names found.")


def get_scan_config() -> tuple:
    selected_sources = [
        "google", "bing", "linkedin", "yahoo",
        "baidu", "duckduckgo", "twitter", "github",
        "hunter", "anubis", "certspotter", "crtsh"
    ]

    return selected_sources, 50000


def main():
    while True:
        url_input = input(" Enter target URL or domain (or 'quit' to exit): ").strip()

        if url_input.lower() in ("quit", "exit", "q"):
            print("\n Exiting. Goodbye!")
            break

        if not url_input:
            print("  No input provided. Please enter a domain.")
            continue

        domain = url_input
        domain = re.sub(r'^https?://', '', domain)
        domain = re.sub(r'^www\.', '', domain)
        domain = domain.split('/')[0].strip()

        if not domain or '.' not in domain:
            print(f"  '{url_input}' doesn't look like a valid domain. Try: example.com")
            continue

        sources, limit = get_scan_config()

        results = run_harvester(domain, sources=sources, limit=limit)

        display_results(results)

        break


if __name__ == "__main__":
    main()