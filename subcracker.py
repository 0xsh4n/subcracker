import requests

def banner():
    with open("banner.txt", "r") as ban:
        banne = ban.read()
        print(banne)
        print("This program is made by mr-shan")

def is_subdomain_available(subdomain_url):
    try:
        r = requests.get(subdomain_url)
        r.raise_for_status()
        return True
    except requests.RequestException as e:
        return False

def fix_url(url):
    if url.startswith("http://"):
        return url[len("http://"):]
    elif url.startswith("https://"):
        return url[len("https://"):]
    return url

def test_subdomains(url, subdomains):
    tried_subdomains = []  
    found_subdomains = []  
    fixed_url = fix_url(url)  
    for idx, subdomain in enumerate(subdomains, start=1):
        url_with_subdomain = f"https://{subdomain}.{fixed_url}"
        tried_subdomains.append(url_with_subdomain)  
        if is_subdomain_available(url_with_subdomain):
            found_subdomains.append(subdomain)
            print(f"({idx}/{len(subdomains)}) Found: {subdomain}.{fixed_url}")
        else:
            print(f"({idx}/{len(subdomains)}) Wrong Subdomain: {subdomain}.{fixed_url}")

    return found_subdomains

def main():
    banner()

    url = input("Enter the URL (with scheme): ")

    subdomain_file = input("Enter your subdomain file name (press Enter for default 'subdomains.txt'): ").strip()
    if not subdomain_file:
        subdomain_file = "subdomains.txt"

    with open(subdomain_file, "r") as lists:
        subdomains = [line.strip() for line in lists.readlines() if line.strip()]

    if is_subdomain_available(url):
        found_subdomains = test_subdomains(url, subdomains)
        if not found_subdomains:
            print("No subdomains found")
        else:
            print("Found subdomains:")
            for subdomain in found_subdomains:
                print(subdomain)
    else:
        print("URL not found:", url)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProgram interrupted by user.")
