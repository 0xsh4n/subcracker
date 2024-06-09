#!/bin/python3

############################################################################
#          Copyright (c) 2023 GH05T-HUNTER5. All rights reserved.          #
# If you want a useful project like this contact us : mrhunter5@proton.me  #
#      You can also create similar projects in collaboration with us       #
#                          Invite : GH05T-HUNTER5                          #
#   This code is copyrighted and may not be copied or edited without the   #
#            express written permission of the copyright holder.           #
############################################################################

import requests
from validlink import check_url_validity

green = "\033[92m"
red = "\033[91m"
white = "\033[97m"
reset = "\033[0m"
cyan = "\033[36m"

def print_banner():
    banner = f"""
 {white}+------------------------------------------------------------------------------------+
 {white}|{green} ███████╗██╗   ██╗██████╗  ██████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗ ██████╗  {white}|
 {white}|{green} ██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝ ██╔══██╗ {white}|
 {white}|{green} ███████╗██║   ██║██████╔╝██║     ██████╔╝███████║██║     █████╔╝ █████╗   ██████╔╝ {white}|
 {white}|{green} ╚════██║██║   ██║██╔══██╗██║     ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝   ██╔══██╗ {white}|
 {white}|{green} ███████║╚██████╔╝██████╔╝╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗███████╗ ██║  ██║ {white}|
 {white}|{green} ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═╝  ╚═╝ {white}|
 {white}+------------------------------------{red}<{cyan}@mr-sh4n{red}>{white}--------------------------------------+{reset}"""
    print(banner)



def is_subdomain_available(subdomain_url):
    try:
        r = requests.get(subdomain_url)
        r.raise_for_status()
        return True, r.status_code
    except requests.RequestException as e:
        return False, None

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
        available, status_code = is_subdomain_available(url_with_subdomain)
        if available:
            found_subdomains.append(subdomain)
            print(f"{white} ({green}{idx}/{len(subdomains)}{white}) [{green}+{white}] {green}Subdomain found : {subdomain}.{fixed_url} {white}({green}Status Code : {status_code}{white})")
        else:
            print(f"{white} ({red}{idx}/{len(subdomains)}{white}) {white}[{red}+{white}] {red}Wrong Subdomain : {subdomain}.{fixed_url} {white}({red}Status Code : {status_code}{white})")

    return found_subdomains

def main():
    print_banner()

    url = input(f"{white} [{green}+{white}] {green}Enter the URL {white}({green}example : https://example.com{white}) : {green}")
    is_valid = check_url_validity(url)
    if is_valid:
        pass
    else:
        print(f"The URL {url} is not valid.")
        exit()

    subdomain_file = input(f"{white} [{green}+{white}] {green}Enter your subdomain file name {white}({green}press Enter for default 'subdomains.txt'{white}) :{green} ").strip()
    if not subdomain_file:
        subdomain_file = "subdomains.txt"

    with open(subdomain_file, "r") as lists:
        subdomains = [line.strip() for line in lists.readlines() if line.strip()]

    if is_subdomain_available(url):
        found_subdomains = test_subdomains(url, subdomains)
        if not found_subdomains:
            print(f"{white} [{red}+{white}] {red}No subdomains found")
        else:
            print(f"{white} [{green}+{white}] {green}Found subdomains : ")
            for subdomain in found_subdomains:
                print(subdomain)
    else:
        print(f"{white} [{red}+{white}] {red}URL not found : ", url)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{white} [{red}+{white}] {red}Program interrupted by user.")
