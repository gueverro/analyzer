import requests
import re
from urllib.parse import urlparse

# ANSI escape codes for colors
GREEN = "\033[92m"
CYAN = "\033[96m"
BLACK = "\033[30m"
RESET = "\033[0m"
RED = "\033[31m"
WHITE = "\033[37m"

# ASCII Banner
BANNER = f"""
{CYAN}                                                                               
  @@@@@@  @@@  @@@  @@@@@@  @@@      @@@ @@@ @@@@@@@@ @@@@@@@@ @@@@@@@ 
 @@!  @@@ @@!@!@@@ @@!  @@@ @@!      @@! !@@      @@! @@!      @@!  @@@
 @!@!@!@! @!@@!!@! @!@!@!@! @!!       !@!@!     @!!   @!!!:!   @!@!!@! 
 {GREEN}!!:  !!! !!:  !!! !!:  !!! !!:        !!:    !!:     !!:      !!: :!! 
  :   : : ::    :   :   : : : ::.: :   .:    :.::.: : : :: :::  :   : :
                            {GREEN}Coded by:{RED}ICC
{CYAN}
"""

# Patterns to avoid in code analysis
SUSPICIOUS_PATTERNS = [
    r'import\s+(os|subprocess|socket|requests)',  # Suspicious imports
    r'(?i)(requests\.get|requests\.post|socket\.connect)',  # Network activity
    r'(?i)(open\(.+?\.txt|open\(.+?\.json|open\(.+?\.csv)',  # File manipulation
    r'eval\(',  # Use of eval
    r'exec\(',  # Use of exec
    r'(?i)(base64\.b64decode|pickle\.load)',  # Potentially dangerous functions
    r'(?i)(input\(.+?\.send|input\(.+?\.post)',  # Sending user input to a server
    r'(?i)(document\.cookie|localStorage\.setItem)',  # Accessing cookies or local storage
    r'(?i)(fetch\(.+?\.then|axios\.post|axios\.get)',  # Fetching data from a server
    r'(?i)(window\.location|window\.open)',  # Redirecting users
]

# Common phishing indicators
PHISHING_INDICATORS = [
    r'www\.\w+\.com\.fake\.com',  # Unusual URL structure
    r'www\.\w+\.com',  # Generic domain names
    r'login',  # Presence of 'login' in the URL
    r'urgent',  # Presence of 'urgent' in the URL
    r'account',  # Presence of 'account' in the URL
]

def analyze_url(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            # Check if login is required
            if "login" in response.url:
                print("Caution: This URL requires login.\nPlease do a background check before logging in.")
            # Check for phishing indicators
            if check_for_phishing_indicators(url):
                print("Caution: This URL may be suspicious for phishing activities.")
            else:
                print("The URL appears to be safe.")
        else:
            print(f"Error: {response.status_code} for URL: {url}")
    except Exception as e:
        print(f"An error occurred: {e}")

def analyze_github_repo(repo_url):
    try:
        response = requests.get(repo_url)
        if response.status_code == 200:
            # Analyze the content of the repository
            print("Analyzing GitHub repository...")
            # Check for suspicious patterns in the code
            if check_for_suspicious_code(response.text):
                print("Caution: The repository contains suspicious code patterns.")
            else:
                print("The repository appears to be safe.")
        else:
            print(f"404 Client Error: Not Found for url: {repo_url}")
    except Exception as e:
        print(f"An error occurred: {e}")

def check_for_suspicious_code(code):
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, code):
            return True
    return False

def check_for_phishing_indicators(url):
    for pattern in PHISHING_INDICATORS:
        if re.search(pattern, url):
            return True
    return False

def main():
    print(BANNER)  # Display the ASCII banner
    choice = input("Do you want to analyze a URL or a GitHub repository?\n(Enter 'url' or 'repo'): ").strip().lower()
    
    if choice == 'url':
        print(f"Please enter the URL to analyze: ")
        url = input("   ╰─> ")
        analyze_url(url)
    
    elif choice == 'repo':
        print(f"Please enter the specific GitHub repository link\n(e.g., https://github.com/username/repo-name/blob/master/file_name): ")
        repo = input("   ╰─> ")
        analyze_github_repo(repo_url)
    
    else:
        print("   ──>Invalid choice. Please enter 'url' or 'repo'.")

if __name__ == "__main__":
    main()
