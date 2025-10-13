# pylint: disable=too-many-lines
"""Contains everything for rescan helper... I should refactor at some point"""

import re
import tkinter as tk
from tkinter import scrolledtext, messagebox
import webbrowser as wb
from csv import DictReader
from json import load, dump
from os import path, makedirs, getenv
import base64
import traceback
from typing import TypedDict, NotRequired

# third party imports
import requests
import customtkinter as ctk
from pyperclip import copy

# Checks if the folder config exists in current directory
# On first run, will create config folder and template config.json
rescan_helper_path = getenv("APPDATA", "NULL") + "/RescanHelper"
if not path.exists(rescan_helper_path + "/config/config.json"):
    if not path.exists(rescan_helper_path + "/config"):
        makedirs(rescan_helper_path + "/config")
    if not path.exists(rescan_helper_path):
        makedirs(rescan_helper_path)

    json_data = {
        "API_KEY": "BASIC VXNlcm5hbWU6UGFzc3dvcmQ=",
        "QUALYS_PLATFORM": "YOUR_QUALYS_PLATFORM_HERE",
        "LOGIN_URL": "https://YOUR_LOGIN_URL_HERE",
        "SNOW_URL": "YOUR_SNOW_URL_HERE",
        "SNOW_API_USER": "YOUR_SNOW_API_USER_HERE",
        "SNOW_API_PASSWORD": "YOUR_SNOW_API_PASSWORD_HERE",
        "SCANNER_APPLIANCE": "scanner1,scanner2,...",
        "SCAN_LIST": {
            "CHANGE NAME IN SETTINGS": {
                "SEARCH_LIST_ID": "ENTER SEARCH LIST",
                "OP_ID": "ENTER OPTION PROFILE",
            }
        },
    }

    with open(rescan_helper_path + "/config/config.json", "w", encoding="UTF-8") as f:
        dump(json_data, f, indent=4)


def get_config():
    """Loads the config file and updates the variables"""
    with open(
        rescan_helper_path + "/config/config.json", encoding="UTF-8"
    ) as config_file:
        config = load(config_file)
        return config


# pylint: disable=too-few-public-methods
class VitObject:
    """
    This class is to allow for auto-completions in the IDE and it helps enforce types
    A VitObject can be thought of as an entry from SNOW, but we exclude all the info we don't need
    """

    def __init__(self, vit_id, qid, ip, ci):
        self.vit_id = str(vit_id)
        self.qid = str(qid)
        self.ip = str(ip)
        self.ci = str(ci)


# Global variables
CONFIG = get_config()
VIT_LIST: list[VitObject] = []
CLOSE_VIT_POPUPS = []
SETTINGS_POPUPS = []
SCAN_SETTINGS_POPUPS = []
CA_POPUPS = []
API_KEY: str = CONFIG["API_KEY"]
QUALYS_PLATFORM: str = CONFIG["QUALYS_PLATFORM"]
LOGIN_URL: str = CONFIG["LOGIN_URL"]
SCANNER_APPLIANCE: str = CONFIG["SCANNER_APPLIANCE"]
SNOW_URL: str = CONFIG["SNOW_URL"]
SNOW_API_USER: str = CONFIG["SNOW_API_USER"]
SNOW_API_PASSWORD: str = CONFIG["SNOW_API_PASSWORD"]
SCAN_LIST = CONFIG["SCAN_LIST"]


def get_qids() -> list[str]:
    """Grabs the qids from the qid listbox object"""
    qid_numbers: list[str] = []
    for qid in qids_listbox.get(0, "end"):
        qid_numbers.append(qid[4:])
    return qid_numbers


def update_search_list(input_id: str) -> int:
    """If the scan type involves updating a search list this api function is called to update it"""
    print("Updating search list...")
    url = f"https://qualysapi.{QUALYS_PLATFORM}/api/2.0/fo/qid/search_list/static/"

    payload = {"action": "update", "id": input_id, "qids": ",".join(get_qids())}

    headers = {"X-Requested-With": "RescanHelperAPI", "Authorization": API_KEY}

    response = requests.post(url, headers=headers, data=payload, timeout=60)

    if "search list updated successfully" in response.text:
        print("Search list updated!")
    else:
        print(response.text)
        print("Error, search list not update!!")
        return -1

    return 0


def launch_scan_helper(title, option, appliances, ips) -> int:
    """Easy api requesting for launching a scan in Qualys"""
    print("Launching scan...")

    if len(ips) == 0:
        return -1
    url = f"https://qualysapi.{QUALYS_PLATFORM}/api/3.0/fo/scan/"

    payload = {
        "action": "launch",
        "scan_title": title,
        "option_id": option,
        "iscanner_name": appliances,
        "priority": "0",
        "ip": ",".join(ips),
    }

    headers = {"X-Requested-With": "RescanHelperAPI", "Authorization": API_KEY}

    response = requests.post(url, headers=headers, data=payload, timeout=60)

    if "New vm scan launched" in response.text:
        return 0

    print(response.text)
    print("Error while launching, scan canceled.")
    return -1


def launch_scan():
    """function called whenever the 'launch scan' button is pressed"""
    ips_arr = ips_listbox.get(0, "end")

    if len(ips_arr) == 0:
        print("No IPs detected, scan canceled")
        return -1

    if len(title_entry.get()) == 0:
        print("Error empty title, scan canceled")
        return -2

    scan = SCAN_LIST[scan_type_var.get()]
    # Check the scan type the user selected then launch that scan
    if scan["SEARCH_LIST_ID"] != "NULL":

        # Checks if all required fields are filled out
        if len(qids_listbox.get(0, "end")) == 0:
            print("No QIDs detected, scan canceled")
            return -3
        if update_search_list(scan["SEARCH_LIST_ID"]) == -1:
            print("Scan canceled.")
            return -4

    # Launch scan with selected scanner appliance group
    if (
        launch_scan_helper(title_entry.get(), scan["OP_ID"], SCANNER_APPLIANCE, ips_arr)
        == -1
    ):
        return -5

    wb.open(f"https://qualysguard.{QUALYS_PLATFORM}/fo/scan/scanList.php")
    print("Scan launched!")
    return 0


class SnowCellObject(TypedDict):
    """Helpful class for auto completing of json"""

    display_value: str
    link: NotRequired[str]
    value: str


class SnowVitEntry(TypedDict):
    """Helpful class for auto completing of json"""

    cmdb_ci: SnowCellObject
    vulnerable_item: SnowCellObject
    ip_address: SnowCellObject
    vulnerability: SnowCellObject


def snow_grab_vit_api(vits: set[str]):
    """Api request to SNOW to grab vit info"""
    url = (
        f"https://{SNOW_URL}/api/now/table/sn_vul_detection?"
        + "sysparm_query=status=0^vulnerable_item.numberIN"
        + ",".join(vits)
        + "&sysparm_display_value=all&sysparm_fields=ip_address"
        + ",vulnerability,cmdb_ci,vulnerable_item"
    )

    # Set proper headers
    headers = {"Content-Type": "application/json", "Accept": "application/json"}

    # Do the HTTP request
    response = requests.get(
        url, auth=(SNOW_API_USER, SNOW_API_PASSWORD), headers=headers, timeout=20
    )

    # Check for HTTP codes other than 200
    if response.status_code != 200:
        print(
            "Status:",
            response.status_code,
            "Headers:",
            response.headers,
            "Error Response:",
            response.json(),
        )
        raise LookupError("SNOW API REQUEST FAILED")

    # Decode the JSON response into a dictionary and use the data
    return response.json()

def snow_grab_vul_api(vuls: set[str]):
    """Api request to SNOW to grab vits from vuls"""
    url = (
        f"https://{SNOW_URL}/api/now/table/sn_vul_m2m_vul_group_item?"
        + "sysparm_query=sn_vul_vulnerable_item.active=true^sn_vul_vulnerability.numberIN"
        + ",".join(vuls)
        + "&sysparm_display_value=true&sysparm_exclude_reference_link=true"
        + "&sysparm_fields=sn_vul_vulnerable_item"
    )

    # Set proper headers
    headers = {"Content-Type": "application/json", "Accept": "application/json"}

    # Do the HTTP request
    response = requests.get(
        url, auth=(SNOW_API_USER, SNOW_API_PASSWORD), headers=headers, timeout=20
    )

    # Check for HTTP codes other than 200
    if response.status_code != 200:
        print(
            "Status:",
            response.status_code,
            "Headers:",
            response.headers,
            "Error Response:",
            response.json(),
        )
        raise LookupError("SNOW API REQUEST FAILED")

    # Decode the JSON response into a dictionary and use the data
    return response.json()

def look_up_vits():
    """Grabs the vits from the vit listbox object"""
    # pylint: disable=global-variable-not-assigned
    global VIT_LIST
    text = text_area.get("1.0", "end").strip()

    vuls: set[str] = set(re.findall(r"[Vv][Uu][Ll]\d{7,8}", text))
    vits: set[str] = set(re.findall(r"[Vv][Ii][Tt]\d{7,8}", text))

    if len(vuls) > 0:
        api_response = snow_grab_vul_api(vuls)
        for vit in api_response['result']:
            vits.add(vit['sn_vul_vulnerable_item'])

    qids: set[str] = set()
    ips: set[str] = set()
    cis: set[str] = set()
    VIT_LIST.clear()

    try:
        api_request_response = snow_grab_vit_api(vits)
        # if result has vits
        vits.clear()
        if api_request_response and len(api_request_response["result"]) > 0:
            for entry in api_request_response["result"]:
                entry: SnowVitEntry = entry
                vit = entry["vulnerable_item"]["display_value"]
                qid = entry["vulnerability"]["display_value"]
                ip = entry["ip_address"]["display_value"]
                ci = entry["cmdb_ci"]["display_value"]

                VIT_LIST.append(VitObject(vit, qid, ip, ci))
                vits.add(vit)
                qids.add(qid)
                ips.add(ip)
                cis.add(ci)
        else:
            print("No vits returned")

    except LookupError:
        print("ERROR - Traceback Info:")
        traceback.print_exc()

    # Opens CA Compatible QIDs
    # pylint: disable=line-too-long
    wb.open(
        f"https://{SNOW_URL}/sn_vul_third_party_entry_list.do?sysparm_query=sourceSTARTSWITHQ%5Esearch_listsLIKEc97b18c21b9a4d5032ceedb1bc4bcb9f%5EORsearch_listsLIKE219bd8061b9a4d5032ceedb1bc4bcbfc%5EidIN"
        + "%2C".join(qids)
        + "&sysparm_first_row=1&sysparm_view="
    )
    # Opens Cloud Agent manager in Qualys
    wb.open(
        f"https://qualysguard.{QUALYS_PLATFORM}/portal-front/module/ca/#tab=ca-agents.datalist-agents"
    )
    # Copies IPs to clipboard in ip1 OR ip2 OR ip3 OR ... format
    check_ips = " OR ".join(cis)
    copy(check_ips)

    # Clears lists and adds the new variables
    vits_listbox.delete(0, "end")
    for vit in vits:
        vits_listbox.insert("end", vit)
    vits_label.configure(text=f"{len(vits)} - VIT(s)")

    qids_listbox.delete(0, "end")
    for qid in qids:
        qids_listbox.insert("end", qid)
    qids_label.configure(text=f"{len(qids)} - QID(s)")

    ips_listbox.delete(0, "end")
    for ip in ips:
        ips_listbox.insert("end", ip)
    ips_label.configure(text=f"{len(ips)} - IP(s)")


def add_entry(listbox, entry):
    """Takes in a listbox and an entry value to add to the listbox"""
    value = entry.get()
    if value:
        listbox.insert("end", value)
        entry.delete(0, "end")


def remove_entry(listbox: tk.Listbox):
    """Takes in whatever the user has selected from a listbox
    object and deletes the selected rows"""
    selected_items = listbox.curselection()
    for item in selected_items[::-1]:
        listbox.delete(item)


def open_vmdr():
    """Bookmark to quickly open VMDR to check results of a scan"""
    qids_search = (
        "vulnerabilities.vulnerability.qid%3A"
        + "%20OR%20vulnerabilities.vulnerability.qid:".join(get_qids())
    )
    ips_search = "%20OR%20".join(ips_listbox.get(0, "end"))
    # pylint: disable=line-too-long
    wb.open(
        f"https://qualysguard.{QUALYS_PLATFORM}/vm/#/vulnerabilities?searchPivotToken=VULNERABILITY&source=&groupByPivot=VULNERABILITY&pageSize=50&pageNumber=0&criteria=&defaultQuery=Information%20%2CDisabled%20%2CIgnored&search="
        + qids_search
        + "&havingQuery="
        + ips_search
    )


def open_vits_fixed():
    """
    Opens the vits fixed popup
    Based on a query from the VMDR utilizing the current IPs and QIDs list
    It checks if the values are now marked as fixed
    (checks from last 3 days so old records aren't kept)
    [Probably should update to check if status = active and is a newer entry]
    """
    # Allows for only 1 popup at a time
    # pylint: disable=global-variable-not-assigned
    global CLOSE_VIT_POPUPS

    def close_popup():
        """Closes the vits fixed popup to ensure screen doesn't get overload with windows"""
        # pylint: disable=global-variable-not-assigned
        global CLOSE_VIT_POPUPS
        CLOSE_VIT_POPUPS[0].destroy()
        CLOSE_VIT_POPUPS.clear()

    if len(CLOSE_VIT_POPUPS) == 1:
        close_popup()

    # Ensures pop up isn't hidden behind program
    popup = ctk.CTkToplevel()
    popup.protocol("WM_DELETE_WINDOW", close_popup)
    popup.title("VITs that can close")
    # pylint: disable=unnecessary-lambda
    popup.after(250, lambda: popup.lift())
    popup.attributes("-topmost", True)
    popup.after_idle(popup.attributes, "-topmost", False)

    # Creates a GUI showcasing the VITs fixed
    listbox = tk.Listbox(
        popup, width=30, height=20, background=GREY, foreground="white"
    )
    listbox.pack(padx=10, pady=5)

    vits_fixed = retrieve_asset_detection(
        ",".join(ips_listbox.get(0, "end")), ",".join(get_qids()), "Fixed"
    )
    if len(vits_fixed) > 0:
        copy("VIT(s) closed, vulnerabilities have been fixed according to rescan.")
    for vit in vits_fixed:
        listbox.insert("end", vit)

    label = ctk.CTkLabel(
        popup, text=f"{len(vits_fixed)} VIT(s) are labeled\nas FIXED in VMDR"
    )
    label.pack(pady=5)

    CLOSE_VIT_POPUPS.append(popup)
    # Opens SNOW VIT Table allowing for easy closing of VITs
    wb.open(
        f"https://{SNOW_URL}/sn_vul_vulnerable_item_list.do?sysparm_query=active%3Dtrue%5EnumberIN"
        + "%2C".join(vits_fixed)
        + "&sysparm_first_row=1&sysparm_view="
    )


def get_vit_id(ip: str, qid: str) -> str:
    """Gets VITs by checking the ip and qid of each VIT, as these should be unique per VIT"""
    for vit in VIT_LIST:
        if vit.ip == ip and vit.qid == qid:
            return vit.vit_id
    return "-1"


def retrieve_asset_detection(ips: str, qids: str, status: str) -> list[str]:
    """Queries the VMDR and returns a list of vit ids that match the specified status"""
    url = f"https://qualysapi.{QUALYS_PLATFORM}/api/4.0/fo/asset/host/vm/detection/"
    if not ips or not qids or not status:
        print("Error missing parameter(s)!")
        return []

    payload = {
        "action": "list",
        "ips": ips,
        "qids": qids,
        "status": status,
        "max_days_since_last_vm_scan": 3,
        "output_format": "CSV_NO_METADATA",
    }

    headers = {"X-Requested-With": "RescanHelperAPI", "Authorization": API_KEY}

    response = requests.post(url, headers=headers, data=payload, timeout=60)

    if response.status_code != 200:
        print(
            f"Error bad response\nCode: {response.status_code}\nMessage: {response.text}"
        )
        return []

    result_vits: list[str] = []

    rows: DictReader = DictReader(response.text.splitlines())

    for row in rows:
        found_vit_id = get_vit_id(row["IP Address"], "QID-" + row["QID"])
        if found_vit_id == "-1":
            continue
        result_vits.append(found_vit_id)

    result_vits = list(set(result_vits))
    return result_vits


def encode_base64(input_string: str):
    """Helper function to easily encode a string into base64"""
    input_string_bytes = input_string.encode("utf-8")
    base64_bytes = base64.b64encode(input_string_bytes)
    base64_string = base64_bytes.decode("utf-8")
    return base64_string


def decode_base64(input_str: str):
    """Helper function to easily decode a string into base64"""
    base64_bytes = input_str.encode("utf-8")
    output_string_bytes = base64.b64decode(base64_bytes)
    output_string = output_string_bytes.decode("utf-8")
    return output_string


# pylint: disable=too-many-positional-arguments,too-many-arguments
def settings_save_config(
    new_username: ctk.CTkEntry,
    new_password: ctk.CTkEntry,
    new_qualys_platform: ctk.CTkEntry,
    new_login_url: ctk.CTkEntry,
    new_scanner_appliance: tk.Listbox,
    new_snow_url: ctk.CTkEntry,
    new_snow_user: ctk.CTkEntry,
    new_snow_password: ctk.CTkEntry,
):
    """Function to easily save config file updates from the settings menu"""
    # pylint: disable=global-statement,line-too-long
    global API_KEY, QUALYS_PLATFORM, LOGIN_URL, SCANNER_APPLIANCE, SNOW_URL, CONFIG, SNOW_API_USER, SNOW_API_PASSWORD
    with open(
        rescan_helper_path + "/config/config.json", "w", encoding="UTF-8"
    ) as config_file:
        API_KEY = "BASIC " + encode_base64(
            new_username.get() + ":" + new_password.get()
        )
        QUALYS_PLATFORM = new_qualys_platform.get()
        LOGIN_URL = new_login_url.get()
        SCANNER_APPLIANCE = ",".join(new_scanner_appliance.get(0, "end"))
        SNOW_URL = new_snow_url.get()
        SNOW_API_USER = new_snow_user.get()
        SNOW_API_PASSWORD = new_snow_password.get()

        CONFIG = {
            "API_KEY": API_KEY,
            "QUALYS_PLATFORM": QUALYS_PLATFORM,
            "LOGIN_URL": LOGIN_URL,
            "SCANNER_APPLIANCE": SCANNER_APPLIANCE,
            "SNOW_URL": SNOW_URL,
            "SNOW_API_USER": SNOW_API_USER,
            "SNOW_API_PASSWORD": SNOW_API_PASSWORD,
            "SCAN_LIST": SCAN_LIST,
        }
        dump(CONFIG, config_file, indent=4)


def settings_close_popup():
    """Close the settings popups"""
    # pylint: disable=global-variable-not-assigned
    global SETTINGS_POPUPS
    SETTINGS_POPUPS[0].destroy()
    SETTINGS_POPUPS.clear()


# pylint: disable=too-many-locals,too-many-statements
def open_settings():
    """
    Opens the settings page where the user can enter info to update the config file
    """
    # Allows for only 1 popup at a time
    # pylint: disable=global-variable-not-assigned
    global SETTINGS_POPUPS
    if len(SETTINGS_POPUPS) == 1:
        settings_close_popup()

    # Ensures pop up isn't hidden behind program
    popup = ctk.CTkToplevel()
    popup.protocol("WM_DELETE_WINDOW", settings_close_popup)
    popup.title("Settings")
    # pylint: disable=unnecessary-lambda
    popup.after(250, lambda: popup.lift())
    popup.attributes("-topmost", True)
    popup.after_idle(popup.attributes, "-topmost", False)

    top_ribbon_label = ctk.CTkLabel(popup, text="Settings", font=("Arial", 20, "bold"))
    top_ribbon_label.pack(pady=5)

    entries_frame = ctk.CTkFrame(popup, fg_color=GREY_DARK)
    entries_frame.pack(pady=10)
    # Label and their corresponding entry field
    username_label = ctk.CTkLabel(entries_frame, text="Username:")
    username_label.grid(row=0, column=0, padx=10)
    username_entry = ctk.CTkEntry(entries_frame, width=300)
    api_key_decode = decode_base64(API_KEY.split(" ")[1]).split(":", 1)
    username = api_key_decode[0]
    username_entry.insert(0, username)
    username_entry.grid(row=0, column=1, padx=10, pady=5)

    password_label = ctk.CTkLabel(entries_frame, text="Password:")
    password_label.grid(row=1, column=0, padx=10)
    password_entry = ctk.CTkEntry(entries_frame, width=300, show="\u2022")
    password = api_key_decode[1]
    password_entry.insert(1, password)
    password_entry.grid(row=1, column=1, padx=10, pady=5)

    def toggle_hidden(entry):
        """Toggle entry object to showcase dots or the actual text"""
        if entry.cget("show") == "\u2022":
            entry.configure(show="")
        else:
            entry.configure(show="\u2022")

    toggle_hidden_password_button = ctk.CTkButton(
        entries_frame,
        text="👁",
        command=lambda: toggle_hidden(password_entry),
        fg_color=GREY,
        border_width=2,
        border_color=BLACK,
        hover_color=GREY_DARK,
        width=30,
    )
    toggle_hidden_password_button.grid(row=1, column=2, padx=10)

    qualys_platform_label = ctk.CTkLabel(entries_frame, text="Qualys Platform:")
    qualys_platform_label.grid(row=2, column=0, padx=10)
    qualys_platform_entry = ctk.CTkEntry(entries_frame, width=300)
    qualys_platform_entry.insert(0, QUALYS_PLATFORM)
    qualys_platform_entry.grid(row=2, column=1, padx=10, pady=5)

    login_url_label = ctk.CTkLabel(entries_frame, text="Login URL:")
    login_url_label.grid(row=3, column=0, padx=10)
    login_url_entry = ctk.CTkEntry(entries_frame, width=300)
    login_url_entry.insert(0, LOGIN_URL)
    login_url_entry.grid(row=3, column=1, padx=10, pady=5)

    snow_url_label = ctk.CTkLabel(entries_frame, text="SNOW URL:")
    snow_url_label.grid(row=4, column=0, padx=10)
    snow_url_entry = ctk.CTkEntry(entries_frame, width=300)
    snow_url_entry.insert(0, SNOW_URL)
    snow_url_entry.grid(row=4, column=1, padx=10, pady=5)

    snow_api_user_label = ctk.CTkLabel(entries_frame, text="SNOW API User:")
    snow_api_user_label.grid(row=5, column=0, padx=10)
    snow_api_user_entry = ctk.CTkEntry(entries_frame, width=300)
    snow_api_user_entry.insert(0, SNOW_API_USER)
    snow_api_user_entry.grid(row=5, column=1, padx=10, pady=5)

    snow_api_password_label = ctk.CTkLabel(entries_frame, text="SNOW API Password:")
    snow_api_password_label.grid(row=6, column=0, padx=10)
    snow_api_password_entry = ctk.CTkEntry(entries_frame, width=300, show="\u2022")
    snow_api_password_entry.insert(0, SNOW_API_PASSWORD)
    snow_api_password_entry.grid(row=6, column=1, padx=10, pady=5)

    toggle_hidden_password_button = ctk.CTkButton(
        entries_frame,
        text="👁",
        command=lambda: toggle_hidden(snow_api_password_entry),
        fg_color=GREY,
        border_width=2,
        border_color=BLACK,
        hover_color=GREY_DARK,
        width=30,
    )
    toggle_hidden_password_button.grid(row=6, column=2, padx=10)

    scanner_appliance_label = ctk.CTkLabel(entries_frame, text="Scanner Appliance:")
    scanner_appliance_label.grid(row=7, column=0, padx=10)
    scanner_appliance_listbox = tk.Listbox(
        entries_frame,
        width=49,
        selectmode="multiple",
        background=GREY,
        foreground=WHITE,
    )
    scanner_appliance_listbox.grid(row=8, column=1, padx=10, pady=5)
    scanner_appliance_add_entry = ctk.CTkEntry(
        entries_frame, width=300, placeholder_text="Enter scanner appliance name"
    )
    scanner_appliance_add_entry.grid(row=7, column=1, padx=10, pady=5)
    scanner_appliance_add_button = ctk.CTkButton(
        entries_frame,
        text="+",
        command=lambda: add_entry(
            scanner_appliance_listbox, scanner_appliance_add_entry
        ),
        fg_color=GREEN,
        border_width=2,
        border_color=BLACK,
        hover_color=GREEN_DARK,
        width=30,
    )
    scanner_appliance_add_button.grid(row=7, column=2, padx=5, pady=5)
    scanner_appliance_remove_button = ctk.CTkButton(
        entries_frame,
        text="-",
        command=lambda: remove_entry(scanner_appliance_listbox),
        fg_color=RED,
        border_width=2,
        border_color=BLACK,
        hover_color=RED_DARK,
        width=30,
    )
    scanner_appliance_remove_button.grid(row=8, column=2, padx=5, pady=5)

    for scanner in SCANNER_APPLIANCE.split(","):
        scanner_appliance_listbox.insert(0, scanner)

    button_frame = ctk.CTkFrame(popup)
    button_frame.pack(pady=5)
    apply_button = ctk.CTkButton(
        button_frame,
        text="Apply",
        command=lambda: settings_save_config(
            username_entry,
            password_entry,
            qualys_platform_entry,
            login_url_entry,
            scanner_appliance_listbox,
            snow_url_entry,
            snow_api_user_entry,
            snow_api_password_entry,
        ),
        fg_color=GREEN,
        border_width=2,
        border_color=BLACK,
        hover_color=GREEN_DARK,
        width=100,
    )
    apply_button.grid(row=0, column=0, padx=10, pady=5)

    def ok_button_function():
        """Saves config then closes the settings window"""
        settings_save_config(
            username_entry,
            password_entry,
            qualys_platform_entry,
            login_url_entry,
            scanner_appliance_listbox,
            snow_url_entry,
            snow_api_user_entry,
            snow_api_password_entry,
        )
        settings_close_popup()

    ok_button = ctk.CTkButton(
        button_frame,
        text="OK",
        command=ok_button_function,
        fg_color=GREEN,
        border_width=2,
        border_color=BLACK,
        hover_color=GREEN_DARK,
        width=100,
    )
    ok_button.grid(row=0, column=1, padx=10)
    SETTINGS_POPUPS.append(popup)


def scan_settings_close_popup():
    """Closes the scan settings window"""
    # pylint: disable=global-variable-not-assigned
    global SCAN_SETTINGS_POPUPS
    SCAN_SETTINGS_POPUPS[0].destroy()
    SCAN_SETTINGS_POPUPS.clear()
    refresh_scan_display()


# pylint: disable=too-many-statements,too-many-locals
def open_scan_settings():
    """Opens the scan settings window"""
    # pylint: disable=global-variable-not-assigned
    global SCAN_SETTINGS_POPUPS
    # updates all global variables and saves to config file
    scans = SCAN_LIST.copy()

    def scan_settings_save_config():
        """Saves the scan settings to the config file"""
        # pylint: disable=global-statement
        global CONFIG, SCAN_LIST
        add_modify_entry()
        SCAN_LIST = scans
        with open(
            rescan_helper_path + "/config/config.json", "w", encoding="UTF-8"
        ) as config_file:
            refresh_scan_display()
            CONFIG = {
                "API_KEY": API_KEY,
                "QUALYS_PLATFORM": QUALYS_PLATFORM,
                "LOGIN_URL": LOGIN_URL,
                "SCANNER_APPLIANCE": SCANNER_APPLIANCE,
                "SNOW_URL": SNOW_URL,
                "SNOW_API_USER": SNOW_API_USER,
                "SNOW_API_PASSWORD": SNOW_API_PASSWORD,
                "SCAN_LIST": SCAN_LIST,
            }
            dump(CONFIG, config_file, indent=4)

    if len(SCAN_SETTINGS_POPUPS) == 1:
        scan_settings_close_popup()

    # Ensures pop up isn't hidden behind program
    popup = ctk.CTkToplevel()
    popup.protocol("WM_DELETE_WINDOW", scan_settings_close_popup)
    popup.title("Scan Settings")
    # pylint: disable=unnecessary-lambda
    popup.after(250, lambda: popup.lift())
    popup.attributes("-topmost", True)
    popup.after_idle(popup.attributes, "-topmost", False)

    top_ribbon_label = ctk.CTkLabel(
        popup, text="Scan Settings", font=("Arial", 20, "bold")
    )
    top_ribbon_label.pack(pady=5)

    entries_frame = ctk.CTkFrame(popup, fg_color=GREY_DARK)
    entries_frame.pack(pady=10)

    # Label and their corresponding entry field
    name_label = ctk.CTkLabel(entries_frame, text="Name:")
    name_label.grid(row=0, column=0, padx=5, pady=5)
    name_entry = ctk.CTkEntry(entries_frame)
    name_entry.grid(row=0, column=1, padx=5, pady=5)

    search_id_label = ctk.CTkLabel(entries_frame, text="Search List ID:")
    search_id_label.grid(row=1, column=0, padx=5, pady=5)
    search_id_entry = ctk.CTkEntry(entries_frame)
    search_id_entry.grid(row=1, column=1, padx=5, pady=5)

    op_id_label = ctk.CTkLabel(entries_frame, text="Option Profile ID:")
    op_id_label.grid(row=2, column=0, padx=5, pady=5)
    op_id_entry = ctk.CTkEntry(entries_frame)
    op_id_entry.grid(row=2, column=1, padx=5, pady=5)

    def add_modify_entry():
        """Function to add or modify entries in the scans dictionary"""
        name = name_entry.get()
        search_id = search_id_entry.get()
        op_id = op_id_entry.get()

        if name and search_id and op_id:
            scans[name] = {"SEARCH_LIST_ID": search_id, "OP_ID": op_id}
            refresh_scan_listbox()
        else:
            messagebox.showerror("Error", "All fields must be filled!")

    def delete_entry():
        """Function to delete scan type entry"""
        selected = scan_listbox.curselection()
        if selected:
            name = scan_listbox.get(selected[0])
            if name in scans:
                del scans[name]
                refresh_scan_listbox()
                temp_scan_names = []
                for scan_name in scans:
                    temp_scan_names.append(scan_name)

                name_entry.delete(0, "end")
                search_id_entry.delete(0, "end")
                op_id_entry.delete(0, "end")
                if scans:
                    name_entry.insert(0, temp_scan_names[0])
                    search_id_entry.insert(
                        0, scans[temp_scan_names[0]]["SEARCH_LIST_ID"]
                    )
                    op_id_entry.insert(0, scans[temp_scan_names[0]]["OP_ID"])
        else:
            messagebox.showerror("Error", "Please select an entry to delete.")

    def refresh_scan_listbox():
        """Refreshes the listbox to show updated scan entries"""
        scan_listbox.delete(0, "end")
        for name in scans:
            scan_listbox.insert("end", name)

    # The listbox function call of on select requires you to catch the event, even if nothing occurs
    # Therefore the event argument is unused but it must be here
    # pylint: disable=unused-argument
    def on_listbox_select(event):
        """
        Called when user selects a scan from the listbox in scan_settings
        This populates the entry fields
        """
        selected = scan_listbox.curselection()
        if selected:
            name = scan_listbox.get(selected[0])
            if name in scans:
                # Populate the entry fields with selected entry's data
                name_entry.delete(0, "end")
                name_entry.insert(0, name)
                search_id_entry.delete(0, "end")
                search_id_entry.insert(0, scans[name]["SEARCH_LIST_ID"])
                op_id_entry.delete(0, "end")
                op_id_entry.insert(0, scans[name]["OP_ID"])

    # Buttons for adding, modifying, and deleting entries
    add_button = ctk.CTkButton(
        entries_frame,
        text="+",
        command=add_modify_entry,
        fg_color=GREEN,
        border_width=2,
        border_color=BLACK,
        hover_color=GREEN_DARK,
        width=30,
    )
    add_button.grid(row=2, column=2, padx=5, pady=5)

    delete_button = ctk.CTkButton(
        entries_frame,
        text="-",
        command=delete_entry,
        fg_color=RED,
        border_width=2,
        border_color=BLACK,
        hover_color=RED_DARK,
        width=30,
    )
    delete_button.grid(row=3, column=2, padx=5, pady=5)

    # Listbox to show current entries
    scan_listbox = tk.Listbox(
        entries_frame, width=22, height=6, background=GREY, foreground="white"
    )
    scan_listbox.grid(row=3, column=1, padx=5, pady=5)

    scan_listbox.bind("<<ListboxSelect>>", on_listbox_select)

    button_frame = ctk.CTkFrame(popup)
    button_frame.pack(pady=5)
    apply_button = ctk.CTkButton(
        button_frame,
        text="Apply",
        command=scan_settings_save_config,
        fg_color=GREEN,
        border_width=2,
        border_color=BLACK,
        hover_color=GREEN_DARK,
        width=100,
    )
    apply_button.grid(row=0, column=0, padx=10, pady=5)

    def ok_button_function():
        """Saves scan settings then closes the popup"""
        scan_settings_save_config()
        scan_settings_close_popup()

    ok_button = ctk.CTkButton(
        button_frame,
        text="OK",
        command=ok_button_function,
        fg_color=GREEN,
        border_width=2,
        border_color=BLACK,
        hover_color=GREEN_DARK,
        width=100,
    )
    ok_button.grid(row=0, column=1, padx=10)

    refresh_scan_listbox()
    SCAN_SETTINGS_POPUPS.append(popup)


# Easy to edit and read HEX values of colors used in the GUI
PURPLE = "#8026FF"
PURPLE_DARK = "#402491"
RED = "#FF1A58"
RED_DARK = "#AD0047"
BLUE = "#0091DA"
BLUE_DARK = "#00598A"
GREEN = "#4FB947"
GREEN_DARK = "#397934"
WHITE = "#FFFFFF"
BLACK = "#000000"
GREY = "#343638"
GREY_DARK = "#242424"

# Initialize the main window
root = ctk.CTk()
root.title("Rescan Helper")

# Initialize CustomTkinter
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

main_top_ribbon_label = ctk.CTkLabel(
    root, text="Rescan Helper", font=("Arial", 20, "bold")
)
main_top_ribbon_label.pack(pady=5)
# Create a scrolled text area
text_area = scrolledtext.ScrolledText(
    root, wrap="word", width=55, height=6, background=GREY, foreground="white"
)
text_area.insert("1.0", "Paste email's contents here")
text_area.pack(padx=10, pady=10)

# Create a frame for the buttons
main_button_frame = ctk.CTkFrame(root)
main_button_frame.pack(pady=10)

# Create the buttons
button_vits = ctk.CTkButton(
    main_button_frame,
    text="Look up VIT(s)",
    command=look_up_vits,
    fg_color=PURPLE,
    border_width=2,
    border_color=BLACK,
    hover_color=PURPLE_DARK,
)
button_vits.grid(row=0, column=0, padx=10, pady=5)

# Create a frame for the list boxes and their controls
list_frame = ctk.CTkFrame(root)
list_frame.pack(pady=10, padx=20)

# VITs list box and controls
vits_listbox = tk.Listbox(
    list_frame,
    width=20,
    height=10,
    background=GREY,
    foreground="white",
    selectmode="multiple",
)
vits_listbox.grid(row=0, column=0, padx=10)
vits_label = ctk.CTkLabel(list_frame, text="VIT(s)")
vits_label.grid(row=1, column=0, padx=10, pady=5)
vits_add_entry = ctk.CTkEntry(list_frame)
vits_add_entry.grid(row=2, column=0, padx=10, pady=5)
vits_add_button = ctk.CTkButton(
    list_frame,
    text="Add",
    command=lambda: add_entry(vits_listbox, vits_add_entry),
    fg_color=GREEN,
    border_width=2,
    border_color=BLACK,
    hover_color=GREEN_DARK,
)
vits_add_button.grid(row=3, column=0, padx=10, pady=5)
vits_remove_button = ctk.CTkButton(
    list_frame,
    text="Remove",
    command=lambda: remove_entry(vits_listbox),
    fg_color=RED,
    border_width=2,
    border_color=BLACK,
    hover_color=RED_DARK,
)
vits_remove_button.grid(row=4, column=0, padx=10, pady=5)
vits_copy_button = ctk.CTkButton(
    list_frame,
    text="Copy",
    command=lambda: copy(", ".join(vits_listbox.get(0, "end"))),
    fg_color=BLUE,
    border_width=2,
    border_color=BLACK,
    hover_color=BLUE_DARK,
)
vits_copy_button.grid(row=5, column=0, padx=10, pady=5)


# QIDs list box and controls
qids_listbox = tk.Listbox(
    list_frame,
    width=20,
    height=10,
    background=GREY,
    foreground="white",
    selectmode="multiple",
)
qids_listbox.grid(row=0, column=1, padx=10)
qids_label = ctk.CTkLabel(list_frame, text="QID(s)")
qids_label.grid(row=1, column=1, padx=10, pady=5)
qids_add_entry = ctk.CTkEntry(list_frame)
qids_add_entry.grid(row=2, column=1, padx=10, pady=5)
qids_add_button = ctk.CTkButton(
    list_frame,
    text="Add",
    command=lambda: add_entry(qids_listbox, qids_add_entry),
    fg_color=GREEN,
    border_width=2,
    border_color=BLACK,
    hover_color=GREEN_DARK,
)
qids_add_button.grid(row=3, column=1, padx=10, pady=5)
qids_remove_button = ctk.CTkButton(
    list_frame,
    text="Remove",
    command=lambda: remove_entry(qids_listbox),
    fg_color=RED,
    border_width=2,
    border_color=BLACK,
    hover_color=RED_DARK,
)
qids_remove_button.grid(row=4, column=1, padx=10, pady=5)
qids_copy_button = ctk.CTkButton(
    list_frame,
    text="Copy",
    command=lambda: copy(", ".join(qids_listbox.get(0, "end"))),
    fg_color=BLUE,
    border_width=2,
    border_color=BLACK,
    hover_color=BLUE_DARK,
)
qids_copy_button.grid(row=5, column=1, padx=10, pady=5)


# IPs list box and controls
ips_listbox = tk.Listbox(
    list_frame,
    width=20,
    height=10,
    background=GREY,
    foreground="white",
    selectmode="multiple",
)
ips_listbox.grid(row=0, column=2, padx=10)
ips_label = ctk.CTkLabel(list_frame, text="IP(s)")
ips_label.grid(row=1, column=2, padx=10, pady=5)
ips_add_entry = ctk.CTkEntry(list_frame)
ips_add_entry.grid(row=2, column=2, padx=10, pady=5)
ips_add_button = ctk.CTkButton(
    list_frame,
    text="Add",
    command=lambda: add_entry(ips_listbox, ips_add_entry),
    fg_color=GREEN,
    border_width=2,
    border_color=BLACK,
    hover_color=GREEN_DARK,
)
ips_add_button.grid(row=3, column=2, padx=10, pady=5)
ips_remove_button = ctk.CTkButton(
    list_frame,
    text="Remove",
    command=lambda: remove_entry(ips_listbox),
    fg_color=RED,
    border_width=2,
    border_color=BLACK,
    hover_color=RED_DARK,
)
ips_remove_button.grid(row=4, column=2, padx=10, pady=5)
ips_copy_button = ctk.CTkButton(
    list_frame,
    text="Copy",
    command=lambda: copy(", ".join(ips_listbox.get(0, "end"))),
    fg_color=BLUE,
    border_width=2,
    border_color=BLACK,
    hover_color=BLUE_DARK,
)
ips_copy_button.grid(row=5, column=2, padx=10, pady=5)

# Create a frame for the buttons
main_button_frame2 = ctk.CTkFrame(root)
main_button_frame2.pack(pady=10)

# Buttons
button_login = ctk.CTkButton(
    main_button_frame2,
    text="Login to Qualys",
    command=lambda: wb.open(LOGIN_URL),
    fg_color=PURPLE,
    border_width=2,
    border_color=BLACK,
    hover_color=PURPLE_DARK,
)
button_login.grid(row=0, column=0, padx=10, pady=5)

button_open_vmdr = ctk.CTkButton(
    main_button_frame2,
    text="Open VMDR",
    command=open_vmdr,
    fg_color=PURPLE,
    border_width=2,
    border_color=BLACK,
    hover_color=PURPLE_DARK,
)
button_open_vmdr.grid(row=0, column=1, padx=10)

button_copy_email = ctk.CTkButton(
    main_button_frame2,
    text="Email copy paste",
    command=lambda: copy(
        "VIT(s) closed, vulnerabilities have been fixed according to rescan."
    ),
    fg_color=PURPLE,
    border_width=2,
    border_color=BLACK,
    hover_color=PURPLE_DARK,
)
button_copy_email.grid(row=1, column=0, pady=5, padx=10)

button_get_vits_to_close = ctk.CTkButton(
    main_button_frame2,
    text="Get VITs to close",
    command=open_vits_fixed,
    fg_color=PURPLE,
    border_width=2,
    border_color=BLACK,
    hover_color=PURPLE_DARK,
)
button_get_vits_to_close.grid(row=1, column=1, pady=5, padx=10)

# Create a frame for the dropdown and launch scan button
bottom_frame = ctk.CTkFrame(root)
bottom_frame.pack(pady=10)

title_label = ctk.CTkLabel(bottom_frame, text="Title: ")
title_label.grid(row=0, column=0, padx=10)

title_entry = ctk.CTkEntry(bottom_frame)
title_entry.grid(row=0, column=1, padx=10, pady=5)


scan_types_names = []


def refresh_scan_display():
    """Refreshes the scan display drop down (used when saving / loading scans)"""
    scan_types_names.clear()
    for scan_name in SCAN_LIST:
        scan_types_names.append(scan_name)
    scan_type_dropdown.configure(values=scan_types_names)
    if scan_types_names:
        scan_type_var.set(scan_types_names[0])


# Create the dropdown menu
scan_type_label = ctk.CTkLabel(bottom_frame, text="Scan type:")
scan_type_label.grid(row=1, column=0, padx=10)
scan_type_var = ctk.StringVar(value=scan_types_names[0] if scan_types_names else "")

scan_type_dropdown = ctk.CTkOptionMenu(
    bottom_frame,
    variable=scan_type_var,
    fg_color=PURPLE,
    button_color=PURPLE,
    button_hover_color=PURPLE_DARK,
)
scan_type_dropdown.grid(row=1, column=1, padx=10, pady=5)
refresh_scan_display()

scan_settings = ctk.CTkButton(
    bottom_frame,
    text="⚙️",
    command=open_scan_settings,
    fg_color=PURPLE,
    border_width=2,
    border_color=BLACK,
    hover_color=PURPLE_DARK,
    width=15,
)
scan_settings.grid(row=1, column=2, padx=5)

# Create the launch scan button
button_launch_scan = ctk.CTkButton(
    bottom_frame,
    text="Launch scan",
    command=launch_scan,
    fg_color=RED,
    border_width=2,
    border_color=BLACK,
    hover_color=RED_DARK,
)
button_launch_scan.grid(row=3, column=1, padx=10, pady=5)

settingsButton = ctk.CTkButton(
    root,
    text="⚙️",
    command=open_settings,
    fg_color=GREY,
    border_width=1,
    border_color=WHITE,
    hover_color=GREY_DARK,
    width=15,
)
settingsButton.place(relx=1.0, rely=0.0, anchor="ne", x=-10, y=5)

# Run the application
root.mainloop()
