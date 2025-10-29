#!/usr/bin/env python3
"""
deploy_esxi_cimc.py

Simple script to mount an ESXi ISO as virtual media on a Cisco CIMC/IMC (Redfish),
set one-time boot to virtual media, and power-cycle the host so it boots the installer.

Prereqs:
 - Python 3.8+
 - pip install requests
 - CIMC/IMC with Redfish/VirtualMedia support
 - An accessible ESXi ISO URL (http:// or https://) or a virtual media upload endpoint if your CIMC requires it.

References:
 - Cisco IMC / Redfish REST API docs (see README in repo). 
 - VMware scripted ESXi install docs for kickstart (ks=).
"""

import requests
import urllib3
import time
import sys

# -- CONFIGURE THESE --
CIMC_HOST = "10.0.0.100"                # CIMC / IMC IP address
USERNAME = "admin"
PASSWORD = "password"
ESXI_ISO_URL = "https://my-http-server.local/images/VMware-ESXi-8.0.0-xxxx.iso"
KICKSTART_URL = "http://my-http-server.local/kickstarts/esxi-ks.cfg"  # optional
VERIFY_SSL = False                       # set True if CIMC has valid cert
TIMEOUT = 10

# -- END CONFIG --

if not VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE = f"https://{CIMC_HOST}"

session = requests.Session()
session.verify = VERIFY_SSL
session.headers.update({"Content-Type": "application/json"})

def create_redfish_session():
    url = f"{BASE}/redfish/v1/Sessions"
    payload = {"UserName": USERNAME, "Password": PASSWORD}
    r = session.post(url, json=payload, timeout=TIMEOUT)
    if r.status_code in (201, 200):
        # session created, token in header
        token = r.headers.get("X-Auth-Token") or r.json().get("Token")
        if token:
            session.headers.update({"X-Auth-Token": token})
        print("[+] Created Redfish session.")
        return True
    else:
        print("[-] Failed to create session:", r.status_code, r.text)
        return False

def get_managers():
    url = f"{BASE}/redfish/v1/Managers"
    r = session.get(url, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    members = data.get("Members", [])
    if not members:
        raise RuntimeError("No Managers found on CIMC")
    # take first manager
    manager_uri = members[0].get("@odata.id")
    return manager_uri  # like /redfish/v1/Managers/1

def get_systems():
    url = f"{BASE}/redfish/v1/Systems"
    r = session.get(url, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    members = data.get("Members", [])
    if not members:
        raise RuntimeError("No Systems found on CIMC")
    system_uri = members[0].get("@odata.id")
    return system_uri  # like /redfish/v1/Systems/1

def create_virtual_media(manager_uri, iso_url, media_name="ESXI_ISO"):
    """
    Create VirtualMedia entry pointing to iso_url.
    Many CIMC implementations accept POST to /Managers/{id}/VirtualMedia
    with an 'Image' field to point to a remote URL. If your CIMC requires
    uploading the ISO via vmedia upload, use the CIMC-specific flow.
    """
    vm_url = f"{BASE}{manager_uri}/VirtualMedia"
    payload = {
        "Name": media_name,
        "Image": iso_url,
        "Inserted": True,
        "MediaTypes": ["CD"]  # typical for ISO
    }
    r = session.post(vm_url, json=payload, timeout=TIMEOUT)
    if r.status_code in (201, 200):
        created = r.headers.get("Location") or r.json().get("@odata.id")
        print(f"[+] Virtual media created: {created}")
        return created
    else:
        # Some CIMC implementations instead require using specific action endpoints.
        print("[-] Failed to create virtual media, status:", r.status_code, r.text)
        return None

def set_one_time_boot_to_cd(system_uri):
    """
    Use Redfish Boot override. Sets BootSourceOverrideTarget to 'Cd'.
    """
    url = f"{BASE}{system_uri}"
    payload = {
        "Boot": {
            "BootSourceOverrideTarget": "Cd",
            "BootSourceOverrideEnabled": "Once"
        }
    }
    r = session.patch(url, json=payload, timeout=TIMEOUT)
    if r.status_code in (200, 204):
        print("[+] One-time boot set to CD/virtual-media.")
        return True
    else:
        print("[-] Failed to set one-time boot:", r.status_code, r.text)
        return False

def reset_system(system_uri, reset_type="ForceRestart"):
    """
    Reset (power cycle) the system to boot into the virtual media.
    Valid ResetType values are implementation-specific; 'ForceRestart' is common.
    """
    action_url = f"{BASE}{system_uri}/Actions/ComputerSystem.Reset"
    payload = {"ResetType": reset_type}
    r = session.post(action_url, json=payload, timeout=TIMEOUT)
    if r.status_code in (200, 202, 204):
        print(f"[+] System reset ({reset_type}) requested.")
        return True
    else:
        print("[-] Failed to reset system:", r.status_code, r.text)
        return False

def main():
    try:
        if not create_redfish_session():
            sys.exit(1)

        manager_uri = get_managers()
        system_uri = get_systems()

        print(f"[i] Manager: {manager_uri}, System: {system_uri}")

        # Create virtual media pointing to ESXi ISO
        vm = create_virtual_media(manager_uri, ESXI_ISO_URL)
        if not vm:
            print("[-] Virtual media creation failed. Some CIMC images require uploading ISO via vKVM/virtual media upload which is vendor-specific. Check CIMC docs.")
            sys.exit(2)

        # (Optional) If you need to pass a Kickstart URL to the ESXi installer, you will need to either
        #  - create a custom ISO with the KS file embedded, OR
        #  - configure the ISO's boot loader to include 'ks=' kernel option to KICKSTART_URL.
        # This script does not modify ISO contents. See VMware docs on 'ks=' and scripted installs.
        if KICKSTART_URL:
            print("[i] Note: For unattended install, ensure the ESXi boot picks up your kickstart (ks=).")
            print(f"[i] Kickstart should be reachable at: {KICKSTART_URL}")

        # Set one-time boot to CD/virtual-media
        if not set_one_time_boot_to_cd(system_uri):
            sys.exit(3)

        # Reset the system to boot from virtual media
        if not reset_system(system_uri):
            sys.exit(4)

        print("[+] Done. Host should be booting the ESXi installer from virtual media.")
        print("[i] Monitor via CIMC vKVM or serial console. If installer requires ks= manual input, either inject KS into ISO or supply it via network + boot options.")

    except Exception as e:
        print("[-] Exception:", str(e))
        sys.exit(99)

if __name__ == "__main__":
    main()
