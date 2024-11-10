#!/usr/bin/env python

"""
    RESTCONF Script to configure an interface or retrieve device information on the DevNet Sandbox.

    Adjusted for:
    - Hostname: devnetsandboxiosxe.cisco.com
    - Username: admin
    - Password: C1sco12345
    - Management Interface: GigabitEthernet1
    - RESTCONF Port: 443
"""

import json
import xml.etree.ElementTree as ET
import requests
import sys
import ipaddress
from collections import OrderedDict
from getpass import getpass
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

headers = {'Content-Type': 'application/yang-data+json',
           'Accept': 'application/yang-data+json'}

url_base = "https://devnetsandboxiosxe.cisco.com:443/restconf/data/ietf-interfaces:interfaces"


def get_configured_interfaces():
    try:
        response = requests.get(
            url_base,
            auth=("admin", "C1sco12345"),
            headers=headers,
            verify=False
        )
        response.raise_for_status()
    except Exception as e:
        print(f"Error retrieving interfaces: {e}", file=sys.stderr)
        sys.exit(1)

    return response.json()["ietf-interfaces:interfaces"]["interface"]


def retrieve_device_info_to_xml():
    try:
        response = requests.get(
            url_base,
            auth=("admin", "C1sco12345"),
            headers={'Accept': 'application/yang-data+xml'},
            verify=False
        )
        response.raise_for_status()
    except Exception as e:
        print(f"Error retrieving device information: {e}", file=sys.stderr)
        sys.exit(1)

    xml_data = response.text
    with open("device_info.xml", "w") as file:
        file.write(xml_data)
    print("Device information has been saved to 'device_info.xml'.")


def configure_ip_address(interface, ip):
    url = f"{url_base}/interface={interface}"

    # Data payload
    data = OrderedDict([
        ('ietf-interfaces:interface', OrderedDict([
            ('name', interface),
            ('type', 'iana-if-type:ethernetCsmacd'),
            ('ietf-ip:ipv4', OrderedDict([
                ('address', [OrderedDict([
                    ('ip', ip["address"]),
                    ('netmask', ip["mask"])
                ])])
            ]))
        ]))
    ])

    try:
        response = requests.put(
            url,
            auth=("admin", "C1sco12345"),
            headers=headers,
            verify=False,
            json=data
        )
        response.raise_for_status()
    except Exception as e:
        print(f"Error configuring interface: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Configuration response:\n{response.text}")

def select_interface(interfaces):
    print("The router has the following interfaces:")
    interface_map = {}  # Map of numbers to interface names
    for idx, interface in enumerate(interfaces, start=1):
        print(f"  {idx}. {interface['name']}")
        interface_map[str(idx)] = interface['name']

    print("\nManagement Interface: GigabitEthernet1 (cannot be modified)\n")

    # Prompt user to select an interface
    selected_index = input("Select the number corresponding to the interface you want to configure: ").strip()
    while selected_index not in interface_map or interface_map[selected_index] == "GigabitEthernet1":
        print("Invalid selection. Please choose a valid number and avoid selecting the management interface.")
        selected_index = input("Select the number corresponding to the interface you want to configure: ").strip()

    return interface_map[selected_index]


def print_interface_details(interface):
    url = f"{url_base}/interface={interface}"

    try:
        response = requests.get(
            url,
            auth=("admin", "C1sco12345"),
            headers=headers,
            verify=False
        )
        response.raise_for_status()
    except Exception as e:
        print(f"Error retrieving interface details: {e}", file=sys.stderr)
        sys.exit(1)

    # Check if the response is a single dictionary or a list
    intf = response.json()["ietf-interfaces:interface"]
    if isinstance(intf, list):
        intf = intf[0]

    print(f"Name: {intf['name']}")
    try:
        ip = intf["ietf-ip:ipv4"]["address"][0]["ip"]
        netmask = intf["ietf-ip:ipv4"]["address"][0]["netmask"]
        print(f"IP Address: {ip} / {netmask}")
    except KeyError:
        print("IP Address: UNCONFIGURED")
    print()


def main():
    print("Connecting to devnetsandboxiosxe.cisco.com...")

    print("\nMenu:")
    print("1. Configure device interface")
    print("2. Retrieve device information (saved as XML)")
    choice = input("Enter your choice (1 or 2): ").strip()

    if choice == "1":
        print("Retrieving configured interfaces...\n")

        interfaces = get_configured_interfaces()


        selected_interface = select_interface(interfaces)

        # Display starting configuration
        print("\nStarting configuration for the interface:")
        print_interface_details(selected_interface)

        try:
            ip_address = input("Enter the new IP address (e.g., 192.168.1.2): ").strip()
            subnet_mask = input("Enter the subnet mask (e.g., 255.255.255.0): ").strip()
            ip = {
                "address": ip_address,
                "mask": subnet_mask
            }
            ipaddress.ip_address(ip["address"])
            ipaddress.ip_address(ip["mask"])
        except ValueError as e:
            print(f"Invalid IP address or subnet mask: {e}", file=sys.stderr)
            sys.exit(1)

        print("\nApplying new configuration...")
        configure_ip_address(selected_interface, ip)

        print("\nFinal configuration for the interface:")
        print_interface_details(selected_interface)


    elif choice == "2":
        print("\nRetrieving device information...")
        retrieve_device_info_to_xml()

    else:
        print("Invalid choice. Exiting.")
        sys.exit(1)


if __name__ == "__main__":
    sys.exit(main())
