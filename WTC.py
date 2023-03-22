import subprocess
import re
import time
import sys
import os
from colorama import init, Fore

# initialize colorama
init()

def run_nmap(domain, port):
    cmd = f"nmap -oX outputfile_{domain}_{port}.xml -p {port} -Pn --script ssl-enum-ciphers {domain}"
    print(f"\n+ Running nmap at {domain} on port {port}")
    output = subprocess.check_output(cmd, shell=True, universal_newlines=True)
    return output

def check_cipher_security(cipher, for_report=False):
    cipher_length = re.search(r"\d{1,4}$", cipher)
    #if cipher_length == 0 or cipher_length == None:
    if cipher_length: 
        cipher_length = cipher_length.group() 
        if int(cipher_length) < 128:
            return "Cipher length below 128"
    if "NULL" in cipher:
        if for_report:
           return "SSL/TLS - Weak Encryption Ciphers - Cipher suites using NULL (anonymous)."
        else:
           return Fore.RED + "SSL/TLS - Weak Encryption Ciphers - Cipher suites using NULL (anonymous)." + Fore.RESET
    if "3DES" in cipher:
        if for_report:
           return "SSL/TLS - Weak Encryption Ciphers - Cipher suites using 3DES."
        else:
           return Fore.RED + "SSL/TLS - Weak Encryption Ciphers - Cipher suites using 3DES." + Fore.RESET
    if "RC4" in cipher:
        if for_report:
           return "SSL/TLS - Weak Encryption Ciphers - Cipher suites using RC4."
        else:
           return Fore.RED + "SSL/TLS - Weak Encryption Ciphers - Cipher suites using RC4." + Fore.RESET
    if "CBC" in cipher:
        if for_report:
           return "SSL/TLS - Weak Encryption Ciphers - Cipher suites using CBC."
        else:
           return Fore.RED + "SSL/TLS - Weak Encryption Ciphers - Cipher suites using CBC." + Fore.RESET

    
    if os.name =="nt":
                cmd = f'curl -s "https://ciphersuite.info/search/?q={cipher}" | findstr "badge bg-fixed-width"'

    else:
                cmd = f'curl -s "https://ciphersuite.info/search/?q={cipher}" | grep "badge bg-fixed-width"'

    #cmd = f'curl -s "https://ciphersuite.info/search/?q={cipher}" | findstr "badge bg-fixed-width"'
    try:
        output = subprocess.check_output(cmd, shell=True, universal_newlines=True)
    except subprocess.CalledProcessError:
        return "Error"
    security_text = re.search(r'<span class="badge bg-fixed-width bg-([a-zA-Z0-9]+)">(\w+)</span>', output)
    if security_text:
        security = security_text.group(2)
        if security == "Secure":
            formatted_security = Fore.GREEN + security + Fore.RESET
        elif security == "Weak":
            formatted_security = Fore.YELLOW + security + Fore.RESET
        elif security == "Insecure":
            formatted_security = Fore.RED + security + Fore.RESET
        elif security == "Recommended":
            formatted_security = Fore.GREEN + security + Fore.RESET
        else:
            formatted_security = Fore.BLUE + security + Fore.RESET
        if for_report:
            return security
        else:
            return formatted_security
    return "Unknown" 

def check_cipher_security_TLS(TLS, for_report_TLS=False):
    if "1.0" in TLS:
        if for_report_TLS:
           return "TLS 1.0 have been completely deprecated."
        else:
           return Fore.RED + "TLS 1.0 have been completely deprecated." + Fore.RESET
    if "1.1" in TLS:
        if for_report_TLS:
           return "TLS 1.1 have been completely deprecated."
        else:
           return Fore.RED + "TLS 1.1 have been completely deprecated." + Fore.RESET
    if "1.2" in TLS:
        if for_report_TLS:
           return "TLS 1.2 can still be used, it is considered safe only when weak ciphers and algorithms are removed."
        else:
           return Fore.YELLOW + "TLS 1.2 can still be used, it is considered safe only when weak ciphers and algorithms are removed." + Fore.RESET
    if "1.3" in TLS:
        if for_report_TLS:
           return "TLS 1.3 is Recommended."
        else:
           return Fore.GREEN + "TLS 1.3 is Recommended." + Fore.RESET
    return "Unknown TLS Status."

def banner():
  print(f""" {Fore.RED} 
    ▄ ▄    ▄  █ ██     ▄▄▄▄▀        ▄▄▄▄▀ ▄  █ ▄███▄       ▄█▄    ▄█ █ ▄▄   ▄  █ ▄███▄   █▄▄▄▄ 
   █   █  █   █ █ █ ▀▀▀ █        ▀▀▀ █   █   █ █▀   ▀      █▀ ▀▄  ██ █   █ █   █ █▀   ▀  █  ▄▀ 
  █ ▄   █ ██▀▀█ █▄▄█    █            █   ██▀▀█ ██▄▄        █   ▀  ██ █▀▀▀  ██▀▀█ ██▄▄    █▀▀▌  
  █  █  █ █   █ █  █   █            █    █   █ █▄   ▄▀     █▄  ▄▀ ▐█ █     █   █ █▄   ▄▀ █  █  
   █ █ █     █     █  ▀            ▀        █  ▀███▀       ▀███▀   ▐  █       █  ▀███▀     █   
    ▀ ▀     ▀     █                        ▀                           ▀     ▀            ▀    
                 ▀         {Fore.RESET}                                                                     
               {Fore.GREEN}   What The Cipher by @FR13ND0x7F {Fore.RESET}
  """) 

def load_animation():

        load_str = "Preparing What The Cipher Utility...."
        ls_len = len(load_str)


        animation = "|/-\\"
        anicount = 0

        counttime = 0

        i = 0

        while (counttime != 100):


                time.sleep(0.075)


                load_str_list = list(load_str)

                x = ord(load_str_list[i])

                y = 0

                if x != 32 and x != 46:
                        if x>90:
                                y = x-32
                        else:
                                y = x + 32
                        load_str_list[i]= chr(y)

                res =''
                for j in range(ls_len):
                        res = res + load_str_list[j]

                sys.stdout.write("\r"+res + animation[anicount])
                sys.stdout.flush()


                load_str = res


                anicount = (anicount + 1)% 4
                i =(i + 1)% ls_len
                counttime = counttime + 1

        if os.name =="nt":
                os.system("cls")

        else:
                os.system("clear")

def main():
    load_animation()
    banner()
    results = []
    while True:
        domain = input("\nEnter domain name / IP (press q to quit and generate report): ")
        if domain.lower() == "q":
            break
        port = input("Enter Port: ")
        nmap_output = run_nmap(domain, port)
        ciphers = re.findall(r"(?<=TLS_).*?(?= )", nmap_output)
        TLS = re.findall(r"TLSv\d\.\d", nmap_output)
        print(nmap_output)
        print("+ Scan Completed.")

        result = (domain, port, nmap_output, ciphers, TLS)
        results.append(result)

    #print("Final Scan Results:")
    #for result in results:
        #print("Domain: {}\nPort: {}\nNmap Output: {}\nCiphers: {}\nTLS Version: {}\n".format(*result))

    report_file = input("\nEnter the name of your report (No extension required eg. Report_v0.1 ): ")
    #report_file = "scan_report.html"
    report_file = (f"{report_file}.html")
    nmap_report = input("\nPrint nmap results in report (y/n): ")
    print(f"\nWriting results to {Fore.RED + report_file + Fore.RESET}")
    with open(report_file, "w") as f:
        f.write("<html><body>")
        f.write("<h1><center>SSL/TLS - Weak Encryption Ciphers Report</center></h1><br>")
        f.write("<link rel='stylesheet' href='https://anmolksachan.github.io/css/style_anmol_fr13nd0x7f_WTC.css'>\n<body>")
        for result in results:
            domain, port, nmap_output, ciphers, TLS = result
            f.write(f"<h2><center>Results for {domain} on port {port}</center></h2>")
            if nmap_report.lower() == "y" or nmap_report.lower() == "yes" :
                f.write("<h3>Nmap Output:</h3>")
                f.write(f"<pre>{nmap_output}</pre>")
            f.write("<h3>Cipher Suites:</h3>")
            f.write("\n<table>\n<tr><th>Target</th><th>Cipher Name</th><th>Status</th></tr>\n")
            for cipher in ciphers:
                security = check_cipher_security(cipher, True)
                f.write(f"<tr><td>{domain}</td><td><a href='https://ciphersuite.info/search/?q={cipher}' target='_blank'>{cipher}</a></td><td>{security}</td></tr>\n")
                print(f"- Target : {domain}, Cipher Name : {Fore.YELLOW + cipher + Fore.RESET}, Status : {check_cipher_security(cipher)}")
            f.write("</table><br>")
            f.write("<h3>TLS Version:</h3>")
            f.write("\n<table>\n<tr><th>Target</th><th>TLS Version</th><th>Recommendation</th></tr>\n")
            for version in TLS:
                security_TLS = check_cipher_security_TLS(version, True)
                f.write(f"<tr><td>{domain}</td><td>{version}</td><td>{security_TLS}</td></tr>\n")
                print(f"- Target : {domain}, TLS Version : {version}, Status : {check_cipher_security_TLS(version)}")
            f.write("</table><br>")
        f.write("</body></html>")

    print(f"\nScan report available at {Fore.RED + report_file + Fore.RESET}")

if __name__ == "__main__":
    main()
