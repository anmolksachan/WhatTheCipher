# What The Cipher

![POC](https://github.com/anmolksachan/anmolksachan.github.io/blob/main/img/WhatTheCipher_POC.gif)

Cipher Suite Checker - This is a Python script that checks the cipher suite of a domain or IP address and generates a report on its security status. It uses Nmap and ciphersuite.info to perform the analysis.

## Installation

1.  Clone the repository:

`git clone https://github.com/anmolksachan/WhatTheCipher.git` 

2.  Install the necessary dependencies:

`pip install -r requirements.txt` 

3.  Run the script:

`python WTC.py` 

## Usage

1.  Enter the domain name or IP address you want to analyze when prompted.
2.  Enter the port number you want to analyze when prompted.
3.  Wait for the script to complete.
4.  Check the results in the generated report file, named `{domain}_{port}_report.html`.

## Features

-   Checks the cipher suite of a domain or IP address using Nmap.
-   Analyzes the security status of each cipher using ciphersuite.info.
-   Generates a report on the security status of each cipher.

## Contributing
Contributions are welcome! If you would like to contribute to the project, please create a pull request with your proposed changes.
-   [Anurag Mondal](https://github.com/7ragnarok7) 

## Credits
-   [Nmap](https://nmap.org/) - Free and open source utility for network discovery and security auditing.
-   [ciphersuite.info](https://ciphersuite.info/) - Website that provides information on the security status of cipher suites.

## License

This project is licensed under the MIT License - see the [LICENSE](https://raw.githubusercontent.com/anmolksachan/WhatTheCipher/main/LICENSE) file for details.
