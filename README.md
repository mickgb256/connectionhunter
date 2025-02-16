ConnectionHunter
================

**ConnectionHunter** is a PowerShell script designed to scan active network connections on a Windows system and detect any matches against a known list of malicious IP addresses.

Features
--------

*   Fetches a list of bad IPs from an online repository.
    
*   Uses netstat to scan active network connections.
    
*   Checks against the bad IP list to identify potential threats.
    
*   Provides real-time alerts and logs results to a file.
    
*   Uses intelligent caching to avoid unnecessary downloads.
    

Prerequisites
-------------

*   Windows PowerShell (5.1 or later recommended)
    
*   Internet access (to fetch the bad IP list)
    

Installation
------------

1.  git clone https://github.com/yourusername/ConnectionHunter.git
    
2.  cd ConnectionHunter
    
3.  Skay
    

Usage
-----

Run the script from PowerShell:

Powershell
...
  .\ConnectionHunter.ps1   `
...

Optional: To check a remote computer (not currently supported, future feature):

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   .\ConnectionHunter.ps1 -RemoteComputer "COMPUTER_NAME"   `

Logging
-------

All alerts and scan results are stored in bad\_ip\_hits.log in the script directory.

Updating Bad IP List
--------------------

The script automatically updates the bad IP list by comparing file sizes and modification timestamps before downloading.

Dependency
----------

ConnectionHunter relies on the [bitwire-it/ipblocklist](https://github.com/bitwire-it/ipblocklist) repository to fetch the latest list of known malicious IPs. A huge thanks to the maintainers for keeping this resource updated!

License
-------

This project is licensed under the terms of The Unlicense. See LICENSE file for details.

Disclaimer
----------

This script is provided "as is" without any guarantees. Use at your own risk.
