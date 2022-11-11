# Some Documentation (to be cleaned up)

### Semgrep Scanning
Utilises semgrep (sementic grep) to perform scanning. With its large user base and extensive database of community curated rules, semgrep allows for multiple scanning options. Semgrep allows for static analysis, dynamic analysis (sinks and taints) etc. VulnGuard allows for the addition of user-defined semgrep rules and other semgrep rules to be added on top of the existing default enabled rules. 

Semgrep rules follow the following format (copy from semgrep)


### Regex/Pattern Matching Scanning
For simpler rules that may not need semgrep, regex rules can be created. Regex rules perform regex pattern matching on code files to look for vulnerabilities. 

Regex Rules follow the following format:


### Default Rules
Default semgrep rules include:

Default regex rules are curated from Microsoft DevSkim

Other rules include:

### User-Defined Rules
Users can add their own custom rules, or define new rules to be used as part of semgrep/regex scanning. This configuration is persisted through shutdown and restarts of VSCode.

### Dependency Checking
Supply chain attacks --> Want to ensure dependecies and modules imported are safe and not malicious. Given the inherent trust given to npm packages with no vulnerability scanning, it is important to check modules/packages. 


When packages are installed/added, package.JSON is naturally modified in the process of installing/adding packages. VulnGuard scans all packages in `node_modules/` whenever package.JSON is updated. Should packages be detected as malicious, warnings will be shown on package.JSON to the developer. 

(KIV)
In addition, new rules will automatically be created to catch any code utilising such malicious packages. Developers who may not check package.JSON will be informed of malicious package when they attempt to import these packages in their code through the newly created rule. 

Dependency Checking builds upon the work done by SpaceRaccoon in npm-scan and other sdc (simple dependency check). The following documents the various heuristics used to determine if a package is malicious. 

1) No Source Code Repository for Package 
2) Unmaintained Package (checks against NPM)
3) Unusually long time between releases for Package (checks against NPM)
4) OS Scripts (.sh, .bat etc) found within packages
4) Fetching of CSP (ref SpaceRaccoon)
5) Creation of Child Proceses
6) JJEncode Obfuscation in Code
7) Unsafe Unicode Used (trojan obfuscation) (ref nodesecure scanner and js-x-ray)
8) Package main export is minfied (ref SpaceRacoon)
9) Install scripts found in manifest scripts
10) Shell Commands found in manifest scripts


Currently, user-defined rules and modules are not enabled thru the GUI, but can be done manually. Currently, only user-defined regex rules are supported. They follow the same format as regex rules mentioned above. 


### Other Notes:
- Semgrep is not supported on windows at the moment, and so is automatically disabled for windows laptops. 
- Semgrep can be automatically installed through the VSCode Extension either using `homebrew` or `pip`. If the installation fails however, one can refer to semgrep docs (LINK DOCS) to configure semgrep for their system. 
- The demo was conducted in Linux


### Assumptions made during Dependency Checks
Note, we only scan packages defined in package.JSON of the project. While this may sound like a problem, the following assumptions are made:
1) A maintained package will be able to resolve any malicious packages being used in its codebase (conversely, a package determined to be unmaintained should not be used at all)
2) A package with long intervals between releases is likely compromised and its modules are not updated, as such the package should not be used at all. 