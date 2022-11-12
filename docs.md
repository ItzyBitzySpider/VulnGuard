# Some Documentation (to be cleaned up)

### Semgrep Scanning
Utilises Semgrep (Semantic Grep) to perform scanning. With its large user base and extensive database of community curated rules, Semgrep allows for multiple scanning options. Semgrep allows for static analysis, dynamic analysis (sinks and taints), etc. VulnGuard allows for the addition of user-defined Semgrep rules and other Semgrep rules to be added on top of the existing default enabled rules.

Semgrep rules follow the following format:




### Regex/Pattern Matching Scanning
For simpler rules that may not need Semgrep, Regex rules can be created. Regex rules perform Regex pattern matching on code files to look for vulnerabilities.

Regex Rules follow the following format:


### Default Rules
Default Semgrep rules include:

1. [p/owasp-top-ten](https://semgrep.dev/p/owasp-top-ten)
2. [p/nodejsscan](https://semgrep.dev/p/nodejsscan)
3. [p/javascript](https://semgrep.dev/p/javascript)
4. [p/expressjs](https://semgrep.dev/p/expressjs)
5. [p/react](https://semgrep.dev/p/react)
6. [p/eslint-plugin-security](https://semgrep.dev/p/eslint-plugin-security)
7. [p/xss](https://semgrep.dev/p/xss)
8. [p/sql-injection](https://semgrep.dev/p/sql-injection)
9. [p/r2c-security-audit](https://semgrep.dev/p/r2c-security-audit)

Default Regex rules are curated from Microsoft DevSkim.

Other rules include:

### User-Defined Rules
Users can add their own custom rules to be used as part of Semgrep/Regex scanning. This configuration persists through shutdowns and restarts of VSCode.

### Dependency Checking
Supply chain attacks --> Want to ensure dependecies and modules imported are safe and not malicious. Given the inherent trust given to npm packages with no vulnerability scanning, it is important to check modules/packages.


When packages are installed/added, `package.json` is naturally modified in the process of installing/adding packages. VulnGuard scans all dependency packages listed in `package.json` whenever `package.json` is updated. Should packages be detected as malicious, warnings will be shown to the developer when viewing `package.json`.


Dependency Checking builds upon the work done by Spaceraccoon in [npm-scan](https://github.com/spaceraccoon/npm-scan) and other sdc (simple dependency check) tools. The following documents the various heuristics used to determine if a package is malicious:

1) No Source Code Repository for Package
2) Unmaintained Package (checks against NPM)
3) Unusually long time between releases for Package (checks against NPM)
4) OS Scripts (.sh, .bat etc) found within packages
5) Fetching of CSP (ref Spaceraccoon)
6) Creation of Child Proceses
7) JJEncode Obfuscation in Code
8) Unsafe Unicode Used (trojan obfuscation) (ref nodesecure scanner and js-x-ray)
9) Package main export is minfied (ref Spaceracoon)
10) Install scripts found in manifest scripts
11) Shell Commands found in manifest scripts


Currently, user-defined rules and modules are not enabled through the GUI, but can be done manually. Currently, only user-defined Regex rules are supported. They follow the same format as Regex rules mentioned above. 


### Other Notes
- Semgrep is not supported on Windows at the moment, and so is automatically disabled on Windows computers.
- Semgrep can be automatically installed through the VSCode Extension using either `homebrew` or `pip`. If the installation fails however, one can refer to [Semgrep Docs](https://semgrep.dev/docs/getting-started/) on how to configure Semgrep for their system. 
- The demo was conducted in Linux.


### Assumptions made during Dependency Checks
Note: We only scan packages defined in `package.json` of the project. While this may sound like a problem, the following assumptions are made:
1) A maintained package will be able to resolve any malicious packages being used in its codebase (conversely, a package determined to be unmaintained should not be used at all).
2) A package with long intervals between releases is likely compromised and its modules are not updated, as such the package should not be used at all.