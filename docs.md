# Some Documentation (to be cleaned up)

### Semgrep Scanning
Utilises [Semgrep (Semantic Grep)](https://semgrep.dev/) to perform scanning. With its large userbase and extensive database of community curated rules, Semgrep allows for multiple scanning options. Semgrep allows for static analysis, dynamic analysis (sinks and taints), etc. VulnGuard allows for the addition of user-defined Semgrep rules/repositories on top of the existing default enabled rules.

Semgrep rules follow the following format:
```

```


### Regex/Pattern Matching Scanning
For simpler rules that may not need Semgrep, Regex rules can be created. Regex rules perform Regex pattern matching on code files to look for vulnerabilities.

Regex Rules are stored in YAML files, and follow the following general format:
```yml
rules:
    # id (Mandatory) - ID for the regex rule.
  - id: <string>

    # message (Mandatory) - Description to be provided to the user when the regex pattern is matched.
    message: <string>

    # severity (Mandatory) - Either "INFO", "WARNING", or "ERROR".
    severity: <string>

    # regex (Mandatory) - Regex pattern to be checked.
    regex: <string>

    # case_sensitive (Optional) - Whether the regex provided should be compiled case sensitive.
    case_sensitive: <boolean>

    # fix (Optional) - Fix to be applied to the line in which the Regex pattern is matched.
    fix: <string>

    # reference (Optional) - Link for the user to 
    reference: <string>
```

VulnGuard also supports the use of the `regex_and`, `regex_or`, and `regex_not` fields, in addition to the nesting of multiple Regex patterns to form a Regex "tree".

**Example 1**
```yml
# This rule is equivalent to the condition (A || B || C), where A, B, C are Regex patterns.

rules:
  - id: 'example-1'
    message: 'Example 1'
    severity: 'INFO'
    regex_or:
      - regex: A
      - regex: B
      - regex: C
```

**Example 2**
```yml
# This rule is equivalent to the condition (A && B && (C || !D)), where A, B, C, D are Regex patterns.

rules:
  - id: 'example-2'
    message: 'Example 2'
    severity: 'INFO'
    regex_and:
      - regex: A
      - regex: B
      - regex_or:
          - regex: C
          - regex_not: D
```

For more examples, see [VulnGuard's default Regex rules](https://github.com/ItzyBitzySpider/VulnGuard/tree/main/files/regex_rules).

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

Default Regex rules are curated from various sources, and include:

1. [Microsoft DevSkim](https://github.com/microsoft/DevSkim)
2. [insider](https://github.com/insidersec/insider)
3. [njsscan](https://github.com/ajinabraham/njsscan)

Other rules include:

### User-Defined Rules
Users can add their own custom rules to be used as part of Semgrep/Regex scanning. This configuration persists through shutdowns and restarts of VSCode.

### Dependency Checking
Supply chain attacks --> Want to ensure dependecies and modules imported are safe and not malicious. Given the inherent trust given to npm packages with no vulnerability scanning, it is important to check modules/packages.


When packages are installed/added, `package.json` is naturally modified in the process of installing/adding packages. VulnGuard scans all dependency packages listed in `package.json` whenever `package.json` is updated. Should packages be detected as malicious, warnings will be shown to the developer when viewing `package.json`.


Dependency Checking builds upon the work done by Spaceraccoon in [npm-scan](https://github.com/spaceraccoon/npm-scan) and other SDC (Simple Dependency Check) tools. The following documents the various heuristics used to determine if a package is malicious:

1. No Source Code Repository for package ([sdc-check](https://github.com/mbalabash/sdc-check))
2. Unmaintained Package (checks against NPM) ([sdc-check](https://github.com/mbalabash/sdc-check))
3. Unusually long time between releases for package (checks against NPM) ([sdc-check](https://github.com/mbalabash/sdc-check))
4. OS Scripts (.sh, .bat, etc.) found within packages ([sdc-check](https://github.com/mbalabash/sdc-check))
5. Fetching of Content Security Policy (CSP) ([npm-scan](https://github.com/spaceraccoon/npm-scan))
6. Creation of Child Processes ([npm-scan](https://github.com/spaceraccoon/npm-scan))
7. JJEncode Code Obfuscation ([npm-scan](https://github.com/spaceraccoon/npm-scan))
8. Unicode Code Obfuscation ([js-x-ray](https://github.com/NodeSecure/js-x-ray))
9. Package main module export is minified ([npm-scan](https://github.com/spaceraccoon/npm-scan))
10. Install Scripts found in manifest scripts ([npm-scan](https://github.com/spaceraccoon/npm-scan))
11. Shell Commands found in manifest scripts ([sdc-check](https://github.com/mbalabash/sdc-check))


Currently, user-defined rules and modules are not enabled through the GUI, but can be done manually. Currently, only user-defined Regex rules are supported. They follow the same format as Regex rules mentioned above. 


### Other Notes
- Semgrep is not supported on Windows at the moment, and so is automatically disabled on Windows computers.
- Semgrep can be automatically installed through the VSCode Extension using either `homebrew` or `pip`. If the installation fails however, one can refer to [Semgrep Docs](https://semgrep.dev/docs/getting-started/) on how to configure Semgrep for their system. 
- The demo was conducted in Linux.


### Assumptions made during Dependency Checks
Note: We only scan packages defined in `package.json` of the project. While this may sound like a problem, the following assumptions are made:
1) A maintained package will be able to resolve any malicious packages being used in its codebase (conversely, a package determined to be unmaintained should not be used at all).
2) A package with long intervals between releases is likely compromised and its modules are not updated, as such the package should not be used at all.