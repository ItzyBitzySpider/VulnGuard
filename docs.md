# Some Documentation

### Semgrep Scanning
VulnGuard utilises [Semgrep (Semantic Grep)](https://semgrep.dev/) to perform scanning. Semgrep's [high performance](https://semgrep.dev/docs/faq/#besides-open-source-and-ease-of-writing-new-rules-what-else-is-different-about-semgrep), large userbase, and extensive database of community-curated rules makes it a powerful tool to detect vulnerabilities. Semgrep has multiple scanning modes, allowing for the use of static analysis, dynamic analysis (sinks and taints), and [much more](https://semgrep.dev/docs/writing-rules/experiments/introduction/). VulnGuard comes with various open-source rules enabled by default, but also allows for the users to add/import their own Semgrep rules/repositories.

Semgrep Rules are stored in YAML files, and follow [this format](https://semgrep.dev/docs/writing-rules/rule-syntax/).

For more examples, refer to the list of [VulnGuard's default Semgrep rules](#default-rules).

For information on how to add user-defined Semgrep rules/repositories, see [this](#user-defined-rules).

### Regex/Pattern Matching Scanning
For simpler rules that may not need Semgrep, Regex rules can be created. Regex rules perform Regex pattern matching on code files to look for vulnerabilities.

Regex Rules are stored in YAML files, and follow the following general format:
```yml
rules:
    # id (Mandatory) - ID for the Regex rule.
  - id: <string>

    # message (Mandatory) - Description to be provided to the user when the Regex pattern is matched.
    message: <string>

    # severity (Mandatory) - Either "INFO", "WARNING", or "ERROR".
    severity: <string>

    # regex (Mandatory) - Regex pattern to be checked.
    regex: <string>

    # case_sensitive (Optional) - Whether the Regex pattern provided should be compiled case sensitive.
    case_sensitive: <boolean>

    # fix (Optional) - Fix to be applied to the line in which the Regex pattern is matched.
    fix: <string>

    # reference (Optional) - Link for the user to find out more about the vulnerability.
    reference: <string>
```

VulnGuard also supports the use of the `regex_and`, `regex_or`, and `regex_not` fields, in addition to the nesting of multiple Regex patterns to form a Regex "tree". VulnGuard will iterate through files line-by-line, and whenever a line matches a Regex pattern/tree, the line will be highlighted to the user.

**Example 1**
```yml
# This rule is equivalent to the condition (A || B || C), where A, B, and C are Regex patterns.

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
# This rule is equivalent to the condition (A && B && (C || !D)), where A, B, C, and D are Regex patterns.

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

Note: VulnGuard does not support the matching of multi-line Regex patterns since Regex checking is done on a line-by-line basis.

For more examples, see [VulnGuard's default Regex rules](./files/regex_rules).

For information on how to add user-defined Regex rules, see [this](#user-defined-rules).

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

### User-Defined Rules
Users can add their own custom rules to be used as part of Semgrep/Regex scanning. This configuration persists through shutdowns and restarts of VSCode.


To add a custom rule, simply navigate to the VulnGuard Dashboard, click the "Plus" icon, and navigate to the YAML file containing the Semgrep/Regex rules to register it with VulnGuard.

USER_DEFINED_RULES_IMAGE

### Dependency Checking
When developing software, it is important to ensure that the dependencies imported are safe and not malicious. This is especially so for web development, given how web applications are inherently vulnerable to a wider range of threats due to web applications possessing a larger attack surface. This makes web applications much more susceptible to [Supply Chain Attacks](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/supply-chain-malware), where attackers try to compromise software by targeting less secure modules/packages used. Given the inherent trust given to npm packages with [limited vulnerability scanning](https://docs.npmjs.com/auditing-package-dependencies-for-security-vulnerabilities), it is important to check modules/packages in greater detail.


While it is important to check modules imported, VulnGuard only scans packages defined in `package.json` of the project (i.e. the "top-level" packages) for vulnerabilities. This is due to the fact that it is not necessarily optimal to check _all_ modules imported by an application, given how many imported modules will have their own dependencies, and so on. Although it may seem to be beneficial to check all the imported modules' dependencies as well, in reality, the vast majority of vulnerabilities found in these dependencies are ["unreachable"](https://snyk.io/blog/reachable-vulnerabilities/) and do not affect the application. This is further reinforced by the fact that secure "top-level" packages should be maintained, and be able to resolve any malicious/vulnerable packages being used in its codebase. Conversely, any unsecure "top-level" packages would be flagged out by VulnGuard and highlighted to the developer. Reducing the number of modules being checked by VulnGuard also has the added benefit of lowering the runtime for the dependency checks, ensuring that developers get the dependency check results faster.


When packages are installed/added, `package.json` is naturally modified in the process of installing/adding packages. VulnGuard scans all dependency packages listed in `package.json` whenever `package.json` is updated, and should packages be detected as malicious, warnings will be shown to the developer when viewing `package.json`.


VulnGuard's Dependency Checking builds upon the work done by Spaceraccoon in [npm-scan](https://github.com/spaceraccoon/npm-scan) and other SDC (Simple Dependency Check) tools. The following documents the various heuristics used to determine if a package is malicious:

**Time-Related Heuristics (checks against npm)**

1. Unmaintained Package ([sdc-check](https://github.com/mbalabash/sdc-check))
2. Unusually long time between releases for package ([sdc-check](https://github.com/mbalabash/sdc-check))

**Obfusication-Related Heuristics**

3. No Source Code Repository for package ([sdc-check](https://github.com/mbalabash/sdc-check))
4. JJEncode Code Obfuscation ([npm-scan](https://github.com/spaceraccoon/npm-scan))
5. Unicode Code Obfuscation ([js-x-ray](https://github.com/NodeSecure/js-x-ray))
6. Package main module export is minified ([npm-scan](https://github.com/spaceraccoon/npm-scan))

**Behavior-Related Heuristics**

7. OS Scripts (.sh, .bat, etc.) found within packages ([sdc-check](https://github.com/mbalabash/sdc-check))
8. Install Scripts found in manifest scripts ([npm-scan](https://github.com/spaceraccoon/npm-scan))
9. Shell Commands found in manifest scripts ([sdc-check](https://github.com/mbalabash/sdc-check))
10. Fetching of Content Security Policy (CSP) ([npm-scan](https://github.com/spaceraccoon/npm-scan))
11. Creation of Child Processes ([npm-scan](https://github.com/spaceraccoon/npm-scan))


### Performance

Ensuring VulnGuard's scan runtime is low is important to ensure that the Extension is responsive to changes in code made by the developer, so that they can be notified as soon as possible when they introduce a vulnerability. The following documents the ways that VulnGuard tries to achieve a low scan runtime:

1. All rule validation and compilation is done during initialization before any scans are performed.
2. All scans performed are done asynchronously on a per-file-per-rule basis.
3. The whole project is only scanned once as a whole during initialization, and afterwards, all subsequent scans on files are only done when they have been modified by the developer.
4. For dependency checking, only the top-level packages are being checked for vulnerabilities.

### Other Notes
- Semgrep is not supported on Windows at the moment, and so is automatically disabled on Windows environments.
- Semgrep can be automatically installed through the VSCode Extension using either `homebrew` or `pip`. If the installation fails however, one can refer to [Semgrep Docs](https://semgrep.dev/docs/getting-started/) on how to configure Semgrep for their system. 
- The demo was conducted in Linux to showcase VulnGuard's Semgrep functionality.