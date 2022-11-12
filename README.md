# VulnGuard
VSCode extension to lint code for security vulnerabilities.

INSERT_VIDEO_HERE

[Watch on Youtube]()

## Usage (or maybe called Install???)

## Features
### Vulnerability Scanning
VulnGuard scans your Node.js projects for security vulnerabilities on-the-fly as you type code. The goal is to notify developers as they are introducing a security vulnerability in order to fix the issue at the point of introduction.

Currently, VulnGuard supports 3 types of checks:
- Semgrep (Not available on Windows systems)
- Regex
- Dependency Scanning

### Viewing 

### Ignoring Specific Lines
Using VSCode Quick Fix, you can disable VulnGuard or even specific ruleset(s) on a line (similar to ESLint).

### Configuration
You can disable specific rulesets, specify which files to ignore via glob patterns, and even configure which checks to run entirely within the VulnGuard Dashboard GUI.

![VulnGuard Dashboard](media/vulnguard.png)

### How It Works
You can read more about what's under the hood in [docs.md](./docs.md).

## Pitch
Something somethibg about scanning code

**Q. So how does VulnGuard help prevent such incidents?**
A. VulnGuard shift-left lah, etc etc

**Q. How is this different from other scanners out there**
A. VulnGuard incorporates the best elements of existing scanners and solutions on the market. etc etc. In addition, VulnGuard incorporates dependency checking based on heuristics. This builds upon the existing work done by space rac etc etc

## Future

In future, we unga bunga AI lmfao

## References
- https://github.com/microsoft/DevSkim
- https://github.com/spaceraccoon/npm-scan/
- https://github.com/NodeSecure/js-x-ray
- https://github.com/mbalabash/sdc-check
- https://github.com/insidersec/insider
- https://github.com/ajinabraham/njsscan
