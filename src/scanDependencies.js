const vscode = require("vscode");
const Global = require("./globals");
const { SEVERITY } = require("./diagnostics");
const { toKebabCase } = require("./utils");
const { analyzePackage } = require("./scanner");

async function scanDependencies(file, context) {
  const analysis = await analyzePackage(context);

  //Delete duplicate IDs
  const packageMap = new Map();
  for (const [packageName, vulns] of Object.entries(analysis)) {
    const packageVulns = new Map();
    vulns.forEach((v) => {
      if (packageVulns.has(v.id)) return;
      packageVulns.set(v.id, v);
    });
    packageMap.set(packageName, packageVulns);
  }

  const uri = (await vscode.workspace.findFiles("package.json", null, 1))[0];

  const diagnostics = [];
  const doc = await vscode.workspace.openTextDocument(uri);
  const txt = doc.getText();
  packageMap.forEach((vulns, packageName) => {
    const searchStr = `"${packageName}"`;
    const start = txt.indexOf(searchStr);
    if (start === -1) return;
    const end = start + searchStr.length;
    const range = new vscode.Range(doc.positionAt(start), doc.positionAt(end));
    vulns.forEach((vuln, id) => {
      diagnostics.push({
        severity: SEVERITY[vuln.severity],
        range: range,
        message: `Unsafe package "${packageName}" - ` + vuln.message,
        source: "VulnGuard",
        code: {
          value: toKebabCase(id),
          target: vuln.reference ? vscode.Uri.parse(vuln.reference) : undefined,
        },
      });
    });
  });
  Global.vulnDiagnostics.set(uri, diagnostics);
}
module.exports = scanDependencies;
