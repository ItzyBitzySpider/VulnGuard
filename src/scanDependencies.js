const vscode = require("vscode");
const Global = require("./globals");
const { SEVERITY } = require("./diagnostics");
const { toKebabCase } = require("./utils");
const { analyzePackage } = require("./scanner");
const { updateWebview } = require("./webview");

async function scanDependencies(file, context) {
  const analysis = await analyzePackage(context);

  // const analysis = {
  //   which: [
  //     {
  //       severity: "WARNING",
  //       range: { start: 15, end: 20 },
  //       message: "Child process creation",
  //       reference: "https://news.ycombinator.com/item?id=17283394",
  //       id: "child-process",
  //     },
  //     {
  //       severity: "WARNING",
  //       range: { start: 15, end: 20 },
  //       message: "Child process creation",
  //       reference: "https://news.ycombinator.com/item?id=17283394",
  //       id: "child-process",
  //     },
  //   ],
  // };

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
          target: vuln.reference ? vscode.Uri.parse(vuln.reference) : id,
        },
      });
    });
  });
  Global.vulnDiagnostics.set(uri, diagnostics);
  Global.unsafePackages = packageMap.size;
  updateWebview(context);
}
module.exports = scanDependencies;
