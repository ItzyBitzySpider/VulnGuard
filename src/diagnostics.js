const vscode = require("vscode");
const Global = require("./globals");
const { toKebabCase } = require("./utils");

const SEVERITY = {
  ERROR: vscode.DiagnosticSeverity.Error,
  WARNING: vscode.DiagnosticSeverity.Warning,
  INFO: vscode.DiagnosticSeverity.Information,
};

/**
 *
 * @param {string[] | undefined} files
 */
function updateDiagnostics(files) {
  function update(docVulns, filePath) {
    vscode.workspace.openTextDocument(filePath).then((document) => {
      const diagnostics = [];
      docVulns.forEach((vuln) => {
        let range = undefined;
        if (vuln.range) {
          range = new vscode.Range(
            document.positionAt(vuln.range.start),
            document.positionAt(vuln.range.end)
          );
        } else {
          const line = document.lineAt(vuln.line_no).range;
          range = new vscode.Range(line.start, line.end);
        }
        if (isRuleDisabled(document, vuln)) return;
        diagnostics.push({
          severity: SEVERITY[vuln.severity],
          range: range,
          message: vuln.message,
          source: "VulnGuard",
          code: {
            value: toKebabCase(vuln.id),
            target: vuln.reference
              ? vscode.Uri.parse(vuln.reference)
              : vuln.id,
          },
          ...(vuln.fix && {tags: [vuln.fix] }),
        });
      });
      Global.vulnDiagnostics.set(document.uri, diagnostics);
    });
  }

  if (files)
    files.forEach((filePath) => {
      const docVulns = Global.vulns.get(filePath);
      if (docVulns) update(docVulns, filePath);
    });
  else Global.vulns.forEach(update);
}

/**
 *
 * @param {vscode.TextDocument} document
 */
function isRuleDisabled(document, vuln) {
  let lineNum = vuln.range
    ? document.positionAt(vuln.range.start).line
    : vuln.line_no;
  if (!lineNum) return false;
  const prevLine = document.lineAt(lineNum - 1).text;
  if (!prevLine.trimStart().startsWith("//")) return false;
  return (
    prevLine.includes("vulnguard-disable-*all*") ||
    prevLine.includes(`vulnguard-disable-${toKebabCase(vuln.id)}`)
  );
}

/**
 * @param {string} fsPath
 */
function handleChange(fsPath) {
  updateDiagnostics([fsPath]);
}

module.exports = {
  updateDiagnostics,
  handleChange,
  SEVERITY,
};
