const vscode = require("vscode");
const Global = require("./globals");
const { toKebabCase } = require("./utils");
const { getVulns } = require("./vuln");

let activeEditor = undefined;

const SEVERITY = {
  ERROR: vscode.DiagnosticSeverity.Error,
  WARNING: vscode.DiagnosticSeverity.Warning,
  INFO: vscode.DiagnosticSeverity.Information,
};

function clearDiagnostics() {
  if (activeEditor) Global.vulnDiagnostics.clear();
}

/**
 *
 * @param {vscode.TextEditor[]} editors
 * @param {vscode.TextEditor} active
 */
function initWindowDiagnostics(editors, active) {
  activeEditor = active;
  updateDiagnostics(editors);
}

/**
 *
 * @param {vscode.TextEditor[]} editors
 * @returns
 */
function updateDiagnostics(editors) {
  if (!editors) return;
  editors.forEach((editor) => {
    const storedVulns = getVulns();
    if (!storedVulns.has(editor.document.uri.fsPath)) return;
    const docVulns = storedVulns.get(editor.document.uri.fsPath);
    const diagnostics = [];
    docVulns.forEach((vuln) => {
      let range = undefined;
      if (vuln.range) {
        range = new vscode.Range(
          editor.document.positionAt(vuln.range.start),
          editor.document.positionAt(vuln.range.end)
        );
      } else {
        const line = editor.document.lineAt(vuln.line_no).range;
        range = new vscode.Range(line.start, line.end);
      }
      if (isRuleDisabled(editor, vuln)) return;
      diagnostics.push({
        severity: SEVERITY[vuln.severity],
        range: range,
        message: vuln.message,
        source: "VulnGuard",
        code: {
          value: toKebabCase(vuln.id),
          target: vuln.reference ? vscode.Uri.parse(vuln.reference) : undefined,
        },
        tags: vuln.fix ? [vuln.fix] : undefined,
      });
    });
    Global.vulnDiagnostics.set(editor.document.uri, diagnostics);
  });
}

/**
 *
 * @param {vscode.TextEditor} editor
 */
function isRuleDisabled(editor, vuln) {
  let lineNum = vuln.range
    ? editor.document.positionAt(vuln.range.start).line
    : vuln.line_no;
  if (!lineNum) return false;
  const prevLine = editor.document.lineAt(lineNum - 1).text;
  if (!prevLine.trimStart().startsWith("//")) return false;
  return (
    prevLine.includes("vulnguard-disable-*all*") ||
    prevLine.includes(`vulnguard-disable-${toKebabCase(vuln.id)}`)
  );
}

/**
 * @param {vscode.TextEditor} editor
 */
function handleChangeActiveEditor(editor) {
  activeEditor = editor;
  if (editor) updateDiagnostics([editor]);
  else clearDiagnostics();
}

/**
 * @param {vscode.TextDocument} document
 */
function handleActiveEditorTextChange(document) {
  if (activeEditor && document === activeEditor.document) {
    updateDiagnostics([activeEditor]);
  } else clearDiagnostics();
}

/**
 * @param {vscode.TextDocument} document
 */
function handleDocumentClose(document) {
  Global.vulnDiagnostics.delete(document.uri);
}

module.exports = {
  initWindowDiagnostics,
  handleActiveEditorTextChange,
  handleChangeActiveEditor,
  handleDocumentClose,
};
