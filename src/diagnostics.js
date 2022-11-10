const vscode = require("vscode");
const Global = require("./globals");
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
    const diagnostics = docVulns.map((vuln) => {
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
      return {
        severity: SEVERITY[vuln.severity],
        range: range,
        message: vuln.message,
        source: "VulnGuard",
        code: {
          //kebab-case vuln id
          value: vuln.id
            .replace(/([a-z])([A-Z])/g, "$1-$2")
            .replace(/[\s_]+/g, "-")
            .toLowerCase(),
          target: vscode.Uri.parse("https://google.com"),
        },
        tags: vuln.fix ? [vuln.fix] : undefined,
      };
    });
    Global.vulnDiagnostics.set(editor.document.uri, diagnostics);
  });
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
