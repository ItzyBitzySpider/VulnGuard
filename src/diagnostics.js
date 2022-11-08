const vscode = require("vscode");
const { FIX_VULN_CODE } = require("./globals");
const { getVulns } = require("./scanTrigger");

let activeEditor = undefined;

const SEVERITY = {
  ERROR: vscode.DiagnosticSeverity.Error,
  WARN: vscode.DiagnosticSeverity.Warning,
  INFO: vscode.DiagnosticSeverity.Information,
};
/**
 *
 * @param {vscode.DiagnosticCollection} vulnDiagnostics
 */
function clearDiagnostics(vulnDiagnostics) {
  if (activeEditor) vulnDiagnostics.clear();
}

/**
 *
 * @param {vscode.DiagnosticCollection} vulnDiagnostics
 * @param {vscode.TextEditor[]} editors
 * @param {vscode.TextEditor} active
 */
function initWindowDiagnostics(vulnDiagnostics, editors, active) {
  activeEditor = active;
  updateDiagnostics(vulnDiagnostics, editors);
}

/**
 *
 * @param {vscode.DiagnosticCollection} vulnDiagnostics
 * @param {vscode.TextEditor[]} editors
 * @returns
 */
function updateDiagnostics(vulnDiagnostics, editors) {
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
        tags: vuln.fix ? [FIX_VULN_CODE] : undefined,
      };
    });
    vulnDiagnostics.set(editor.document.uri, diagnostics);
  });
}

/**
 * @param {vscode.TextEditor} editor
 * @param {vscode.DiagnosticCollection} vulnDiagnostics
 */
function handleChangeActiveEditor(editor, vulnDiagnostics) {
  activeEditor = editor;
  if (editor) updateDiagnostics(vulnDiagnostics, [editor]);
  else clearDiagnostics(vulnDiagnostics);
}

/**
 * @param {vscode.TextDocument} document
 * @param {vscode.DiagnosticCollection} vulnDiagnostics
 */
function handleActiveEditorTextChange(document, vulnDiagnostics) {
  if (activeEditor && document === activeEditor.document) {
    updateDiagnostics(vulnDiagnostics, [activeEditor]);
  } else clearDiagnostics(vulnDiagnostics);
}

/**
 * @param {vscode.TextDocument} document
 * @param {vscode.DiagnosticCollection} vulnDiagnostics
 */
function handleDocumentClose(document, vulnDiagnostics) {
  vulnDiagnostics.delete(document.uri);
}

/**
 *
 * @param {vscode.Uri} uri
 * @param {vscode.DiagnosticCollection} vulnDiagnostics
 */
function handleFileDelete(uri, vulnDiagnostics) {
  if (uri.scheme !== "file") return;
  vulnDiagnostics.delete(uri);
}

module.exports = {
  initWindowDiagnostics,
  handleActiveEditorTextChange,
  handleChangeActiveEditor,
  handleDocumentClose,
  handleFileDelete,
};
