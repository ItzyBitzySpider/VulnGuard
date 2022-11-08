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
 */
function updateDiagnostics(vulnDiagnostics) {
  if (!activeEditor || !activeEditor.document) return;

  const storedVulns = getVulns();
  if (!storedVulns.has(activeEditor.document.uri.fsPath)) return;
  const docVulns = storedVulns.get(activeEditor.document.uri.fsPath);
  const diagnostics = docVulns.map((vuln) => {
    let range = undefined;
    if (vuln.range) {
      range = new vscode.Range(
        activeEditor.document.positionAt(vuln.range.start),
        activeEditor.document.positionAt(vuln.range.end)
      );
    } else {
      const line = activeEditor.document.lineAt(vuln.line_no).range;
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
  vulnDiagnostics.set(activeEditor.document.uri, diagnostics);
}

/**
 * @param {vscode.TextEditor} editor
 * @param {vscode.DiagnosticCollection} vulnDiagnostics
 */
function handleChangeActiveEditor(editor, vulnDiagnostics) {
  activeEditor = editor;
  if (editor) updateDiagnostics(vulnDiagnostics);
  else clearDiagnostics(vulnDiagnostics);
}

/**
 * @param {vscode.TextDocumentChangeEvent} event
 * @param {vscode.DiagnosticCollection} vulnDiagnostics
 */
function handleActiveEditorTextChange(event, vulnDiagnostics) {
  if (activeEditor && event.document === activeEditor.document) {
    updateDiagnostics();
  } else clearDiagnostics(vulnDiagnostics);
}

/**
 * @param {vscode.TextDocument} document
 * @param {vscode.DiagnosticCollection} vulnDiagnostics
 */
function handleDocumentClose(document, vulnDiagnostics) {
  vulnDiagnostics.delete(document.uri);
}

// TODO Config Change
// function handleChangeConfig() {
// const settings = vscode.workspace.getConfiguration("vulnguard");
// if (!settings.get('isEnable')) return;
//       init(settings);
//       triggerUpdateDecorations();
// }

module.exports = {
  handleActiveEditorTextChange,
  handleChangeActiveEditor,
  handleDocumentClose,
};
