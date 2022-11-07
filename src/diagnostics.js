const vscode = require("vscode");
const { FIX_VULN_CODE } = require("./globals");

let activeEditor = undefined;

function clearDiagnostics(vulnDiagnostics) {
  if (activeEditor) vulnDiagnostics.clear();
}

function updateDiagnostics(vulnDiagnostics) {
  if (!activeEditor || !activeEditor.document) return;
  let text = activeEditor.document.getText();

  var startPosA = activeEditor.document.positionAt(100);
  var endPosA = activeEditor.document.positionAt(500);
  var startPosB = activeEditor.document.positionAt(700);
  var endPosB = activeEditor.document.positionAt(1000);

  console.log(vulnDiagnostics);
  vulnDiagnostics.set(activeEditor.document.uri, [
    {
      severity: vscode.DiagnosticSeverity.Information,
      range: {
        start: startPosA,
        end: endPosA,
      },
      message: "TEST MESSAGE",
      source: "VulnGuard",
      code: FIX_VULN_CODE,
    },
    {
      severity: vscode.DiagnosticSeverity.Information,
      range: {
        start: startPosB,
        end: endPosB,
      },
      message: "TEST MESSAGE TWO",
      source: "VulnGuard",
      code: FIX_VULN_CODE,
    },
  ]);
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
  if (activeEditor && event.document === activeEditor.document)
    updateDiagnostics(vulnDiagnostics);
  else clearDiagnostics(vulnDiagnostics);
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
};
