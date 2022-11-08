const vscode = require("vscode");
const diagnostics = require("./diagnostics");
const semgrep = require("./semgrep");
const { createWebview } = require("./webview");
const { Feature, setFeatureContext, Rule } = require("./feature");
const Global = require("./globals");
const { FixVulnCodeActionProvider } = require("./codeaction");
const { setFeature, getFeatures } = require("./settings");
const { scanWorkspace, scanFile, renameVulns } = require("./scanTrigger");

//TODO interrupt scan process
//TODO webview read for stats; Disable tick

/**
 * @param {vscode.ExtensionContext} context
 */
async function activate(context) {
  console.log("VulnGuard has started and is running!");

  const semgrepServer = await semgrep.findSemgrep(context);
  if (!semgrepServer && getFeatures(context)["semgrep"])
    setFeature(context, "semgrep", false);

  setFeatureContext(context);

  let tmpVar = 0;

  const featureList = Global.getFeatureList();
  featureList.push(
    new Feature(
      "semgrep",
      "SemGrep",
      (file) => {
        return {
          start: 50,
          end: 100,
          severity: "ERROR",
          message: "SemGrep Rule Caught",
        };
      },
      [new Rule("sr1", "tt1", "test trr", "ERROR")]
    )
  );
  featureList.push(
    new Feature(
      "regex",
      "Regex",
      (file) => {
        if (tmpVar > 11) tmpVar = 0;
        switch (tmpVar++ % 4) {
          case 0:
            return;
          case 1:
            return {
              id: "id1",
              range: {
                start: tmpVar * 5,
                end: (tmpVar + 1) * 5 - 2,
              },
              fix: "<some random fixed code>",
              severity: "ERROR",
              message: "Regex Err Caught",
            };
          case 2:
            return {
              id: "id2",
              line_no: tmpVar * 2,
              fix: "<some random fixed code>",
              severity: "WARN",
              message: "Regex Warn Caught",
            };
          case 3:
            return {
              id: "id3",
              range: {
                start: tmpVar * 5,
                end: (tmpVar + 1) * 5 - 2,
              },
              severity: "INFO",
              message: "Regex Info Caught",
            };
        }
      },
      [
        new Rule("rr1", "t1", "test rr", "WARN"),
        new Rule("rr2", "t2", "test rr", "INFO"),
        new Rule("rr3", "t3", "test rr", "ERROR"),
      ]
    )
  );

  const watcher = vscode.workspace.createFileSystemWatcher("**/*.js");
  const vulnDiagnostics = vscode.languages.createDiagnosticCollection("vulns");
  const vulnCodeActions = vscode.languages.registerCodeActionsProvider(
    { language: "javascript", scheme: "file" },
    new FixVulnCodeActionProvider()
  );

  scanWorkspace(context).then(() =>
    diagnostics.initWindowDiagnostics(
      vulnDiagnostics,
      vscode.window.visibleTextEditors,
      vscode.window.activeTextEditor
    )
  );

  //onSave active document
  // vscode.workspace.onDidSaveTextDocument(
  //   (event) => {
  //     if (event.uri.scheme !== "file") return;
  //     console.log(event.uri);
  //   },
  //   null,
  //   context.subscriptions
  // );

  //onEdit
  vscode.workspace.onDidChangeTextDocument(
    (event) => {
      console.log("TT");
      if (changeTimer) clearTimeout(changeTimer);
      changeTimer = setTimeout(() => {
        console.log("Scanning");
        scanFile(event.document.uri.fsPath).then(() =>
          diagnostics.handleActiveEditorTextChange(
            event.document,
            vulnDiagnostics
          )
        );
      }, 1500);
    },
    null,
    context.subscriptions
  );
  // Change tab
  vscode.window.onDidChangeActiveTextEditor(
    (editor) => diagnostics.handleChangeActiveEditor(editor, vulnDiagnostics),
    null,
    context.subscriptions
  );
  vscode.workspace.onDidCloseTextDocument(
    (document) => diagnostics.handleDocumentClose(document, vulnDiagnostics),
    null,
    context.subscriptions
  );
  vscode.workspace.onDidRenameFiles(
    (event) => {
      event.files.forEach((f) => {
        if (f.oldUri.scheme === "file")
          renameVulns(f.oldUri.fsPath, f.newUri.fsPath);
      });
    },
    null,
    context.subscriptions
  );

  let changeTimer;
  context.subscriptions.push(
    vscode.commands.registerCommand("vulnguard.dashboard", () =>
      createWebview(context)
    ),
    //onCreate
    watcher.onDidCreate((uri) => {
      if (uri.scheme !== "file") return;
      scanFile(uri.fsPath);
    }),
    //onDelete
    watcher.onDidDelete((uri) =>
      diagnostics.handleFileDelete(uri, vulnDiagnostics)
    ),
    vulnDiagnostics,
    vulnCodeActions
  );
}

// This method is called when your extension is deactivated
function deactivate() {}

module.exports = {
  activate,
  deactivate,
};
