const vscode = require("vscode");
const diagnostics = require("./diagnostics");
const findSemgrep = require("./findSemgrep");
const { createWebview, updateWebview } = require("./webview");
const { Feature, setFeatureContext } = require("./feature");
const Global = require("./globals");
const { FixVulnCodeActionProvider } = require("./codeaction");
const { setFeature, getFeatures } = require("./settings");
const { scanWorkspace, scanFile } = require("./scanTrigger");
const { renameVulns, deleteVulns } = require("./vuln");
const { initScanner, regexRuleSetsScan } = require("./scanner");

//TODO use fix property to fix code

/**
 * @param {vscode.ExtensionContext} context
 */
async function activate(context) {
  console.log("VulnGuard has started and is running!");

  await findSemgrep(context);
  if (!Global.semgrepServer && getFeatures(context)["semgrep"])
    setFeature(context, "semgrep", false);

  await initScanner(context);
  setFeatureContext(context);

  let tmpVar = 0;
  const featureList = Global.getFeatureList();
  featureList.push(
    new Feature(
      "tester",
      "Test Feature",
      async (file) => {
        const x = await regexRuleSetsScan(Global.enabledRegexRuleSets, file);
        return x;
      },
      () => ({
        enabled: Global.enabledRegexRuleSets,
        all: Global.regexRuleSets,
      })
    )
  );
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
      () => ({
        enabled: [{ path: "sr1", ruleSet: [] }],
        all: [
          { path: "sr1", ruleSet: [] },
          { path: "sr2", ruleSet: [] },
        ],
      })
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
              severity: "WARNING",
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
      () => ({
        enabled: [
          { path: "rr1", ruleSet: [] },
          { path: "rr3", ruleSet: [] },
        ],
        all: [
          { path: "rr1", ruleSet: [] },
          { path: "rr2", ruleSet: [] },
          { path: "rr3", ruleSet: [] },
        ],
      })
    )
  );

  const watcher = vscode.workspace.createFileSystemWatcher("**/*.js");
  const vulnDiagnostics = vscode.languages.createDiagnosticCollection("vulns");
  const vulnCodeActions = vscode.languages.registerCodeActionsProvider(
    { language: "javascript", scheme: "file" },
    new FixVulnCodeActionProvider()
  );

  // TODO possibly scan entire workspace on start?
  // scanWorkspace(context).then(() => {
  //   diagnostics.initWindowDiagnostics(
  //     vulnDiagnostics,
  //     vscode.window.visibleTextEditors,
  //     vscode.window.activeTextEditor
  //   );
  //   updateWebview(context);
  // });

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
  let changeTimer;
  vscode.workspace.onDidChangeTextDocument(
    (event) => {
      if (changeTimer) clearTimeout(changeTimer);
      changeTimer = setTimeout(() => {
        scanFile(event.document.uri.fsPath).then(() => {
          diagnostics.handleActiveEditorTextChange(
            event.document,
            vulnDiagnostics
          );
          updateWebview(context);
        });
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
        if (f.oldUri.scheme === "file") {
          renameVulns(f.oldUri.fsPath, f.newUri.fsPath);
        }
      });
    },
    null,
    context.subscriptions
  );
  //onDelete
  vscode.workspace.onDidDeleteFiles(
    (event) => {
      event.files.forEach((uri) => deleteVulns(uri));
    },
    null,
    context.subscriptions
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("vulnguard.dashboard", () =>
      createWebview(context)
    ),
    //onCreate
    watcher.onDidCreate((uri) => {
      if (uri.scheme !== "file") return;
      scanFile(uri.fsPath).then(() => updateWebview(context));
    }),
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
