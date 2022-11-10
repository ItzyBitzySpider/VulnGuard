const vscode = require("vscode");
const diagnostics = require("./diagnostics");
const findSemgrep = require("./findSemgrep");
const { createWebview, updateWebview } = require("./webview");
const { Feature, setFeatureContext } = require("./feature");
const Global = require("./globals");
const { FixVulnCodeActionProvider } = require("./codeaction");
const { setFeature, getFeatures, getUserRulesets } = require("./settings");
const { scanWorkspace, scanFile } = require("./scanTrigger");
const { renameVulns, deleteVulns } = require("./utils");
const {
  initScanner,
  regexRuleSetsScan,
  semgrepRuleSetsScan,
} = require("./scanner");

//TODO file opened state independent diagnostics

/**
 * @param {vscode.ExtensionContext} context
 */
async function activate(context) {
  console.log("VulnGuard has started and is running!");

  await findSemgrep(context);
  if (!Global.semgrepServer && getFeatures(context)["semgrep"])
    setFeature(context, "semgrep", false);

  initScanner(context);
  setFeatureContext(context);

  getUserRulesets(context);
  const featureList = Global.getFeatureList();
  if (Global.semgrepServer) {
    featureList.push(
      new Feature(
        "semgrep",
        "SemGrep",
        (file) => semgrepRuleSetsScan(Global.enabledSemgrepRuleSets, file),
        () => ({
          enabled: Global.enabledSemgrepRuleSets,
          all: Global.semgrepRuleSets,
        })
      )
    );
  }
  featureList.push(
    new Feature(
      "regex",
      "Regex",
      async (file) =>
        await regexRuleSetsScan(Global.enabledRegexRuleSets, file),
      () => ({
        enabled: Global.enabledRegexRuleSets,
        all: Global.regexRuleSets,
      })
    )
  );

  const watcher = vscode.workspace.createFileSystemWatcher("**/*.js");
  const vulnCodeActions = vscode.languages.registerCodeActionsProvider(
    { language: "javascript", scheme: "file" },
    new FixVulnCodeActionProvider()
  );

  scanWorkspace(context).then(() => {
    diagnostics.initWindowDiagnostics(
      vscode.window.visibleTextEditors,
      vscode.window.activeTextEditor
    );
    createWebview(context);
  });

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
        scanFile(context, event.document.uri.fsPath).then(() => {
          diagnostics.handleActiveEditorTextChange(event.document);
          updateWebview(context);
        });
      }, 1500);
    },
    null,
    context.subscriptions
  );
  // Change tab
  vscode.window.onDidChangeActiveTextEditor(
    diagnostics.handleChangeActiveEditor,
    null,
    context.subscriptions
  );
  vscode.workspace.onDidCloseTextDocument(
    diagnostics.handleDocumentClose,
    null,
    context.subscriptions
  );
  vscode.workspace.onDidRenameFiles(
    (event) => {
      event.files.forEach((f) => {
        if (f.oldUri.scheme === "file") {
          renameVulns(context, f.oldUri.fsPath, f.newUri.fsPath);
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
    vscode.commands.registerCommand("vulnguard.docs", (uri) =>
      vscode.env.openExternal(uri)
    ),
    //onCreate
    watcher.onDidCreate((uri) => {
      if (uri.scheme !== "file") return;
      scanFile(context, uri.fsPath).then(() => updateWebview(context));
    }),
    Global.vulnDiagnostics,
    vulnCodeActions
  );
}

// This method is called when your extension is deactivated
function deactivate() {}

module.exports = {
  activate,
  deactivate,
};
