// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
const vscode = require("vscode");
const diagnostics = require("./diagnostics");
const semgrep = require("./semgrep");
const { createWebview } = require("./webview");
const { Feature, setFeatureContext } = require("./feature");

const featureList = [];

/**
 * @param {vscode.ExtensionContext} context
 */
async function activate(context) {
  console.log("VulnGuard has started and is running!");

  const semgrepServer = await semgrep.findSemgrep(context);

  setFeatureContext(context);

  featureList.push(
    new Feature("semgrep", "SemGrep", (filename) => {}, [
      {
        id: "sr1",
        title: "tt1",
        description: "test trr",
        enabled: false,
        severity: "ERROR",
      },
      ,
    ])
  );
  featureList.push(
    new Feature("regex", "Regex", (filename) => {}, [
      {
        id: "rr1",
        title: "t1",
        description: "test rr",
        enabled: true,
        severity: "WARN",
      },
      {
        id: "rr2",
        title: "t2",
        description: "test rr",
        enabled: false,
        severity: "INFO",
      },
      {
        id: "rr3",
        title: "t3",
        description: "test rr",
        enabled: true,
        severity: "WARN",
      },
    ])
  );

  const vulnDiagnostics = vscode.languages.createDiagnosticCollection("vulns");
  const watcher = vscode.workspace.createFileSystemWatcher("**/*.js");

  //onSave active document
  vscode.workspace.onDidSaveTextDocument(
    (event) => {
      if (event.uri.scheme !== "file") return;
      console.log(event.uri);
    },
    null,
    context.subscriptions
  );
  //onEdit
  vscode.workspace.onDidChangeTextDocument(
    (event) => diagnostics.handleActiveEditorTextChange(event, vulnDiagnostics),
    null,
    context.subscriptions
  );
  //Change tab
  vscode.window.onDidChangeActiveTextEditor(
    (editor) => diagnostics.handleChangeActiveEditor(editor, vulnDiagnostics),
    null,
    context.subscriptions
  );
  // TODO handle config change
  // vscode.workspace.onDidChangeConfiguration(
  //   () => {
  // settings = workspace.getConfiguration('todohighlight');

  // //NOTE: if disabled, do not re-initialize the data or we will not be able to clear the style immediately via 'toggle highlight' command
  // if (!settings.get('isEnable')) return;

  // init(settings);
  // triggerUpdateDecorations();

  //     console.log("HERE3");
  //   },
  //   null,
  //   context.subscriptions
  // );

  context.subscriptions.push(
    vscode.commands.registerCommand("vulnguard.dashboard", () =>
      createWebview(context)
    ),
    //onSave
    watcher.onDidChange((uri) => {
      if (uri.scheme !== "file") return;
      console.log(uri);
    }),
    //onCreate
    watcher.onDidCreate((uri) => {
      if (uri.scheme !== "file") return;
      console.log(uri);
    }),
    //onDelete
    watcher.onDidDelete((uri) => {
      if (uri.scheme !== "file") return;
      console.log(uri);
    }),
    vulnDiagnostics
  );
}

// This method is called when your extension is deactivated
function deactivate() {}

module.exports = {
  activate,
  deactivate,
  featureList,
};
