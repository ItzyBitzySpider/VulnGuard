// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
const vscode = require("vscode");
const diagnostics = require("./diagnostics");
const semgrep = require("./semgrep");
const { createWebview } = require("./webview");
const { Feature, setFeatureContext, Rule } = require("./feature");
const Global = require("./globals");
const { FixVulnCodeActionProvider } = require("./codeaction");

/**
 * @param {vscode.ExtensionContext} context
 */
async function activate(context) {
  console.log("VulnGuard has started and is running!");

  const semgrepServer = await semgrep.findSemgrep(context);

  setFeatureContext(context);

  const featureList = Global.getFeatureList();
  featureList.push(
    new Feature("semgrep", "SemGrep", () => {}, [
      new Rule("sr1", "tt1", "test trr", "ERROR"),
    ])
  );
  featureList.push(
    new Feature("regex", "Regex", () => {}, [
      new Rule("rr1", "t1", "test rr", "WARN"),
      new Rule("rr2", "t2", "test rr", "INFO"),
      new Rule("rr3", "t3", "test rr", "ERROR"),
    ])
  );

  const watcher = vscode.workspace.createFileSystemWatcher("**/*.js");
  const vulnDiagnostics = vscode.languages.createDiagnosticCollection("vulns");
  // const vulnCodeActions = vscode.languages.registerCodeActionsProvider(
  //   "**/*.js",
  //   {
  //     provideCodeActions: (doc, range, ctx, cancellationToken) => {
  //       console.log(doc.fileName, range.start, range.end);
  //       return [
  //         {
  //           title: "TITLE",
  //           kind: vscode.CodeActionKind.QuickFix,
  //           diagnostics: vulnDiagnostics,
  //           edit: (a, b) => {
  //             console.log(a, b);
  //           },
  //           arguments: [doc, range],
  //         },
  //       ];
  //     },
  //     resolveCodeAction: (codeAction, cancellationToken) => {
  //       console.log("SELECTED", codeAction);
  //     },
  //   },
  //   { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
  // );
  const vulnCodeActions = vscode.languages.registerCodeActionsProvider(
    { language: "typescript", scheme: "file" },
    new FixVulnCodeActionProvider()
  );

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
    vscode.commands.registerCommand("vulnguard.fixvuln", () =>
      console.log("FIX VULN")
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
