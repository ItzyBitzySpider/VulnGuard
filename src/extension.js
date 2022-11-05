// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
const vscode = require("vscode");
const highlight = require("./diagnostics");

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
  console.log("VulnGuard has started and is running!");

  // The command has been defined in the package.json file
  // Now provide the implementation of the command with  registerCommand
  // The commandId parameter must match the command field in package.json
  let disposable = vscode.commands.registerCommand(
    "vulnguard.helloWorld",
    function () {
      // The code you place here will be executed every time your command is executed

      // Display a message box to the user
      vscode.window.showInformationMessage("Hello World from VulnGuard!");
    }
  );

  const vulnDiagnostics = vscode.languages.createDiagnosticCollection("vulns");
  const watcher = vscode.workspace.createFileSystemWatcher("**/*.js");

  //onSave active document
  vscode.workspace.onDidSaveTextDocument((event) => {
    if (event.uri.scheme !== "file") return;
    console.log(event.uri);
  });
  //onEdit
  vscode.workspace.onDidChangeTextDocument(
    (event) => highlight.handleActiveEditorTextChange(event, vulnDiagnostics),
    null,
    context.subscriptions
  );
  //Change tab
  vscode.window.onDidChangeActiveTextEditor(
    (editor) => highlight.handleChangeActiveEditor(editor, vulnDiagnostics),
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
    disposable,
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
};
