const vscode = require("vscode");
const diagnostics = require("./diagnostics");
const findSemgrep = require("./findSemgrep");
const { createWebview, updateWebview } = require("./webview");
const { Feature, setFeatureContext } = require("./feature");
const Global = require("./globals");
const {
  FixVulnCodeActionProvider,
  UnsafePackageCodeActionProvider,
} = require("./codeaction");
const { setFeature, getFeatures, getUserRulesets } = require("./settings");
const { scanWorkspace, scanFile } = require("./scanTrigger");
const { renameVulns, deleteVulns } = require("./utils");
const {
  initScanner,
  initDependencyScanner,
  regexRuleSetsScan,
  semgrepRuleSetsScan,
} = require("./scanner");
const scanDependencies = require("./scanDependencies");
const { exit } = require("process");
const fs = require("fs");

/**
 * @param {vscode.ExtensionContext} context
 */
async function activate(context) {
  if (!(await vscode.workspace.findFiles("package.json", null, 1)).length) {
    console.warn(
      "VulnGuard shutting down as package.json not found in workspace."
    );
    exit(0);
  }
  console.log("VulnGuard has started and is running!");

  await findSemgrep(context);
  if (!Global.semgrepServer && getFeatures(context)["semgrep"])
    setFeature(context, "semgrep", false);

  initScanner(context);
  initDependencyScanner(context);
  setFeatureContext(context);

  getUserRulesets(context);
  const featureList = Global.getFeatureList();
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
  featureList.push(
    new Feature(
      "dependency",
      "unsecure Dependencies",
      (file) => scanDependencies(file, context),
      () => ({
        enabled: Global.dependencyRegexRuleSets,
        all: Global.dependencyRegexRuleSets,
      })
    )
  );

  const packageJsonWatcher =
    vscode.workspace.createFileSystemWatcher("**/package.json");
  const packageCodeActions = vscode.languages.registerCodeActionsProvider(
    { language: "json", pattern: "package.json" },
    new UnsafePackageCodeActionProvider()
  );

  const watcher =
    vscode.workspace.createFileSystemWatcher("{**/*.js,**/*.ejs}");
  const vulnCodeActions = vscode.languages.registerCodeActionsProvider(
    { language: "javascript", scheme: "file" },
    new FixVulnCodeActionProvider()
  );

  scanWorkspace(context, "**/*.js").then(() => {
    diagnostics.updateDiagnostics();
    createWebview(context);
  });

  scanWorkspace(context, "**/package.json", ["dependency"]);
  //onCreate
  watcher.onDidCreate(
    (uri) => {
      if (uri.scheme !== "file") return;
      scanFile(context, uri.fsPath).then(() => {
        diagnostics.handleChange(uri.fsPath);
        updateWebview(context);
      });
    },
    null,
    context.subscriptions
  );
  //onSave
  watcher.onDidChange(
    (uri) => {
      if (uri.scheme !== "file") return;
      scanFile(context, uri.fsPath).then(() => {
        diagnostics.handleChange(uri.fsPath);
        updateWebview(context);
      });
    },
    null,
    context.subscriptions
  );

  //onCreate
  packageJsonWatcher.onDidCreate(
    (uri) => {
      if (uri.scheme !== "file") return;
      scanFile(context, uri.fsPath, ["dependency"]).then(() => {
        diagnostics.handleChange(uri.fsPath);
        updateWebview(context);
      });
    },
    null,
    context.subscriptions
  );
  //onSave
  let prevPackageJson = undefined;
  packageJsonWatcher.onDidChange(
    async (uri) => {
      if (uri.scheme !== "file") return;
      try {
        const packageJson = JSON.parse(fs.readFileSync(uri.fsPath, "utf8"));
        if (prevPackageJson) {
          if (
            JSON.stringify(packageJson.dependencies) ===
              JSON.stringify(prevPackageJson.dependencies) &&
            JSON.stringify(packageJson.devDependencies) ===
              JSON.stringify(prevPackageJson.devDependencies)
          )
            return;
        }
        prevPackageJson = packageJson;
        scanFile(context, uri.fsPath, ["dependency"]).then(() => {
          diagnostics.handleChange(uri.fsPath);
          updateWebview(context);
        });
      } catch (e) {
        console.warn(e.message);
      }
    },
    null,
    context.subscriptions
  );

  //onEdit
  // let changeTimer;
  // vscode.workspace.onDidChangeTextDocument(
  //   (event) => {
  //     if (changeTimer) clearTimeout(changeTimer);
  //     changeTimer = setTimeout(() => {
  //       scanFile(context, event.document.uri.fsPath).then(() => {
  //         diagnostics.handleChange(event.document.uri.fsPath);
  //         updateWebview(context);
  //       });
  //     }, 1500);
  //   },
  //   null,
  //   context.subscriptions
  // );
  // Change tab
  // vscode.window.onDidChangeActiveTextEditor(
  //   diagnostics.handleChangeActiveEditor,
  //   null,
  //   context.subscriptions
  // );
  // vscode.workspace.onDidCloseTextDocument(
  //   diagnostics.handleDocumentClose,
  //   null,
  //   context.subscriptions
  // );
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
    (event) => event.files.forEach((uri) => deleteVulns(uri)),
    null,
    context.subscriptions
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("itzybitzyspider.vulnguard.dashboard", () =>
      createWebview(context)
    ),
    vscode.commands.registerCommand("itzybitzyspider.vulnguard.docs", (uri) =>
      vscode.env.openExternal(uri)
    ),
    Global.vulnDiagnostics,
    vulnCodeActions,
    packageCodeActions
  );
}

// This method is called when your extension is deactivated
function deactivate() {}

module.exports = {
  activate,
  deactivate,
};
