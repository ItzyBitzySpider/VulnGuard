const Feature = require("./feature");
const vscode = require("vscode");
const path = require("path");
const Icons = require("./webview-icons");

let panel = undefined;
let vulnguardLogo = undefined;
let styles = undefined;

function createWebview(context) {
  const columnToShowIn = vscode.window.activeTextEditor
    ? vscode.window.activeTextEditor.viewColumn
    : undefined;

  if (panel) panel.reveal(columnToShowIn);
  else {
    panel = vscode.window.createWebviewPanel(
      "vulnGuard",
      "VulnGuard Dashboard",
      vscode.ViewColumn.One,
      {
        localResourceRoots: [
          vscode.Uri.file(path.join(context.extensionPath, "media")),
        ],
        enableScripts: true,
      }
    );
    vulnguardLogo = panel.webview.asWebviewUri(
      vscode.Uri.file(
        path.join(context.extensionPath, "media", "vulnguard.png")
      )
    );
    styles = panel.webview.asWebviewUri(
      vscode.Uri.file(path.join(context.extensionPath, "media", "styles.css"))
    );
    panel.onDidDispose(
      () => {
        panel = undefined;
      },
      null,
      context.subscriptions
    );
  }
  updateWebview(context);
}

/**
 *
 * @param {vscode.ExtensionContext} context
 */
function updateWebview(context) {
  const { featureList } = require("./extension");
  console.log(featureList);
  for (const x of featureList) {
    console.log(x);
  }
  panel.webview.html = `<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <link rel="stylesheet" type="text/css" href="${styles}" />
    <title>VulnGuard Dashboard</title>
  </head>
  <body style="padding: 10px">
    <div class="row">
      <div style="margin-right: 50px"><img src="${vulnguardLogo}" /></div>
      <div class="col">
        <h1>VulnGuard</h1>
        <div class="row">
          <p>Version</p>
          <div class="version-box">
            <p style="font-size: 1rem">
              ${context.extension.packageJSON.version}
            </p>
          </div>
        </div>
      </div>
      <div class="col count">
        <h1>5</h1>
        <h3>Errors</h3>
      </div>
      <div class="col count">
        <h1>52</h1>
        <h3>Warnings</h3>
      </div>
      <div class="col count">
        <h1>515</h1>
        <h3>Alerts</h3>
      </div>
    </div>
    <div class="divider"></div>
    <div class="column">
      <h2>Features</h2>
      ${featureList.reduce((prev, curr) => {
        return (
          prev +
          `
      <div class="row">
        <label class="checkbox"
          >${curr.title}
          <input type="checkbox" checked="${curr.enabled}" />
          <span class="checkmark"></span
        ></label>
      </div>
      `
        );
      }, "")} ${featureList.reduce((prev, curr) => {
    return (
      prev +
      `
      <h2>${curr.title}</h2>
      <div class="entries">
        <div>Modify ${curr.title} Rules</div>
        <div>Modify or edit header</div>
        <div>Modify or edit header</div>
        <div>Modify or edit header</div>
      </div>
      `
    );
  }, "")}
    </div>
  </body>
</html>`;
}

module.exports = {
  createWebview,
  updateWebview,
};
