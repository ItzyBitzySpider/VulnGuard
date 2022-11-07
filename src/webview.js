const Feature = require("./feature");
const vscode = require("vscode");
const path = require("path");
const Icons = require("./webview-icons");
const { setFeature } = require("./settings");
const { getFeatureList } = require("./extension");

let panel = undefined;
let vulnguardLogo = undefined;
let styles = undefined;

const isWindows = process.platform === "win32";
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
        retainContextWhenHidden: true,
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
  const featureList = getFeatureList();

  panel.webview.html = `<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <link rel="stylesheet" type="text/css" href="${styles}" />
    <title>VulnGuard Dashboard</title>
  </head>
  <body style="padding: 10px">
    <script>
      (function () {
        const vscode = acquireVsCodeApi();
        window.addEventListener("input", (evt) => {
          const src = evt.srcElement;
          if (src.type === "checkbox") {
            vscode.postMessage({
              command: "checkbox",
              id: src.id.split("__checkbox")[0],
              value: src.checked,
            });
          }
        });
        window.addEventListener("click", function (evt) {
          const src = evt.srcElement;
          if(src.nodeName !== "BUTTON") return;
          const id = src.id.split("__button__");
          vscode.postMessage({
            command: "button",
            id: id[0],
            rule: id[1],
            value: id[2],
          });
        });
      })();
    </script>
    <div class="row">
      <div style="margin-right: 50px; width: 150px">
        <img src="${vulnguardLogo}" />
      </div>
      <div class="col" style="margin-right: 20px">
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
      <div style="flex: 1"></div>
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
      <div style="width:50px"></div>
    </div>
    <div class="divider"></div>
    <div class="column">
      <h2>Features</h2>
      ${featureList.reduce(
        (prev, curr) =>
          prev +
          `
      <div class="row">
        <label class="checkbox"
          >${curr.title}
          <input
            type="checkbox"
            id="${curr.id}__checkbox"
            checked="${curr.isEnabled()}" />
          <span class="checkmark"></span
        ></label>
      </div>
      `,
        ""
      )} 
      ${featureList.reduce(
        (prev, curr) =>
          prev +
          `
      <h2>${curr.title}</h2>
      <div class="entries">
        <div class="row">
          <p style="flex: 1">5/15 ${curr.title} Rules Enabled</p>
          <button id="${curr.id}__button__reset" type="button">
            ${Icons.redo}
          </button>
        </div>
        ${curr.rules.reduce(
          (prevRule, currRule) =>
            prevRule +
            `<div class="row">
        <p style="flex: 1">${currRule.title}</p>
        <button id="${curr.id}__button__${
              currRule.id
            }__button__${!currRule.isEnabled()}" type="button">
          ${currRule.isEnabled() ? Icons.disable : Icons.tick}
        </button>
      </div>`,
          ""
        )}
      </div>
      `,
        ""
      )}
    </div>
  </body>
</html>
`;

  panel.webview.onDidReceiveMessage(
    (message) => {
      switch (message.command) {
        case "checkbox":
          vscode.window.showInformationMessage(
            message.id + " " + message.value
          );
          setFeature(context, message.id, message.value);
          return;

        case "button":
          vscode.window.showInformationMessage(
            message.id + " " + message.rule + " " + message.value
          );
          return;
      }
    },
    undefined,
    context.subscriptions
  );
}

module.exports = {
  createWebview,
  updateWebview,
};
