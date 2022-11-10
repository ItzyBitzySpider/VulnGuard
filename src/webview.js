const vscode = require("vscode");
const path = require("path");
const Icons = require("./webview-icons");
const {
  setFeature,
  getIgnoredRegex,
  addIgnoredRegex,
  deleteIgnoredRegex,
  addUserRuleset,
} = require("./settings");
const Global = require("./globals");
const { getTitleFromPath, Feature } = require("./feature");
const { enableRuleSet, disableRuleSet } = require("./scanner");

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

  panel.webview.onDidReceiveMessage(
    (message) => {
      switch (message.command) {
        case "checkbox":
          setFeature(context, message.id, message.value);
          vscode.window.showInformationMessage(
            "VulnGuard: Feature selection saved"
          );
          return;

        case "button":
          //Ignored files related commands
          if (message.id === "ignore") {
            if (message.rule === "add")
              vscode.window
                .showInputBox({
                  placeHolder: "e.g. tmp/*.js",
                  prompt: "Add VulnGuard ignore regex",
                  value: "",
                })
                .then((query) => {
                  if (!query || query === "" || query.includes(",")) {
                    vscode.window.showInformationMessage(
                      "VulnGuard: Ignored directory not added as an error occurred."
                    );
                    return;
                  }
                  addIgnoredRegex(context, query);
                  vscode.window.showInformationMessage(
                    "VulnGuard: Ignored directory added"
                  );
                  updateWebview(context);
                });
            else if (!Number.isNaN(message.rule)) {
              const idx = parseInt(message.rule);
              if (idx >= 0 && idx < getIgnoredRegex(context).length) {
                deleteIgnoredRegex(context, idx);
                vscode.window.showInformationMessage(
                  "VulnGuard: Ignored directory deleted"
                );
                updateWebview(context);
              } else
                vscode.window.showInformationMessage(
                  `VulnGuard: An error occurred when deleting ignored directory at ${idx}`
                );
            }
          } else {
            if (message.rule === "add-ruleset") {
              vscode.window
                .showOpenDialog({
                  canSelectFiles: true,
                  openLabel: "Select File",
                  title: "Add Ruleset",
                  filters: { "YAML Config": ["yml", "yaml"] },
                })
                .then(
                  (value) => {
                    if (!value) {
                      vscode.window.showWarningMessage(
                        "Ruleset not added. No file selected."
                      );
                      return;
                    }
                    addUserRuleset(context, message.id, value[0].path);
                    updateWebview(context);
                    vscode.window.showInformationMessage("Ruleset added");
                  },
                  (reason) => {
                    vscode.window.showWarningMessage(
                      "Ruleset not added.",
                      reason
                    );
                  }
                );
            } else {
              //Enabling/disabling rules
              message.value === "true"
                ? enableRuleSet(context, message.rule)
                : disableRuleSet(context, message.rule);
              updateWebview(context);
            }
          }
          return;
      }
    },
    undefined,
    context.subscriptions
  );
  updateWebview(context);
}

/**
 *
 * @param {Feature} feature
 * @returns {string}
 */
function getFeatureEntries(feature) {
  const rulesetData = feature.getRulesetData();
  let entries = "";
  rulesetData.rulesets.forEach((enabled, path) => {
    entries += `<div class="row">
    <p class="${enabled ? "" : "disabled"}" style="flex: 1">${getTitleFromPath(
      path
    )}</p>
    <button id="${
      feature.id
    }__button__${path}__button__${!enabled}" type="button">
      ${enabled ? Icons.disable : Icons.tick}
    </button>
  </div>`;
  });
  return `<h2>${feature.title}</h2>
  ${
    feature.id === "semgrep" && (isWindows || !Global.semgrepServer)
      ? `<p style="margin-top:-10px;margin-bottom:15px;color:#71717a">${feature.title} disabled on Windows</p>`
      : ""
  }
  <div class="entries">
    <div class="row">
      <p style="flex: 1">${rulesetData.enabled} of ${rulesetData.total} ${
    feature.title
  } Rule(s) Enabled</p>
    <button id="${feature.id}__button__add-ruleset" type="button">
      ${Icons.add}
    </button>
    </div>
    ${entries}
  </div>
  `;
}

/**
 *
 * @param {vscode.ExtensionContext} context
 */
function updateWebview(context) {
  if (!panel) return;

  const featureList = Global.getFeatureList();
  const ignoredRegex = getIgnoredRegex(context);
  let error = 0,
    warning = 0,
    alert = 0;
  Global.vulns.forEach((v) => {
    v.forEach((vuln) => {
      switch (vuln.severity) {
        case "ERROR":
          error++;
          return;
        case "WARNING":
          warning++;
          return;
        case "INFO":
          alert++;
          return;
      }
    });
  });

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
        <h1>${error}</h1>
        <h3>Errors</h3>
      </div>
      <div class="col count">
        <h1>${warning}</h1>
        <h3>Warnings</h3>
      </div>
      <div class="col count">
        <h1>${alert}</h1>
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
        <label class="checkbox${
          curr.id === "semgrep" && (isWindows || !Global.semgrepServer)
            ? " disabled"
            : ""
        }"
          >${
            curr.title +
            (curr.id === "semgrep" && isWindows ? " (Disabled on Windows)" : "")
          }
          <input
            type="checkbox"
            id="${curr.id}__checkbox"
            checked="${
              curr.id === "semgrep" && (isWindows || !Global.semgrepServer)
                ? false
                : curr.isEnabled()
            }" 
            ${
              curr.id === "semgrep" && (isWindows || !Global.semgrepServer)
                ? `disabled="true"`
                : ""
            }/>
          <span class="checkmark"></span
        ></label>
      </div>
      `,
        ""
      )} 
      <h2>Ignored Files</h2>
      <div class="entries">
        <div class="row">
          <p style="flex: 1">Add or modify ignored paths (.js files enabled by default)</p>
          <button id="ignore__button__add" type="button">
            ${Icons.add}
          </button>
        </div>
        ${ignoredRegex.reduce(
          (prev, currRegex, idx) =>
            prev +
            `<div class="row">
        <p style="flex: 1">${currRegex}</p>
        <button id="ignore__button__${idx}" type="button">
          ${Icons.trash}
        </button>
      </div>`,
          ""
        )}
    </div>
      ${featureList.reduce((prev, curr) => prev + getFeatureEntries(curr), "")}
    </div>
  </body>
</html>
`;
}

module.exports = {
  createWebview,
  updateWebview,
};
