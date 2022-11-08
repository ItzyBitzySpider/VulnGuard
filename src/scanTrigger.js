const vscode = require("vscode");
const path = require("path");
const GLOBALS = require("./globals");
const { getIgnoredRegex } = require("./settings");

async function scanDirectory(context, directory) {
  const uris = await vscode.workspace.findFiles(
    path.join(directory, "**/*.js"),
    `{${getIgnoredRegex(context).join(",")}}`
  );
  uris.forEach((uri) => {
    console.log("Scanning", uri.fsPath);
    scanFile(uri.fsPath);
  });
}

async function scanFile(path) {
  const tmpVulnList = [];
  GLOBALS.getFeatureList().forEach((feature) => {
    if (!feature.isEnabled()) return;
    const vuln = feature.checker(path);
    if (vuln) tmpVulnList.push(vuln);
  });
  const { getVulns } = require("./vuln");
  getVulns().set(path, tmpVulnList);
}

async function scanWorkspace(context) {
  const uris = await vscode.workspace.findFiles(
    "**/*.js",
    `{${getIgnoredRegex(context).join(",")}}`
  );
  uris.forEach((uri) => scanFile(uri.fsPath));
}

module.exports = {
  scanWorkspace,
  scanDirectory,
  scanFile,
};
