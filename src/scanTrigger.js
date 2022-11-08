const vscode = require("vscode");
const GLOBALS = require("./globals");
const { getIgnoredRegex } = require("./settings");

async function scanWorkspace(context) {
  const uris = await vscode.workspace.findFiles(
    "**/*.js",
    `{${getIgnoredRegex(context).join(",")}}`
  );
  uris.forEach((uri) => scanFile(uri));
}

async function scanFile(uri) {
  GLOBALS.getFeatureList().forEach((feature) => {
    if (!feature.isEnabled()) return;
    const vuln = feature.checker(uri);
    console.log(vuln);
  });
}

module.exports = { scanWorkspace, scanFile };
