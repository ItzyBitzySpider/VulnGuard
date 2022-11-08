const vscode = require("vscode");
const GLOBALS = require("./globals");
const { getIgnoredRegex } = require("./settings");

const vulns = new Map();

function getVulns() {
  return vulns;
}

async function scanWorkspace(context) {
  const uris = await vscode.workspace.findFiles(
    "**/*.js",
    `{${getIgnoredRegex(context).join(",")}}`
  );
  uris.forEach((uri) => scanFile(uri.fsPath));
}

async function scanFile(path) {
  const tmpVulnList = [];
  GLOBALS.getFeatureList().forEach((feature) => {
    if (!feature.isEnabled()) return;
    const vuln = feature.checker(path);
    if (vuln) tmpVulnList.push(vuln);
  });
  vulns.set(path, tmpVulnList);
}

module.exports = { scanWorkspace, scanFile, getVulns };
