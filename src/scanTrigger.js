const vscode = require("vscode");
const path = require("path");
const GLOBALS = require("./globals");
const { getIgnoredRegex } = require("./settings");

async function scan(fsPath) {
  console.log("Scanning", fsPath);
  const tmpVulnList = [];
  for (const feature of GLOBALS.getFeatureList()) {
    if (!feature.isEnabled()) continue;

    const vuln = await feature.scanForVulns(fsPath);
    if (vuln) tmpVulnList.push(...vuln);
  }
  const { getVulns } = require("./vuln");
  getVulns().set(fsPath, tmpVulnList);
  console.log(getVulns());
}

async function scanWorkspace(context) {
  const uris = await vscode.workspace.findFiles(
    "**/*.js",
    `{${getIgnoredRegex(context).join(",")}}`
  );
  await Promise.all(uris.map((uri) => scan(uri.fsPath)));
}
async function scanFile(context, filePath) {
  const uris = await vscode.workspace.findFiles(
    new vscode.RelativePattern(
      path.dirname(filePath).replaceAll("\\", "/"),
      path.basename(filePath)
    ),
    `{${getIgnoredRegex(context).join(",")}}`,
    1
  );
  if (uris.length > 0) await scan(uris[0].fsPath);
}

module.exports = {
  scanWorkspace,
  scanFile,
};
