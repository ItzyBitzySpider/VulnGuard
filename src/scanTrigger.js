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
}

async function scanIgnored(context, ignored) {
  const search = ignored.endsWith(".js")
    ? ignored
    : path.join(ignored, "*.js").replaceAll("\\", "/");
  const uris = await vscode.workspace.findFiles(
    search,
    `{${getIgnoredRegex(context).join(",")}}`
  );
  console.log("Rescanning", search);
  console.log(uris);
  await Promise.all(uris.map((uri) => scan(uri.fsPath)));
}

async function scanWorkspace(context) {
  const uris = await vscode.workspace.findFiles(
    "**/*.js",
    `{${getIgnoredRegex(context).join(",")}}`
  );
  await Promise.all(uris.map((uri) => scan(uri.fsPath)));
}
async function scanFile(context, filePath) {
  vscode.workspace.workspaceFolders.forEach((f) => {
    if (filePath.startsWith(f)) filePath = filePath.replace(f, "");
  });
  const uris = await vscode.workspace.findFiles(
    filePath,
    `{${getIgnoredRegex(context).join(",")}}`,
    1
  );
  if (uris.length > 0) await scan(uris[0].fsPath);
}

module.exports = {
  scanWorkspace,
  scanFile,
  scanIgnored,
};
