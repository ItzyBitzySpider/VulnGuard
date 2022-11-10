const vscode = require("vscode");
const path = require("path");
const Global = require("./globals");
const { getIgnoredRegex } = require("./settings");

async function scan(fsPath) {
  console.log("Scanning", fsPath);
  const tmpVulnList = [];
  for (const feature of Global.getFeatureList()) {
    if (!feature.isEnabled()) continue;

    const vuln = await feature.scanForVulns(fsPath);
    if (vuln) tmpVulnList.push(...vuln);
  }
  require("./vuln").getVulns().set(fsPath, tmpVulnList);
}

async function scanIgnored(context, ignored) {
  const search = ignored.endsWith(".js")
    ? ignored
    : path.join(ignored, "*.js").replaceAll("\\", "/");
  const uris = await vscode.workspace.findFiles(
    search,
    `{${getIgnoredRegex(context).join(",")}}`
  );
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
    const fs = f.uri.fsPath + path.sep;
    if (filePath.startsWith(fs)) filePath = filePath.replace(fs, "");
  });
  const uris = await vscode.workspace.findFiles(
    filePath,
    `{${getIgnoredRegex(context).join(",")}}`,
    1
  );
  if (uris.length > 0) await scan(uris[0].fsPath);
  else console.warn("Cannot scan file: ", filePath);
}

module.exports = {
  scanWorkspace,
  scanFile,
  scanIgnored,
};
