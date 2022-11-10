const vscode = require("vscode");
const path = require("path");
const Global = require("./globals");
const { getIgnoredRegex } = require("./settings");

/**
 *
 * @param {string} fsPath
 * @param {string[] | undefined} enabledFeatures - Optional list of feature IDs. When given, only scans for enabledFeatures and adds to existing vulns. Scans all features if this parameter is not given
 */
async function scan(fsPath, enabledFeatures) {
  console.log("Scanning", fsPath);
  const tmpVulnList = [];
  for (const feature of Global.getFeatureList()) {
    if (!feature.isEnabled()) continue;
    if (enabledFeatures && !enabledFeatures.includes(feature.id)) continue;

    const vuln = await feature.scanForVulns(fsPath);
    if (!vuln) continue;
    tmpVulnList.push(
      ...vuln.map((v) => {
        v.featureId = feature.id;
        return v;
      })
    );
  }
  if (enabledFeatures && Global.vulns.has(fsPath))
    Global.vulns.set(fsPath, [...tmpVulnList, ...Global.vulns.get(fsPath)]);
  else Global.vulns.set(fsPath, tmpVulnList);
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

/**
 *
 * @param {vscode.ExtensionContext} context
 * @param {string[] | undefined} enabledFeatures - Optional list of feature IDs. When given, only scans for enabledFeatures and adds to existing vulns. Scans all features if this parameter is not given
 */
async function scanWorkspace(context, enabledFeatures) {
  const uris = await vscode.workspace.findFiles(
    "**/*.js",
    `{${getIgnoredRegex(context).join(",")}}`
  );
  await Promise.all(uris.map((uri) => scan(uri.fsPath, enabledFeatures)));
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
