const vscode = require("vscode");
const path = require("path");
const GLOBALS = require("./globals");
const { getIgnoredRegex } = require("./settings");

const vulns = new Map();

function getVulns() {
  return vulns;
}
function renameVulns(oldPath, newPath) {
  //New entry
  if (newPath.endsWith(".js") && !oldPath.endsWith(".js")) {
    console.log("Add new");
    scanFile(newPath);
    return;
  }
  //Delete entry
  if (!newPath.endsWith(".js") && oldPath.endsWith(".js")) {
    console.log("Delete old");
    vulns.delete(oldPath);
    return;
  }
  //Javascript file name change
  if (newPath.endsWith(".js") && oldPath.endsWith(".js")) {
    console.log("File rename");
    vulns.set(newPath, vulns.get(oldPath));
    vulns.delete(oldPath);
    return;
  }
  //TODO fix this buggy thing
  //Potential directory change
  if (!newPath.endsWith(".js") && !oldPath.endsWith(".js")) {
    oldPath = oldPath + path.sep;
    newPath = newPath + path.sep;
    console.log("Dir change");
    vulns.forEach((v, k) => {
      if (k.startsWith(oldPath)) {
        vulns.set(k.replace(oldPath, newPath), v);
        vulns.delete(k);
        console.log(k, k.replace(oldPath, newPath));
      }
    });
    return;
  }
}

async function scanWorkspace(context) {
  const uris = await vscode.workspace.findFiles(
    "**/*.js",
    `{${getIgnoredRegex(context).join(",")}}`
  );
  uris.forEach((uri) => scanFile(uri.fsPath));
}

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
  vulns.set(path, tmpVulnList);
}

module.exports = {
  scanWorkspace,
  scanDirectory,
  scanFile,
  getVulns,
  renameVulns,
};
