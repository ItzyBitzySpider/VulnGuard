const path = require("path");
const { scanFile } = require("./scanTrigger");
const Global = require("./globals");

function toKebabCase(s) {
  return s
    .replace(/([a-z])([A-Z])/g, "$1-$2")
    .replace(/[\s_]+/g, "-")
    .toLowerCase();
}

function renameVulns(context, oldPath, newPath) {
  //New entry
  if (newPath.endsWith(".js") && !oldPath.endsWith(".js")) {
    scanFile(context, newPath);
    return;
  }
  //Delete entry
  if (!newPath.endsWith(".js") && oldPath.endsWith(".js")) {
    Global.vulns.delete(oldPath);
    return;
  }
  //Javascript file name change
  if (newPath.endsWith(".js") && oldPath.endsWith(".js")) {
    Global.vulns.set(newPath, Global.vulns.get(oldPath));
    Global.vulns.delete(oldPath);
    return;
  }
  //Potential directory change
  if (!newPath.endsWith(".js") && !oldPath.endsWith(".js")) {
    oldPath = oldPath + path.sep;
    newPath = newPath + path.sep;
    Global.vulns.forEach((v, k) => {
      if (k.startsWith(oldPath)) {
        Global.vulns.set(k.replace(oldPath, newPath), v);
        Global.vulns.delete(k);
      }
    });
    return;
  }
}
function deleteVulns(uri) {
  //Array deletion
  if (typeof uri !== "string") {
    uri.forEach((u) => {
      if (Global.vulns.has(u.fsPath)) Global.vulns.delete(u.fsPath);
      if (Global.vulnDiagnostics.has(u)) Global.vulnDiagnostics.delete(u);
    });
  } else if (uri.endsWith(".js")) Global.vulns.delete(uri);
  else
    Global.vulns.forEach((v, filename) => {
      if (filename.startsWith(uri.fsPath + path.sep)) {
        Global.vulns.delete(filename);
      }
    });
}

function deleteVulnsWithFeature(featureId) {
  Global.vulns.forEach((vulnList, file) => {
    Global.vulns.set(
      file,
      vulnList.filter((v) => v.featureId !== featureId)
    );
  });
}

module.exports = {
  toKebabCase,
  renameVulns,
  deleteVulns,
  deleteVulnsWithFeature,
};
