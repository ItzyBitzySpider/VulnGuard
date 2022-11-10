const path = require("path");
const { scanFile } = require("./scanTrigger");
const Global = require("./globals");

const vulns = new Map();
/**
 * @typedef {Object} range
 * @property {number} start - Error start idx
 * @property {number} end - Error end idx
 *
 * @typedef {Object} error
 * @property {string} id
 * @property {range | undefined} range
 * @property {number | undefined} line_no
 * @property {string | undefined} fix
 * @property {("INFO"|"ERROR"|"WARNING")} severity - severity of error
 * @property {string} message - Error message
 *
 * @returns {Map<string,error[]>}
 */
function getVulns() {
  return vulns;
}

function renameVulns(context, oldPath, newPath) {
  //New entry
  if (newPath.endsWith(".js") && !oldPath.endsWith(".js")) {
    scanFile(context, newPath);
    return;
  }
  //Delete entry
  if (!newPath.endsWith(".js") && oldPath.endsWith(".js")) {
    vulns.delete(oldPath);
    return;
  }
  //Javascript file name change
  if (newPath.endsWith(".js") && oldPath.endsWith(".js")) {
    vulns.set(newPath, vulns.get(oldPath));
    vulns.delete(oldPath);
    return;
  }
  //Potential directory change
  if (!newPath.endsWith(".js") && !oldPath.endsWith(".js")) {
    oldPath = oldPath + path.sep;
    newPath = newPath + path.sep;
    vulns.forEach((v, k) => {
      if (k.startsWith(oldPath)) {
        vulns.set(k.replace(oldPath, newPath), v);
        vulns.delete(k);
      }
    });
    return;
  }
}
function deleteVulns(uri) {
  //Array deletion
  if (typeof uri !== "string") {
    uri.forEach((u) => {
      if (vulns.has(u.fsPath)) vulns.delete(u.fsPath);
      if (Global.vulnDiagnostics.has(u)) Global.vulnDiagnostics.delete(u);
    });
  } else if (uri.endsWith(".js")) vulns.delete(uri);
  else
    vulns.forEach((v, filename) => {
      if (filename.startsWith(uri.fsPath + path.sep)) {
        vulns.delete(filename);
      }
    });
}

module.exports = {
  getVulns,
  renameVulns,
  deleteVulns,
};
