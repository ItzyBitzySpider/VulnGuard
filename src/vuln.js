const path = require("path");
const { scanFile } = require("./scanTrigger");

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

function renameVulns(oldPath, newPath) {
  //New entry
  if (newPath.endsWith(".js") && !oldPath.endsWith(".js")) {
    scanFile(newPath);
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
        console.log(k.substring(30), k.replace(oldPath, newPath).substring(30));
      }
    });
    return;
  }
}
function deleteVulns(fsPath) {
  if (fsPath.endsWith(".js")) vulns.delete(fsPath);
  else
    vulns.forEach((v, k) => {
      if (k.startsWith(fsPath + path.sep)) vulns.delete(k);
    });
}

module.exports = {
  getVulns,
  renameVulns,
  deleteVulns,
};
