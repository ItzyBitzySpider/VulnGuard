const path = require("path");
const { scanFile } = require("./scanTrigger");
const Global = require("./globals");

const vulns = new Map();

function getVulns() {
  return vulns;
}

module.exports = {
  getVulns,
  renameVulns,
  deleteVulns,
};
