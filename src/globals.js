const { Feature } = require("./feature");
const vscode = require("vscode");

const featureList = [];
/**
 *
 * @returns {Feature[]}
 */
function getFeatureList() {
  return featureList;
}
var regexRuleSets = [];
var semgrepRuleSets = [];

var enabledRegexRuleSets = [];
var enabledSemgrepRuleSets = [];
var semgrepServer = undefined;

var vulnDiagnostics = vscode.languages.createDiagnosticCollection("vulns");

module.exports = {
  getFeatureList,
  regexRuleSets,
  semgrepRuleSets,
  enabledRegexRuleSets,
  enabledSemgrepRuleSets,
  semgrepServer,
  vulnDiagnostics,
};
