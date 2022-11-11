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

/**
 * @typedef {Object} range
 * @property {number} start - Error start idx
 * @property {number} end - Error end idx
 *
 * @typedef {Object} vuln
 * @property {string} id
 * @property {range | undefined} range
 * @property {number | undefined} line_no
 * @property {string | undefined} fix
 * @property {("INFO"|"ERROR"|"WARNING")} severity - severity of error
 * @property {string} message - Error message
 *
 * @type {Map<string,vuln[]>} vulns
 */
var vulns = new Map();

var regexRuleSets = [];
var semgrepRuleSets = [];

var enabledRegexRuleSets = [];
var enabledSemgrepRuleSets = [];
var semgrepServer = undefined;

var dependencyRegexRuleSets = {}; //Object of arrays

var vulnDiagnostics = vscode.languages.createDiagnosticCollection("vulns");

const NON_STANDARD_SCAN_FEATURES = ["dependency"];

module.exports = {
  getFeatureList,
  regexRuleSets,
  semgrepRuleSets,
  enabledRegexRuleSets,
  enabledSemgrepRuleSets,
  semgrepServer,
  vulnDiagnostics,
  vulns,
  dependencyRegexRuleSets,
  NON_STANDARD_SCAN_FEATURES,
};
