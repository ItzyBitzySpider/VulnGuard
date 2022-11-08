const { Feature } = require("./feature");

const featureList = [];
/**
 *
 * @returns {Feature[]}
 */
function getFeatureList() {
  return featureList;
}
const FIX_VULN_CODE = "vulnfix";
var regexRuleSets = [];
var semgrepRuleSets = [];

var enabledRegexRuleSets = [];
var enabledSemgrepRuleSets = [];

module.exports = {
  getFeatureList,
  FIX_VULN_CODE,
  regexRuleSets,
  semgrepRuleSets,
  enabledRegexRuleSets,
  enabledSemgrepRuleSets,
};
