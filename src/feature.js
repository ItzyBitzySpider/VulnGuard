const path = require("path");

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
 * Callback for the security checks to be run on the code
 * @callback scanForVulns
 * @param {string} fileUri
 * @returns {error[] | Promise<error[]> | undefined} error
 *
 */

const { getFeatures } = require("./settings");

let context = undefined;

function setFeatureContext(ctx) {
  context = ctx;
}

class Feature {
  /**
   * @callback getRulesetParam
   * @returns {rulesetParam}
   *
   * @typedef {rulesetParam}
   * @property {object[]} enabled
   * @property {object[]} all
   *
   * @param {string} id - Lowercase string identifier e.g. semgrep
   * @param {string} title - Feature title to be displayed e.g. "SemGrep"
   * @param {scanForVulns} scanforVulns - The callback that flags code errors\
   * @param {getRulesetParam} getRuleParams - Get 2 lists of rulesets (enabled and all)
   */
  constructor(id, title, scanforVulns, getRuleParams) {
    this.id = id;
    this.title = title;
    this.scanForVulns = scanforVulns;
    this.getRuleParams = getRuleParams;
  }

  isEnabled() {
    const enabled = getFeatures(context)[this.id];
    if (enabled === undefined) return true;
    return enabled;
  }

  /**
   *
   * @typedef {featureRulesetData}
   * @property {number} total - Total number of rulesets
   * @property {number} enabled - Total number of enabled rulesets
   * @property {Map<string,boolean>} rulesets - Map of ruleset paths to enabled state
   *
   * @returns {featureRulesetData}
   */
  getRulesetData() {
    const rulesets = this.getRuleParams();
    const enabled = rulesets.enabled.map((r) => r.path ? r.path : r); //TODO: Normalize field format in scanner.js
    const all = rulesets.all.map((r) => r.path ? r.path : r);
    const outputRulesets = new Map();
    all.forEach((path) => outputRulesets.set(path, false));
    enabled.forEach((path) => {
      if (!outputRulesets.has(path))
        console.warn("Key found in enabled but not in all:", path);
      outputRulesets.set(path, true);
    });
    return {
      enabled: enabled.length,
      total: all.length,
      rulesets: outputRulesets,
    };
  }
}

/**
 *
 * @param {string} filePath
 * @returns {string}
 */
function getTitleFromPath(filePath) {
  return path
    .basename(filePath)
    .replace(new RegExp(path.extname(filePath) + "$"), "")
    .replaceAll(/[_-]/g, " ") //Replace hyphen and underscore with space
    .replaceAll(/(\b[a-z](?!\s))/g, (x) => x.toUpperCase()); //Capitalize first letter of each word
}

module.exports = { Feature, setFeatureContext, getTitleFromPath };
