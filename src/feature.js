/**
 * @typedef {Object} error
 * @property {number} start - Error start idx
 * @property {number} end - Error end idx
 * @property {("INFO"|"ERROR"|"WARN")} severity - severity of error
 * @property {string} message - Error message
 *
 * @typedef {Object} rule
 * @property {string} id
 * @property {string} title
 * @property {string} description
 * @property {boolean} enabled
 * @property {("INFO"|"ERROR"|"WARN")} severity
 *
 * Callback for the security checks to be run on the code
 * @callback checker
 * @param {string} fileUri
 * @returns {error} error
 */

const { getFeatures } = require("./settings");

let context = undefined;

function setFeatureContext(ctx) {
  context = ctx;
}

class Feature {
  /**
   * @param {string} id - Lowercase string identifier e.g. semgrep
   * @param {string} title - Feature title to be displayed e.g. "SemGrep"
   * @param {checker} checker - The callback that flags code errors\
   * @param {rule[]} rules - List of rules
   */
  constructor(id, title, checker, rules) {
    this.id = id;
    this.title = title;
    this.checker = checker;
    this.rules = rules;
  }

  isEnabled() {
    const enabled = getFeatures(context)[id];
    if (enabled === undefined) return undefined;
    return enabled;
  }
}

module.exports = { Feature, setFeatureContext };
