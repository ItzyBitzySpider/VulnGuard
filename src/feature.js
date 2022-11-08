/**
 * @typedef {Object} range
 * @property {number} start - Error start idx
 * @property {number} end - Error end idx
 *
 *
 * @typedef {Object} error
 * @property {string} id
 * @property {range | undefined} range
 * @property {number | undefined} line_no
 * @property {string | undefined} fix
 * @property {("INFO"|"ERROR"|"WARN")} severity - severity of error
 * @property {string} message - Error message
 *
 * Callback for the security checks to be run on the code
 * @callback checker
 * @param {string} fileUri
 * @returns {error | undefined} error
 */

const { getFeatures } = require("./settings");

let context = undefined;

function setFeatureContext(ctx) {
  context = ctx;
}

class Rule {
  /**
   * @param {string} id
   * @param {string} title
   * @param {string} description
   * @param {("INFO"|"ERROR"|"WARN")} severity
   */
  constructor(id, title, checker, rules) {
    this.id = id;
    this.title = title;
    this.checker = checker;
    this.rules = rules;
  }

  isEnabled() {
    return Math.random() > 0.5;
  }
}

class Feature {
  /**
   * @param {string} id - Lowercase string identifier e.g. semgrep
   * @param {string} title - Feature title to be displayed e.g. "SemGrep"
   * @param {checker} checker - The callback that flags code errors\
   * @param {Rule[]} rules - List of rules
   */
  constructor(id, title, checker, rules) {
    this.id = id;
    this.title = title;
    this.checker = checker;
    this.rules = rules;
  }

  isEnabled() {
    const enabled = getFeatures(context)[this.id];
    if (enabled === undefined) return undefined;
    return enabled;
  }
}

module.exports = { Feature, Rule, setFeatureContext };
