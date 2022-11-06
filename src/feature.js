/**
 * @typedef {Object} error
 * @property {number} start - Error start idx
 * @property {number} end - Error end idx
 * @property {("INFO"|"ERROR"|"WARN")} severity - severity of error
 * @property {string} message - Error message
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
   * @param {string} identifier - Lowercase string identifier e.g. semgrep
   * @param {string} title - Feature title to be displayed e.g. "SemGrep"
   * @param {checker} checker - The callback that flags code errors
   */
  constructor(identifier, title, checker) {
    this.identifier = identifier;
    this.title = title;
    this.checker = checker;
    this.enabled = getFeatures(context)[identifier];
    if (this.enabled === undefined) this.enabled = true;
  }
}

module.exports = { Feature, setFeatureContext };
