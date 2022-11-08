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

module.exports = {
  getFeatureList,
  FIX_VULN_CODE,
};
