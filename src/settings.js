const vscode = require("vscode");
const fs = require("fs");
const path = require("path");

let features = undefined;

function getFeaturesPath(context) {
  const dir = context.globalStorageUri.fsPath;
  if (!fs.existsSync(dir)) fs.mkdirSync(dir);

  return dir + "/features.json";
}

/**
 * @param {vscode.ExtensionContext} context
 */
function getFeatures(context) {
  if (features) return features;
  if (!context) return undefined;

  const featuresPath = getFeaturesPath(context);
  if (!fs.existsSync(featuresPath))
    fs.copyFileSync(
      path.join(context.extensionPath, "files", "features.json"),
      featuresPath
    );
  features = JSON.parse(fs.readFileSync(featuresPath));
  return features;
}

/**
 * @param {vscode.ExtensionContext} context
 * @param {string} feature
 * @param {boolean} enabled
 */
function setFeature(context, feature, enabled) {
  features[feature] = enabled;

  const featuresPath = getFeaturesPath(context);
  fs.writeFile(featuresPath, features.toString());
}

module.exports = { getFeatures, setFeature };
