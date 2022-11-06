const vscode = require("vscode");
const fs = require("fs");

let features = undefined;

/**
 * @param {vscode.ExtensionContext} context
 */
function getFeatures(context) {
  if (features) return features;
  if (!context) return undefined;

  const dir = context.globalStorageUri.fsPath;
  if (!fs.existsSync(dir)) fs.mkdirSync(dir);

  const featuresPath = dir + "/features.json";
  if (!fs.existsSync(featuresPath))
    fs.copyFileSync(
      context.asAbsolutePath("./defaults/features.json"),
      featuresPath
    );
  features = JSON.parse(fs.readFileSync(featuresPath));
  return features;
}

/**
 * @param {vscode.ExtensionContext} context
 */
function setFeatures(context, feature, enabled) {}

module.exports = { getFeatures, setFeatures };
