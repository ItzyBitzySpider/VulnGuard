const vscode = require("vscode");
const fs = require("fs");
const path = require("path");

function getGlobalPath(context) {
  const dir = context.globalStorageUri.fsPath;
  if (!fs.existsSync(dir)) fs.mkdirSync(dir);
  return dir;
}
function getWorkspacePath(context) {
  const dir = context.storageUri.fsPath;
  if (!fs.existsSync(dir)) fs.mkdirSync(dir);
  return dir;
}

let features = undefined;
function getFeaturesPath(context) {
  const dir = getGlobalPath(context);
  return path.join(dir, "features.json");
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
  fs.writeFile(featuresPath, JSON.stringify(features), function (err) {
    if (err) return console.log(err);
    console.log(`Written to ${featuresPath}`);
  });
}

let ignoredRegex = undefined;
function getIgnoredRegexPath(context) {
  const dir = getWorkspacePath(context);
  return path.join(dir, "ignored.txt");
}
function getIgnoredRegex(context) {
  if (ignoredRegex) return ignoredRegex;
  if (!context) return undefined;

  const ignoredPath = getIgnoredRegexPath(context);
  if (!fs.existsSync(ignoredPath)) ignoredRegex = [];
  else ignoredRegex = fs.readFileSync(ignoredPath, "utf-8").split("\n");

  return ignoredRegex;
}
function addIgnoredRegex(context, regex) {
  ignoredRegex.push(regex);
  const ignoredPath = getIgnoredRegexPath(context);
  fs.writeFileSync(ignoredPath, ignoredRegex.join("\n"));
}
function deleteIgnoredRegex(context, idx) {
  ignoredRegex.splice(idx, 1);
  const ignoredPath = getIgnoredRegexPath(context);
  fs.writeFileSync(ignoredPath, ignoredRegex.join("\n"));
}

module.exports = {
  getFeatures,
  setFeature,
  getIgnoredRegex,
  addIgnoredRegex,
  deleteIgnoredRegex,
};
