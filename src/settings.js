const vscode = require("vscode");
const fs = require("fs");
const path = require("path");
const Global = require("./globals");

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

  if (enabled) require("./scanTrigger").scanWorkspace(context, feature);
  else require("./utils").deleteVulnsWithFeature(feature);

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
  if (!fs.existsSync(ignoredPath))
    fs.copyFileSync(
      path.join(context.extensionPath, "files", "ignored.txt"),
      ignoredPath
    );
  ignoredRegex = fs.readFileSync(ignoredPath, "utf-8").split(/\r?\n/);

  return ignoredRegex;
}
function addIgnoredRegex(context, regex) {
  regex = regex.replaceAll("\\", "/");
  ignoredRegex.push(regex);
  vscode.workspace
    .findFiles(regex, `${ignoredRegex.join(",")}}`)
    .then((uris) => Global.vulns.deleteVulns(uris));

  const ignoredPath = getIgnoredRegexPath(context);
  fs.writeFile(ignoredPath, ignoredRegex.join("\n"), function (err) {
    if (err) return console.log(err);
    console.log(`Written to ${ignoredPath}`);
  });
}
function deleteIgnoredRegex(context, idx) {
  const removedIgnore = ignoredRegex.splice(idx, 1);
  require("./scanTrigger").scanIgnored(context, removedIgnore[0]);
  const ignoredPath = getIgnoredRegexPath(context);
  fs.writeFile(ignoredPath, ignoredRegex.join("\n"), function (err) {
    if (err) return console.log(err);
    console.log(`Written to ${ignoredPath}`);
  });
}

let disabledRules = undefined;
function getDisabledRulesPath(context) {
  const dir = getGlobalPath(context);
  return path.join(dir, "disabled.json");
}
/**
 * @param {vscode.ExtensionContext} context
 */
function getDisabledRules(context) {
  if (disabledRules) return disabledRules;
  if (!context) return undefined;

  const disabledRulesPath = getDisabledRulesPath(context);
  if (!fs.existsSync(disabledRulesPath))
    fs.writeFileSync(disabledRulesPath, JSON.stringify([]), "utf8");
  disabledRules = JSON.parse(fs.readFileSync(disabledRulesPath, "utf8"));
  return disabledRules;
}
/**
 * @param {vscode.ExtensionContext} context
 * @param {object[]} disabled
 */
function setDisabledRules(context, disabled) {
  disabledRules = disabled;
  const disabledRulesPath = getDisabledRulesPath(context);
  fs.writeFile(
    disabledRulesPath,
    JSON.stringify(disabled),
    { encoding: "utf8" },
    function (err) {
      if (err) return console.log(err);
      console.log(`Written to ${disabledRulesPath}`);
    }
  );
}

let userRulesets;
function getUserRulesetPath(context) {
  const dir = getGlobalPath(context);
  return path.join(dir, "rulesets.json");
}
/**
 * @param {vscode.ExtensionContext} context
 */
function getUserRulesets(context) {
  if (userRulesets) return userRulesets;
  if (!context) return undefined;

  const rulesetPath = getUserRulesetPath(context);
  if (!fs.existsSync(rulesetPath))
    fs.writeFileSync(rulesetPath, JSON.stringify({}), "utf8");
  userRulesets = JSON.parse(fs.readFileSync(rulesetPath, "utf8"));
  return userRulesets;
}
/**
 * @param {vscode.ExtensionContext} context
 * @param {string} feature
 * @param {string} path
 */
function addUserRuleset(context, feature, path) {
  const rulesetPath = getUserRulesetPath(context);
  if (!userRulesets[feature]) userRulesets[feature] = [];
  userRulesets[feature].push(path);
  fs.writeFile(
    rulesetPath,
    JSON.stringify(userRulesets),
    { encoding: "utf8" },
    function (err) {
      if (err) return console.log(err);
      console.log(`Written to ${rulesetPath}`);
    }
  );
}
/**
 * @param {vscode.ExtensionContext} context
 * @param {string} feature
 * @param {string} path
 */
function deleteUserRuleset(context, feature, path) {
  const rulesetPath = getUserRulesetPath(context);
  userRulesets[feature].splice(userRulesets[feature].indexOf(path), 1);
  fs.writeFile(
    rulesetPath,
    JSON.stringify(userRulesets),
    { encoding: "utf8" },
    function (err) {
      if (err) return console.log(err);
      console.log(`Written to ${rulesetPath}`);
    }
  );
}

module.exports = {
  getFeatures,
  setFeature,
  getIgnoredRegex,
  addIgnoredRegex,
  deleteIgnoredRegex,
  getDisabledRules,
  setDisabledRules,
  getUserRulesets,
  addUserRuleset,
  deleteUserRuleset,
};
