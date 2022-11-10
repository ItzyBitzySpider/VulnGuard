const { getDisabledRules, setDisabledRules, getUserRulesets } = require("./settings");
const promisify = require("util").promisify;
const execFile = require("child_process").execFile;
const path = require("path");
const fs = require("fs");
const readline = require("readline");
const yaml = require("yaml");
const execFileAsync = promisify(execFile);
const Global = require("./globals");
const vscode = require("vscode");
const crypto = require("crypto");
const os = require("os");

//SEMGREP FUNCTION
async function semgrepRuleSetsScan(configs, path, exclude = null) {
  var hits = [];
  //append --exclude-rule to semgrep command for each exclude rule
  if (exclude)
    exclude = exclude.map((rule) => {
      return "--exclude-rule=" + rule;
    });
  const promises = configs.map((config) => {
    return execFileAsync("semgrep", [
      "--json",
      ...exclude,
      "--config=" + config,
      path,
    ]);
  });
  const results = await Promise.all(promises);
  for (const result of results) {
    const dat = JSON.parse(result.stdout);
    for (const result of dat.results) {
      hits.push({
        severity: result.extra.severity,
        range: {
          start: result.start.offset,
          end: result.end.offset,
        },
        message: result.extra.message,
        ...(result.extra.fix && { fix: result.extra.fix }),
        ...(result.metadata.reference && {
          reference: result.metadata.reference,
        }),
        id: result.check_id,
      });
    }
  }
  return hits;
}

//REGEX FUNCTION
async function regexRuleSetsScanText(ruleSets, text) { //TODO: Find better way
  return await regexRuleSetsScan(ruleSets, writeToTempFile(text));
}

async function regexRuleSetsScan(ruleSets, path) {
  var hits = [];
  const promises = ruleSets.map((ruleSet) => {
    return regexRuleSetScan(ruleSet, path);
  });
  const results = await Promise.all(promises);
  for (const result of results) {
    hits = hits.concat(result);
  }
  return hits;
}

async function regexRuleSetScan(ruleSet, path) {
  var hits = [];
  //array of promises to run regex for each rule
  const promises = ruleSet.ruleSet.map((rule) => {
    return regexRuleScan(rule, path);
  });
  const results = await Promise.all(promises);
  for (const result of results) {
    hits = hits.concat(result);
  }
  return hits;
}

async function regexRuleScan(rule, path) {
  var hits = [];
  var line_no = 0;
  var rd = readline.createInterface({
    input: fs.createReadStream(path),
    console: false,
  });
  for await (const line of rd) {
    if (rule.regex instanceof RegExp) {
      //Can provide start and end indices since this is a simple regex rule (not a regex tree)
      let match;
      while ((match = rule.regex.exec(line)) !== null) {
        hits.push({
          severity: rule.severity,
          range: {
            start: match.index,
            end: rule.regex.lastIndex,
          },
          message: rule.message,
          ...(rule.fix && { fix: rule.fix }),
          ...(rule.reference && { reference: rule.reference }),
          id: rule.id,
        });
      }
    } else {
      if (applyRegexCheck(rule.regex, "regex_and", line)) {
        hits.push({
          severity: rule.severity,
          line_no: line_no,
          message: rule.message,
          ...(rule.fix && { fix: rule.fix }),
          ...(rule.reference && { reference: rule.reference }),
          id: rule.id,
        });
      }
    }
    line_no += 1;
  }
  return hits;
}

function applyRegexCheck(node, parent_type, text) {
  //Assumes tree is valid
  var res;
  if (parent_type === "regex" || parent_type === "regex_and") {
    res = true; //Neutral element of AND is 1
    for (const field of node) {
      const propertyNames = Object.getOwnPropertyNames(field);
      const key = propertyNames[0];
      const val = field[key];

      if (val instanceof RegExp) {
        if (key === "regex_not") {
          res &= !val.test(text);
        } else {
          res &= val.test(text);
        }
      } else {
        res &= applyRegexCheck(val, key, text);
      }
    }
  } else {
    //regex_or
    res = false; //Neutral element of OR is 0
    for (const field of node) {
      const propertyNames = Object.getOwnPropertyNames(field);
      const key = propertyNames[0];
      const val = field[key];

      if (val instanceof RegExp) {
        if (key === "regex_not") {
          res |= !val.test(text);
        } else {
          res |= val.test(text);
        }
      } else {
        res |= applyRegexCheck(val, key, text);
      }
    }
  }
  return res;
}

//Misc Functions
function writeToTempFile(text) {
  const tmpPath = path.join(os.tmpdir(), crypto.randomBytes(16).toString('hex'));
  fs.writeFileSync(tmpPath, text, "utf8");
  return tmpPath;
}

function getFilesRecursively(top_dir) {
  if (!fs.existsSync(top_dir)) {
    console.warn("Directory not found: " + top_dir);
    return [];
  }
  var files = [];
  function explore(dir) {
    fs.readdirSync(dir).forEach((file) => {
      const absolute = path.join(dir, file);
      return fs.statSync(absolute).isDirectory()
        ? explore(absolute)
        : files.push(absolute);
    });
  }
  explore(top_dir);
  return files;
}

function getPathType(path) {
  try {
    var stat = fs.lstatSync(path);
    if (stat.isDirectory()) {
      return 1; //Directory
    } else {
      return 0; //File
    }
  } catch (error) {
    return 2; //Path does not exist
  }
}

function analyzePackage(dir) {
  var hits = [];

  const manifest = fs.readFileSync(path.join(dir, "package.json"), "utf8");
  const dat = JSON.parse(manifest);

  if (dat["main"]) {
    hits = hits.concat(await regexRuleSetsScanText(Global.dependencyRegexRuleSets["manifest.main"], JSON.stringify(dat["main"])));
  }
  if (dat["scripts"]) {
    hits = hits.concat(await regexRuleSetsScanText(Global.dependencyRegexRuleSets["manifest.scripts"], JSON.stringify(dat["scripts"])));
  }

  function explore(dir) {
    fs.readdirSync(dir).forEach((file) => {
      const absolute = path.join(dir, file);
      if (fs.statSync(absolute).isDirectory()) {
        explore(absolute);
      } else {
        if (['.coffee', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.json'].includes(path.extname(absolute))) {
          hits = hits.concat(await regexRuleSetsScan(Global.dependencyRegexRuleSets["check"], absolute));
        }
      }
    });
  }

  explore(path.join(dir, "node_modules"));

  return hits;
}

//Rulesets loading and validation functions
function validateRegexTree(node, case_sensitive) {
  for (const field of node) {
    const propertyNames = Object.getOwnPropertyNames(field);
    if (propertyNames.length !== 1) {
      throw (
        "Expected 1 property name, got " +
        propertyNames.length +
        " (" +
        propertyNames +
        ")"
      );
    }

    const key = propertyNames[0];
    if (
      key !== "regex" &&
      key !== "regex_and" &&
      key !== "regex_or" &&
      key !== "regex_not"
    ) {
      throw "Unknown key name " + key;
    }

    const val = field[key];
    const val_type = typeof val; //TODO: Should val_type be strictly enforced?

    if (val_type === "object") {
      if (key === "regex_not") {
        throw "regex_not cannot be used on a regex subtree";
      }
      validateRegexTree(val, case_sensitive);
    } else {
      if (key === "regex_or") {
        throw "regex_or can only be used on a regex subtree";
      }
      field[key] = new RegExp(field[key], "g" + (case_sensitive ? "" : "i")); //Compile regex while validating tree
    }
  }
}

function loadRegexRuleSet(path) {
  //Wrap around function _loadRegexRuleSet() to catch exceptions thrown
  try {
    var tmp = _loadRegexRuleSet(path);
    Global.regexRuleSets.push(tmp);
    Global.enabledRegexRuleSets.push(tmp);
  } catch (error) {
    vscode.window.showErrorMessage(
      "Error loading regex ruleset " + path + ": " + error
    );
    console.error("Unable to load Regex RuleSet", path, "due to error:", error);
    let tmp = { path: path }; //Only store path
    Global.regexRuleSets.push(tmp);
  }
}

function _loadRegexRuleSet(path) {
  var regexRules = [];
  const cfg = fs.readFileSync(path, "utf8");
  const dat = yaml.parse(cfg);
  for (const rule of dat.rules) {
    const propertyNames = Object.getOwnPropertyNames(rule);
    var f_id = false,
      f_message = false,
      f_severity = false,
      f_regex = false,
      f_fix = false,
      f_reference = false,
      f_case_sensitive = false;
    regex_type = "";
    for (const propertyName of propertyNames) {
      if (propertyName === "id") {
        f_id = true;
      } else if (propertyName === "message") {
        f_message = true;
      } else if (propertyName === "severity") {
        f_severity = true;
      } else if (
        propertyName === "regex" ||
        propertyName === "regex_and" ||
        propertyName === "regex_or" ||
        propertyName === "regex_not"
      ) {
        if (f_regex) {
          throw (
            "Only 1 top-level regex property is supported (found duplicate types: " +
            regex_type +
            " & " +
            propertyName +
            ")"
          );
        }
        f_regex = true;
        regex_type = propertyName;
      } else if (propertyName === "fix") {
        //Optional
        f_fix = true;
      } else if (propertyName === "reference") {
        //Optional
        f_reference = true;
      } else if (propertyName === "case_sensitive") {
        f_case_sensitive = true;
      } else {
        throw "Unknown property name " + propertyName;
      }
    }

    if (!f_id) {
      throw "rule is missing 'id' field";
    }
    if (!f_message) {
      throw "rule is missing 'message' field";
    }
    if (!f_severity) {
      throw "rule is missing 'severity' field";
    }
    if (!f_regex) {
      throw "rule is missing 'regex'/'regex_and'/'regex_or'/'regex_not' field";
    }
    if(!f_case_sensitive) {
      rule.case_sensitive = true; //Case sensitive by default
    }

    if (regex_type === "regex" || regex_type === "regex_and") {
      if (regex_type === "regex_and") {
        //Internally switch regex_and -> regex
        rule.regex = rule.regex_and;
        delete rule.regex_and;
      }

      if (typeof rule.regex === "object") {
        validateRegexTree(rule.regex, rule.case_sensitive);
      } else {
        //TODO: Should val_type be strictly enforced?
        rule.regex = new RegExp(rule.regex, "g" + (rule.case_sensitive ? "" : "i")); //Compile regex while validating
      }
    } else if (regex_type === "regex_or") {
      if (typeof rule.regex_or !== "object") {
        throw "regex_or can only be used on a regex subtree";
      }

      rule.regex = [{ regex_or: rule.regex_or }]; //Internally make regex_or a subtree of regex
      delete rule.regex_or;

      validateRegexTree(rule.regex, rule.case_sensitive);
    } else {
      //regex_not
      if (typeof rule.regex_not === "object") {
        throw "regex_not cannot be used on a regex subtree";
      } //TODO: Should val_type be strictly enforced?
      rule.regex_not = new RegExp(rule.regex_not, "g" + (rule.case_sensitive ? "" : "i")); //Compile regex while validating

      rule.regex = [{ regex_not: rule.regex_not }]; //Internally make regex_not a subfield of regex
      delete rule.regex_not;
    }
    regexRules.push(rule);
  }

  return { path: path, ruleSet: regexRules };
}

function loadRegexRuleSets(dir) {
  var files = getFilesRecursively(dir);
  for (const file of files) {
    loadRegexRuleSet(file);
  }
}

function loadSemgrepRuleSet(path) {
  //TODO: Do proper data validation?
  Global.semgrepRuleSets.push(path);
  Global.enabledSemgrepRuleSets.push(path);
}

function loadSemgrepRuleSets(dir) {
  var files = getFilesRecursively(dir);
  for (const file of files) {
    loadSemgrepRuleSet(file);
  }
}

function validRuleSet(path) {
  for (const regexRuleSet of Global.regexRuleSets) {
    if (regexRuleSet.path === path) {
      return 1;
    }
  }
  for (const semgrepRuleSet of Global.semgrepRuleSets) {
    if (semgrepRuleSet === path) {
      return 2;
    }
  }
  return 0;
}

//Initialize and abstract away backend for frontend
function initScanner(context) {
  //Load disabled.json into memory
  var disabled = getDisabledRules(context);

  //Load all user-created RuleSets into memory
  var userRulesets = getUserRulesets(context);

  //Load all Regex RuleSets into memory
  loadRegexRuleSets(path.join(context.extensionPath, "files", "regex_rules"));
  if (userRulesets["regex"]) { //There are user-created Regex RuleSets
    for (const regexRuleset of userRulesets["regex"]) {
      const pathType = getPathType(regexRuleset);
      if (pathType === 0) { //File
        loadRegexRuleSet(regexRuleset);
      } else if (pathType === 1) { //Directory
        loadRegexRuleSets(regexRuleset);
      } else {
        console.error(
          "Unable to load user-created Regex RuleSet",
          regexRuleset,
          "since it could not be found"
        );
        let tmp = { path: regexRuleset }; //Only store path
        Global.regexRuleSets.push(tmp);
      }
    }
  }

  //Load all Semgrep RuleSets into memory (if possible)
  if (Global.semgrepServer) {
    loadSemgrepRuleSets(
      path.join(context.extensionPath, "files", "semgrep_rules")
    );
    if (userRulesets["semgrep"]) { //There are user-created Semgrep RuleSets
      for (const semgrepRuleset of userRulesets["semgrep"]) {
        if (semgrepRuleset.startsWith("p/")) { //Semgrep Repository
          loadSemgrepRuleSet(semgrepRuleset);
          continue;
        }

        const pathType = getPathType(semgrepRuleset);
        if (pathType === 0) { //File
          loadSemgrepRuleSet(semgrepRuleset);
        } else if (pathType === 1) { //Directory
          loadSemgrepRuleSets(semgrepRuleset);
        } else {
          console.error(
            "Unable to load user-created Semgrep RuleSet",
            semgrepRuleset,
            "since it could not be found"
          );
          Global.semgrepRuleSets.push(semgrepRuleset);
        }
      }
    }
  }

  var cleanedDisabled = [];
  for (const disabledRuleSet of disabled) {
    //Process disabled.json
    const validity = validRuleSet(disabledRuleSet);
    if (validity === 1) {
      cleanedDisabled.push(disabledRuleSet);
      Global.enabledRegexRuleSets = Global.enabledRegexRuleSets.filter(
        (item) => item.path !== disabledRuleSet
      );
    } else if (validity === 2) {
      cleanedDisabled.push(disabledRuleSet);
      Global.enabledSemgrepRuleSets = Global.enabledSemgrepRuleSets.filter(
        (item) => item !== disabledRuleSet
      );
    } else {
      //Remove disabled RuleSets that cannot be found
      console.warn(
        "Removing disabled RuleSet",
        disabledRuleSet,
        "from disabled.json since it could not be found in the files directory"
      );
    }
  }
  setDisabledRules(context, cleanedDisabled); //Update disabled.json (if necessary)
  return (
    Global.regexRuleSets,
    Global.enabledRegexRuleSets,
    Global.semgrepRuleSets,
    Global.enabledSemgrepRuleSets
  );
}

function disableRuleSet(context, path) {
  var disabled = getDisabledRules(context); //Load disabled.json into memory
  if (disabled.includes(path)) {
    vscode.window.showErrorMessage(
      "Unable to disable RuleSet " + path + " since it was already disabled"
    );
    console.error(
      "Unable to disable RuleSet " + path + " since it was already disabled"
    );
    return;
  }

  const validity = validRuleSet(path);
  if (validity === 1) {
    Global.enabledRegexRuleSets = Global.enabledRegexRuleSets.filter(
      (item) => item.path !== path
    );
  } else if (validity === 2) {
    Global.enabledSemgrepRuleSets = Global.enabledSemgrepRuleSets.filter(
      (item) => item !== path
    );
  } else {
    vscode.window.showErrorMessage(
      "Unable to disable RuleSet " + path + " since it could not be found"
    );
    console.error(
      "Unable to disable RuleSet " + path + " since it does not exist"
    );
    return;
  }

  disabled.push(path);
  setDisabledRules(context, disabled); //Update disabled.json
}

function enableRuleSet(context, path) {
  var disabled = getDisabledRules(context); //Load disabled.json into memory
  if (!disabled.includes(path)) {
    vscode.window.showErrorMessage(
      "Unable to enable RuleSet " + path + " since it was already enabled"
    );
    console.error(
      "Unable to re-enable RuleSet " + path + " since it was not disabled"
    );
    return;
  }

  const validity = validRuleSet(path);
  if (validity === 1) {
    for (const regexRuleSet of Global.regexRuleSets) {
      if (regexRuleSet.path === path) {
        let tmp;
        try {
          tmp = _loadRegexRuleSet(path);
        } catch (error) {
          vscode.window.showErrorMessage(
            "Unable to re-enable Regex RuleSet " +
              path +
              " due to error: " +
              error
          );
          console.error(
            "Unable to re-enable Regex RuleSet " +
              path +
              " due to error: " +
              error
          );
          return;
        }

        //Remove original regexRuleSet (since it may have no RuleSet data)
        Global.regexRuleSets = Global.regexRuleSets.filter(
          (item) => item.path !== path
        );

        //Add new updated Regex RuleSet
        Global.regexRuleSets.push(tmp);
        Global.enabledRegexRuleSets.push(tmp);
        break;
      }
    }
  } else if (validity === 2) {
    Global.enabledSemgrepRuleSets.push(path); //TODO: Do proper data validation?
  } else {
    vscode.window.showErrorMessage(
      "Unable to re-enable RuleSet " + path + " since it could not be found"
    );
    console.error(
      "Unable to re-enable RuleSet " + path + " since it does not exist"
    );
    return;
  }

  disabled = disabled.filter((item) => item !== path);
  setDisabledRules(context, disabled); //Update disabled.json
}

function initDependencyScanner(context) {
  //Helper Functions (TODO: Cleanup and remove hacky mess)
  function loadDependencyRegexRuleSet(path, dependencyType) {
    //Wrap around function _loadRegexRuleSet() to catch exceptions thrown
    try {
      var tmp = _loadRegexRuleSet(path);
      if (!Global.dependencyRegexRuleSets[dependencyType]) Global.dependencyRegexRuleSets[dependencyType] = [];
      Global.dependencyRegexRuleSets[dependencyType].push(tmp);
    } catch (error) {
      throw "Unable to load Dependency (", dependencyType, ") Regex RuleSet", path, "due to error:", error;
    }
  }

  function loadDependencyRegexRuleSets(dir, dependencyType) {
    var files = getFilesRecursively(dir);
    for (const file of files) {
      loadDependencyRegexRuleSet(file, dependencyType);
    }
  }

  //Load all Dependency Regex RuleSets into memory
  loadDependencyRegexRuleSets(path.join(context.extensionPath, "files", "dep_check_rules"), "check");
  loadDependencyRegexRuleSets(path.join(context.extensionPath, "files", "dep_manifest_main_rules"), "manifest.main");
  loadDependencyRegexRuleSets(path.join(context.extensionPath, "files", "dep_manifest_scripts_rules"), "manifest.scripts");

  return Global.dependencyRegexRuleSets;
}

module.exports = {
  disableRuleSet,
  enableRuleSet,
  initScanner,
  initDependencyScanner,
  regexRuleSetsScan,
  semgrepRuleSetsScan,
};
