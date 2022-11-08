const promisify = require("util").promisify;
const execFile = require("child_process").execFile;
const path = require("path");
const fs = require("fs");
const readline = require("readline");
const yaml = require('yaml');
const execFileAsync = promisify(execFile);

async function semgrepRuleSetsScan(configs, path, exclude=null) {
    var hits = [];
    //append --exclude-rule to semgrep command for each exclude rule
    if (exclude) exclude = exclude.map((rule) => { return "--exclude-rule=" + rule });
    const promises = configs.map((config) => { return execFileAsync("semgrep", ["--json", ...exclude, "--config=" + config, path]); });
    const results = await Promise.all(promises);
    for (const result of results) {
        const dat = JSON.parse(result.stdout);
        for (const result of dat.results) {
            hits.push({
                "severity": result.extra.severity,
                "range": {
                    "start": result.start.offset,
                    "end": result.end.offset,
                },
                "message": result.extra.message,
                ...(result.extra.fix && { "fix": result.extra.fix }),
                "id": result.check_id,
            });
        }
    }
    return hits;
}

async function regexRuleSetsScan(ruleSets, path) {
    var hits = [];
    const promises = ruleSets.map((ruleSet) => { return regexRuleSetScan(ruleSet, path); });
    const results = await Promise.all(promises);
    for (const result of results) {
        hits = hits.concat(result);
    }
    return hits;
}

async function regexRuleSetScan(ruleSet, path) {
    var hits = [];
    //array of promises to run regex for each rule
    const promises = ruleSet.ruleSet.map((rule) => { return regexRuleScan(rule, path); });
    const results = await Promise.all(promises);
    for (const result of results) {
        hits = hits.concat(result);
    }
    return hits;
}

async function regexRuleScan(rule, path) {
    var hits = [];
    var line_no = 0;
    var rd = readline.createInterface({ input: fs.createReadStream(path), console: false });
    for await (const line of rd) {
        line_no += 1;
        if (rule.regex instanceof RegExp) { //Can provide start and end indices since this is a simple regex rule (not a regex tree)
            let match;
            while ((match = rule.regex.exec(line)) !== null) {
                hits.push({
                    "severity": rule.severity,
                    "range": {
                        "start": match.index,
                        "end": rule.regex.lastIndex,
                    },
                    "message": rule.message,
                    ...(rule.fix && { "fix": rule.fix }),
                    "id": rule.id,
                });
            }
        } else {
            if (applyRegexCheck(rule.regex, "regex_and", line)) {
                hits.push({
                    "severity": rule.severity,
                    "line_no": line_no,
                    "message": rule.message,
                    ...(rule.fix && { "fix": rule.fix }),
                    "id": rule.id,
                });
            }
        }
    }
    return hits;
}

function scan(path) {
    Promise.all([semgrepRuleSetsScan(enabledSemgrepRuleSets, path), regexRuleSetsScan(enabledRegexRuleSets, path)]).then((values) => {
        console.log(values);
    });
}

function applyRegexCheck(node, parent_type, text) { //Assumes tree is valid
    var res;
    if (parent_type === "regex" || parent_type === "regex_and") {
        res = true; //Neutral element of AND is 1
        for (const field of node) {
            const propertyNames = Object.getOwnPropertyNames(field);
            const key = propertyNames[0];
            const val = field[key];

            if (val instanceof RegExp) {
                if (key === "regex_not") {
                    res &= !(val.test(text));
                } else {
                    res &= val.test(text);
                }
            } else {
                res &= applyRegexCheck(val, key, text);
            }
        }
    } else { //regex_or
        res = false; //Neutral element of OR is 0
        for (const field of node) {
            const propertyNames = Object.getOwnPropertyNames(field);
            const key = propertyNames[0];
            const val = field[key];

            if (val instanceof RegExp) {
                if (key === "regex_not") {
                    res |= !(val.test(text));
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

function validateRegexTree(node) {
    for (const field of node) {
        const propertyNames = Object.getOwnPropertyNames(field);
        if (propertyNames.length !== 1) {
            throw "Expected 1 property name, got " + propertyNames.length + " (" + propertyNames + ")";
        }

        const key = propertyNames[0];
        if (key !== "regex" && key !== "regex_and" && key !== "regex_or" && key !== "regex_not") {
            throw "Unknown key name " + key;
        }

        const val = field[key];
        const val_type = typeof val; //TODO: Should val_type be strictly enforced?

        if (val_type === "object") {
            if (key === "regex_not") {
                throw "regex_not cannot be used on a regex subtree";
            }
            validateRegexTree(val);
        } else {
            if (key === "regex_or") {
                throw "regex_or can only be used on a regex subtree";
            }
            field[key] = new RegExp(field[key], 'g'); //Compile regex while validating tree
        }
    }
}

function getFilesRecursively(top_dir) {
    var files = [];
    function explore(dir) {
        fs.readdirSync(dir).forEach(file => {
            const absolute = path.join(dir, file);
            return fs.statSync(absolute).isDirectory() ? explore(absolute) : files.push(absolute);
        });
    }
    explore(top_dir);
    return files;
}

var regexRuleSets = [];
var semgrepRuleSets = [];

var enabledRegexRuleSets = [];
var enabledSemgrepRuleSets = [];

async function loadRegexRuleSet(path) {
    var regexRules = [];
    const cfg = fs.readFileSync(path, 'utf8');
    const dat = yaml.parse(cfg);
    for (const rule of dat.rules) {
        const propertyNames = Object.getOwnPropertyNames(rule);
        var f_id = false, f_message = false, f_severity = false, f_regex = false, f_fix = false, regex_type = "";
        for (const propertyName of propertyNames) {
            if (propertyName === "id") {
                f_id = true;
            } else if (propertyName === "message") {
                f_message = true;
            } else if (propertyName === "severity") {
                f_severity = true;
            } else if (propertyName === "regex" || propertyName === "regex_and" || propertyName === "regex_or" || propertyName === "regex_not") {
                if (f_regex) {
                    throw "Only 1 top-level regex property is supported (found duplicate types: " + regex_type + " & " + propertyName + ")";
                }
                f_regex = true;
                regex_type = propertyName;
            } else if (propertyName === "fix") { //Optional
                f_fix = true;
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

        if (regex_type === "regex" || regex_type === "regex_and") {
            if (regex_type === "regex_and") { //Internally swtich regex_and -> regex
                rule.regex = rule.regex_and;
                delete rule.regex_and;
            }

            if (typeof rule.regex === "object") {
                validateRegexTree(rule.regex);
            } else { //TODO: Should val_type be strictly enforced?
                rule.regex = new RegExp(rule.regex, 'g'); //Compile regex while validating
            }
        } else if (regex_type === "regex_or") {
            if (typeof rule.regex_or !== "object") {
                throw "regex_or can only be used on a regex subtree";
            }

            rule.regex = [{regex_or: rule.regex_or}]; //Internally make regex_or a subtree of regex
            delete rule.regex_or;

            validateRegexTree(rule.regex);
        } else { //regex_not
            if (typeof rule.regex_not === "object") {
                throw "regex_not cannot be used on a regex subtree";
            } //TODO: Should val_type be strictly enforced?
            rule.regex_not = new RegExp(rule.regex_not, 'g'); //Compile regex while validating

            rule.regex = [{regex_not: rule.regex_not}]; //Internally make regex_not a subfield of regex
            delete rule.regex_not;
        }
        regexRules.push(rule);
    }

    //Use Semgrep to scan Regex rules to check for duplicate IDs, etc.
    await semgrepRuleSetsScan(["p/semgrep-rule-lints"], path, ["yaml.semgrep.missing-language-field.missing-language-field", "yaml.semgrep.duplicate-pattern.duplicate-pattern", "yaml.semgrep.unsatisfiable.unsatisfiable-rule"]).then((results) => { //Remove incompatible rules
        for (const result of results) {
            if (result.severity === "ERROR") {
                 throw result;
            } else {
                 console.log(result);
            }
        }
        var tmp = {path: path, ruleSet: regexRules}; //Only add current RuleSet if it has no errors
        regexRuleSets.push(tmp);
        enabledRegexRuleSets.push(tmp);
    }).catch((error) => {
        console.error(error);
        throw "Error parsing regex RuleSet";
    });
}

async function loadRegexRuleSets(dir) {
    var files = getFilesRecursively(dir);
    for (const file of files) {
        await loadRegexRuleSet(file);
    }
}

function loadSemgrepRuleSet(path) { //TODO: Do proper data validation?
    semgrepRuleSets.push(path);
    enabledSemgrepRuleSets.push(path);
}

function loadSemgrepRuleSets(dir) {
    var files = getFilesRecursively(dir);
    for (const file of files) {
        loadSemgrepRuleSet(file);
    }
}

function validRuleSet(path) {
    for (const regexRuleSet of regexRuleSets) {
        if (regexRuleSet.path === path) {
            return 1;
        }
    }
    for (const semgrepRuleSet of semgrepRuleSets) {
        if (semgrepRuleSet === path) {
            return 2;
        }
    }
    return 0;
}

async function initScanner() { //TODO: Figure out proper subdirectory names
    if (!fs.existsSync("files/disabled.json")) { //Initialize disabled.json if it does not exist
        fs.writeFileSync('files/disabled.json', JSON.stringify([]), 'utf8');
    }

    const cfg = fs.readFileSync("files/disabled.json", 'utf8');
    var disabled = JSON.parse(cfg); //Load disabled.json into memory

    await loadRegexRuleSets("files/regex_rules"); //Load all the rules into memory
    loadSemgrepRuleSets("files/semgrep_rules");

    var cleanedDisabled = [];
    for (const disabledRuleSet of disabled) { //Process disabled.json
        const validity = validRuleSet(disabledRuleSet);
        if (validity === 1) {
            cleanedDisabled.push(disabledRuleSet);
            enabledRegexRuleSets = enabledRegexRuleSets.filter(item => item.path !== disabledRuleSet);
        } else if (validity === 2) {
            cleanedDisabled.push(disabledRuleSet);
            enabledSemgrepRuleSets = enabledSemgrepRuleSets.filter(item => item !== disabledRuleSet);
        } else { //Remove disabled RuleSets that cannot be found
            console.warn("Removing disabled RuleSet", disabledRuleSet, "from disabled.json since it could not be found in the files directory");
        }
    }

    fs.writeFileSync('files/disabled.json', JSON.stringify(cleanedDisabled), 'utf8'); //Update disabled.json (if necessary)
}

function disableRuleSet(path) {
    const validity = validRuleSet(path);
    if (validity === 1) {
        enabledRegexRuleSets = enabledRegexRuleSets.filter(item => item.path !== path);
    } else if (validity === 2) {
        enabledSemgrepRuleSets = enabledSemgrepRuleSets.filter(item => item !== path);
    } else {
        throw "Unable to disable RuleSet " + path + " since it does not exist";
    }

    const cfg = fs.readFileSync("files/disabled.json", 'utf8');
    var disabled = JSON.parse(cfg); //Load disabled.json into memory

    if (disabled.includes(path)) {
        throw "Unable to disable RuleSet " + path + " since it was already disabled";
    }

    disabled.push(path);
    fs.writeFileSync('files/disabled.json', JSON.stringify(disabled), 'utf8'); //Update disabled.json
}

function enableRuleSet(path) {
    const cfg = fs.readFileSync("files/disabled.json", 'utf8');
    var disabled = JSON.parse(cfg); //Load disabled.json into memory

    if (!disabled.includes(path)) {
        throw "Unable to re-enable RuleSet " + path + " since it was not disabled";
    }

    const validity = validRuleSet(path);
    if (validity === 1) {
        for (const regexRuleSet of regexRuleSets) {
            if (regexRuleSet.path === path) {
                enabledRegexRuleSets.push(regexRuleSet);
                break;
            }
        }
    } else if (validity === 2) {
        enabledSemgrepRuleSets.push(path);
    } else {
        throw "Unable to re-enable RuleSet " + path + " since it does not exist";
    }

    disabled = disabled.filter(item => item !== path);
    fs.writeFileSync('files/disabled.json', JSON.stringify(disabled), 'utf8'); //Update disabled.json
}

//wrap in async since top level runs synchronously
(async () => {
initScanner();

console.time('test')
scan("sample.js")
console.timeEnd('test')
})();