const promisify = require("util").promisify;
const execFile = require("child_process").execFile;
const fs = require("fs");
const readline = require("readline");
const yaml = require('yaml');
const execFileAsync = promisify(execFile);

async function semgrepScan(configs, path) {
    var hits = [];
    //configs is list of paths to config files, path is path to directory/file to scan
    //array of promises to run semgrep for each config
    const promises = configs.map((config) => { return execFileAsync("semgrep", ["--json", "--config=" + config, path]); });
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
                "source": "VulnGuard",
            });
        }
    }
    return hits;
}

async function regexScan(rules, path) {
    var hits = [];
    //array of promises to run regex for each rule
    const promises = rules.map((rule) => { return regexRuleScan(rule, path); });
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
                    ...(result.extra.fix && { "fix": result.extra.fix }),
                    "id": rule.id,
                    "source": "VulnGuard",
                });
            }
        } else {
            if (applyRegexCheck(rule.regex, "regex_and", line)) {
                hits.push({
                    "severity": rule.severity,
                    "line_no": line_no,
                    "message": rule.message,
                    ...(result.extra.fix && { "fix": result.extra.fix }),
                    "id": rule.id,
                    "source": "VulnGuard",
                });
            }
        }
    }
    return hits;
}

function scan(path) {
    Promise.all([semgrepScan(semgrepRules, path), regexScan(regexRules, path)]).then((values) => {
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

var semgrepRules = [];
var regexRules = [];

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
        /*if(val_type !== "string" && val_type !== "object"){
            throw "Unknown value type " + val_type
        }*/

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

function loadRegexRules(path) {
    const cfg = fs.readFileSync(path, 'utf8');
    const dat = yaml.parse(cfg);
    for (const rule of dat.rules) { //TODO: Implement fix for Regex?
        if (!('id' in rule)) {
            throw "rule is missing 'id' field";
        }
        if (!('message' in rule)) {
            throw "rule is missing 'message' field";
        }
        if (!('severity' in rule)) {
            throw "rule is missing 'severity' field";
        }
        if (!('regex' in rule)) {
            throw "rule is missing 'regex' field";
        } //TODO: Throw error on unrecognized fields (fix, metadata optional)

        if (typeof rule.regex === "object") {
            validateRegexTree(rule.regex);
        } else { //TODO: Should val_type be strictly enforced?
            rule.regex = new RegExp(rule.regex, 'g') ;//Compile regex while validating
        }
        regexRules.push(rule);
    }
    //console.log(util.inspect(regexRules, false, null, true))
}

function loadSemgrepRules(path) { //TODO: Do proper data validation?
    semgrepRules.push(path);
}

loadRegexRules('rules.yml')
loadSemgrepRules('semgrep.yml')

console.time('test')
scan("sample.js")
console.timeEnd('test')