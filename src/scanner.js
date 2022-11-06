const promisify = require("util").promisify
const execFile = require("child_process").execFile
const fs = require("fs")
const readline = require("readline")
//const util = require("util")

const yaml = require('yaml') //npm i yaml

const execFileAsync = promisify(execFile)

const semgrepScan = async function (configs, path){
    var hits = []
    for(const config of configs){
        //For simple patterns, the pattern can be passed to Semgrep via the CLI --pattern option
        //However, due to the nature of Semgrep, it is not possible to pass pattern trees to Semgrep via --pattern
        //Instead, the entire YAML config file containing the pattern tree should be passed via --config
        const { stdout, stderr } = await execFileAsync("semgrep", ["--quiet", "--json", "--config", config, path])
        const dat = JSON.parse(stdout)
        for(const result of dat.results){
            hits.push({"id": config, "start": result.start.offset, "end": result.end.offset}) //TODO: Get proper ID, message, fix, etc. by parsing the Semgrep YAML config or Semgrep output?
        }
    }
    return hits
}

const regexScan = async function (rules, path){
    var hits = []
    for(const rule of rules){ //Note: Regex is applied line-by-line as opposed to Semgrep, which is applied file-by-file
        var line_no = 0
        var rd = readline.createInterface({input: fs.createReadStream(path), console: false})
        for await(const line of rd){
            line_no += 1
            if(rule.regex instanceof RegExp){ //Can provide start and end indices since this is a simple regex rule (not a regex tree)
                let match
                while((match = rule.regex.exec(line)) !== null) {
                    hits.push({"id": rule.id, "line_no": line_no, "start": match.index, "end": rule.regex.lastIndex})
                }
            } else {
                if(applyRegexCheck(rule.regex, "regex_and", line)) {
                    hits.push({"id": rule.id, "line_no": line_no})
                }
            }
        }
    }
    return hits
}

function scan(path){
  Promise.all([semgrepScan(semgrepRules, path), regexScan(regexRules, path)]).then((values) => {
    console.log(values)
  })
}

function applyRegexCheck(node, parent_type, text){ //Assumes tree is valid
    var res
    if(parent_type === "regex" || parent_type === "regex_and"){
        res = true //Neutral element of AND is 1
        for(const field of node){
            const propertyNames = Object.getOwnPropertyNames(field)
            const key = propertyNames[0]        
            const val = field[key]

            if(val instanceof RegExp){
                if(key === "regex_not"){
                    res &= !(val.test(text))
                } else {
                    res &= val.test(text)
                }
            } else {
                res &= applyRegexCheck(val, key, text)
            }
        }
    } else { //regex_or
        res = false //Neutral element of OR is 0
        for(const field of node){
            const propertyNames = Object.getOwnPropertyNames(field)
            const key = propertyNames[0]        
            const val = field[key]

            if(val instanceof RegExp){
                if(key === "regex_not"){
                    res |= !(val.test(text))
                } else {
                    res |= val.test(text)
                }
            } else {
                res |= applyRegexCheck(val, key, text)
            }
        }
    }
    return res
}

var semgrepRules = []
var regexRules = []

function validateRegexTree(node) {
    for(const field of node){
        const propertyNames = Object.getOwnPropertyNames(field)
        if(propertyNames.length !== 1){
            throw "Expected 1 property name, got " + propertyNames.length + " (" + propertyNames + ")"
        }

        const key = propertyNames[0]
        if(key !== "regex" && key !== "regex_and" && key !== "regex_or" && key !== "regex_not"){
            throw "Unknown key name " + key
        }
        
        const val = field[key]
        const val_type = typeof val //TODO: Should val_type be strictly enforced?
        /*if(val_type !== "string" && val_type !== "object"){
            throw "Unknown value type " + val_type
        }*/

        if(val_type === "object"){
            if(key === "regex_not"){
                throw "regex_not cannot be used on a regex subtree"
            }
            validateRegexTree(val)
        } else {
            if(key === "regex_or"){
                throw "regex_or can only be used on a regex subtree"
            }
            field[key] = new RegExp(field[key], 'g') //Compile regex while validating tree
        }
    }
}

function loadRegexRules(path) {
    const cfg = fs.readFileSync(path, 'utf8')
    const dat = yaml.parse(cfg)
    for(const rule of dat.rules){ //TODO: Implement fix for Regex?
        if(!('id' in rule)){
            throw "rule is missing 'id' field"
        }
        if(!('message' in rule)){
            throw "rule is missing 'message' field"
        }
        if(!('severity' in rule)){
            throw "rule is missing 'severity' field"
        }
        if(!('regex' in rule)){
            throw "rule is missing 'regex' field"
        } //TODO: Throw error on unrecognized fields (fix, metadata optional)

        if(typeof rule.regex === "object"){
	    validateRegexTree(rule.regex)
        } else { //TODO: Should val_type be strictly enforced?
            rule.regex = new RegExp(rule.regex, 'g') //Compile regex while validating
        }
        regexRules.push(rule)
    }
    //console.log(util.inspect(regexRules, false, null, true))
}

function loadSemgrepRules(path) { //TODO: Do proper data validation?
    semgrepRules.push(path)
}

loadRegexRules('rules.yml')
loadSemgrepRules('semgrep.yml')

console.time('test')
scan("sample.js")
console.timeEnd('test')