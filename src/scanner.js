const promisify = require("util").promisify
const execFile = require("child_process").execFile
const fs = require("fs")

const yaml = require('yaml')

const execFileAsync = promisify(execFile)

const semgrepScan = async function (rules, path){
    var hits = []
    for(const rule of rules){
        const pattern = rule.pattern
        //console.log("semgrep", pattern)
        const { stdout, stderr } = await execFileAsync("semgrep", ["--quiet", "--json", "--pattern", pattern, "--lang", "generic", path], {timeout: 30 * 1000})
        const dat = JSON.parse(stdout)
        for(const result of dat.results){
            //console.log(result.start.line, result.start.col, "->", result.end.line, result.end.col)
            //console.log(`start=${result.start.offset} end=${result.end.offset}`)
            hits.push({"id": rule.id, "start": result.start.offset, "end": result.end.offset})
        }
    }
    return hits
}

const regexScan = async function (rules, path){
    var hits = []
    for(const rule of rules){
        const regex = rule.regex
        //console.log("regex", regex)
        const text = fs.readFileSync(path).toString('utf-8')
        let match
        while((match = regex.exec(text)) !== null) {
            //console.log(`${match[0]} start=${match.index} end=${regex.lastIndex}`)
            hits.push({"id": rule.id, "start": match.index, "end": regex.lastIndex})
        }
    }
    return hits
}

function scan(path){
  Promise.all([semgrepScan(semgrepRules, path), regexScan(regexRules, path)]).then((values) => {
    console.log(values)
  })
}

var semgrepRules = []
var regexRules = []

function loadRules() {
    const cfg = fs.readFileSync('rules.yml', 'utf8')
    const dat = yaml.parse(cfg)
    for(const rule of dat.rules){ //TODO: Throw error on unrecognized fields
        if(!('id' in rule)){
            throw "rule is missing 'id' field"
        }
        if(!('message' in rule)){
            throw "rule is missing 'message' field"
        }
        if(!('severity' in rule)){
            throw "rule is missing 'severity' field"
        }
        if(!('pattern' in rule) && !('regex' in rule)){
            throw "rule is missing 'pattern'/'regex' field"
        }
        if(('pattern' in rule) && ('regex' in rule)){
            throw "rule cannot have both a 'pattern'/'regex' field"
        }

        if('pattern' in rule){
            semgrepRules.push(rule)
        }
        if('regex' in rule){
            rule.regex = new RegExp(rule.regex, 'g')
            regexRules.push(rule)
        }
    }
    console.log(semgrepRules)
    console.log(regexRules)
}

loadRules()

console.time('test')
scan("/etc/hosts")
console.timeEnd('test')