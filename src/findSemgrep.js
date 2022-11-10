const which = require("which");
const vscode = require("vscode");
const extension = require("./extension");
const Global = require("./globals");

const SEMGREP_BINARY = "semgrep";

async function findSemgrep(ctx) {
  if (process.platform === "win32") {
    console.log("Windows Detected - Semgrep Disabled");
    Global.semgrepServer = undefined;
    return;
  }

  const server = which.sync(SEMGREP_BINARY, { nothrow: true });
  if (!server) {
    const brew = which.sync("brew", { nothrow: true });
    const pip = which.sync("pip", { nothrow: true });
    const pip3 = which.sync("pip3", { nothrow: true });
    const pip_install = "Install with pip (Preferred)";
    const brew_install = "Install with brew";
    const resp = await vscode.window.showInformationMessage(
      "Semgrep is not installed! Please install to use this extension",
      pip_install,
      brew_install
    );
    let command = null;
    switch (resp) {
      case pip_install:
        command = pip3 ? pip3 : pip;
        break;
      case brew_install:
        command = brew;
        break;
    }
    if (command) {
      const terminal = vscode.window.createTerminal(`Ext Terminal #1`);
      terminal.sendText(command + " install semgrep && exit");
      vscode.window.onDidCloseTerminal((t) => {
        if (t == terminal) {
          vscode.window.showInformationMessage(
            "Semgrep successfully installed"
          );
          if (resp == brew_install) {
            vscode.window.showInformationMessage(
              "Please run *sudo launchctl config user path '$(brew --prefix)/bin:${PATH}'* and restart to enable Semgrep. See [https://docs.brew.sh/FAQ#my-mac-apps-dont-find-homebrew-utilities]"
            );
          }
          extension.activate(ctx);
        }
      });
    } else if (resp) {
      vscode.window.showErrorMessage(
        "Error: chosen package manager not installed"
      );
    }
    Global.semgrepServer = null;
    return;
  }
  Global.semgrepServer = server;
}

module.exports = findSemgrep;
