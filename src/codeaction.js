const vscode = require("vscode");
const { FIX_VULN_CODE } = require("./globals");

class FixVulnCodeActionProvider {
  constructor() {
    this.providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];
  }

  /**
   *
   * @param {vscode.TextDocument} document
   * @param {vscode.Range} range
   * @param {vscode.CodeActionContext} context
   * @param {vscode.CancellationToken} token
   * @returns {vscode.CodeAction[] | undefined}
   */

  provideCodeActions(document, range, context, token) {
    // for each diagnostic entry that has the matching `code`, create a code action command
    console.log(document, range);
    console.log(
      context.diagnostics
        .filter((diagnostic) => diagnostic.code === FIX_VULN_CODE)
        .map((diagnostic) => this.createCommandCodeAction(document, diagnostic))
    );
    console.log(context.diagnostics);
    return context.diagnostics
      .filter((diagnostic) => diagnostic.code === FIX_VULN_CODE)
      .map((diagnostic) => this.createCommandCodeAction(document, diagnostic));
  }

  /**
   *
   * @param {vscode.TextDocument} document
   * @param {vscode.Diagnostic} diagnostic
   */
  createCodeAction(document, diagnostic) {
    const fixAction = new vscode.CodeAction(
      "Fix bug",
      vscode.CodeActionKind.QuickFix
    );
    fixAction.edit = new vscode.WorkspaceEdit();
    fixAction.edit.replace(
      document.uri,
      new vscode.Range(
        diagnostic.range.start,
        diagnostic.range.end.translate(0, " TEST OUTPUT".length)
      ),
      document.getText(diagnostic.range) + " TEST OUTPUT"
    );
  }
}

module.exports = { FixVulnCodeActionProvider };
