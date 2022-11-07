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
    return context.diagnostics
      .filter((diagnostic) => diagnostic.tags.includes(FIX_VULN_CODE))
      .map((diagnostic) => this.createCodeAction(document, diagnostic.range));
  }

  /**
   *
   * @param {vscode.TextDocument} document
   * @param {vscode.Range} range
   * @returns {vscode.CodeAction}
   */
  createCodeAction(document, range) {
    const fixAction = new vscode.CodeAction(
      "Fix bug",
      vscode.CodeActionKind.QuickFix
    );
    //Copy range to avoid invalidArgument range
    const r = new vscode.Range(
      range.start.line,
      range.start.character,
      range.end.line,
      range.end.character
    );
    fixAction.edit = new vscode.WorkspaceEdit();
    fixAction.edit.replace(
      document.uri,
      r,
      document.getText(r) + " TEST OUTPUT"
    );
    return fixAction;
  }
}

module.exports = {
  FixVulnCodeActionProvider,
};
