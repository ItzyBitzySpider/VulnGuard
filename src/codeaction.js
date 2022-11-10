const vscode = require("vscode");

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
    const outputActions = [];
    context.diagnostics.forEach((diagnostic) =>
      outputActions.push(...this.createCodeAction(document, diagnostic))
    );
    return outputActions;
  }

  /**
   *
   * @param {vscode.TextDocument} document
   * @param {vscode.Diagnostic} diagnostic
   * @returns {vscode.CodeAction}
   */
  createCodeAction(document, diagnostic) {
    const fixAction = new vscode.CodeAction(
      "Fix using VulnGuard suggestion",
      vscode.CodeActionKind.QuickFix
    );
    if (diagnostic.tags) {
      fixAction.edit = new vscode.WorkspaceEdit();
      fixAction.edit.replace(
        document.uri,
        diagnostic.range,
        diagnostic.tags[0]
      );
    }

    const ignoreLineRuleAction = new vscode.CodeAction(
      `Disable ${diagnostic.code.value} for this line`,
      vscode.CodeActionKind.QuickFix
    );
    const firstLine = new vscode.Range(
      diagnostic.range.start.line,
      0,
      diagnostic.range.start.line,
      diagnostic.range.start.character
    );
    ignoreLineRuleAction.edit = new vscode.WorkspaceEdit();
    ignoreLineRuleAction.edit.replace(
      document.uri,
      firstLine,
      `// vulnguard-disable-${diagnostic.code.value} \n` +
        document.getText(firstLine)
    );

    return diagnostic.tags
      ? [fixAction, ignoreLineRuleAction]
      : [ignoreLineRuleAction];
  }
}

module.exports = {
  FixVulnCodeActionProvider,
};
