const { DiagnosticCategory } = require("typescript");
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

    const ignoreLineAction = new vscode.CodeAction(
      `Disable VulnGuard for this line`,
      vscode.CodeActionKind.QuickFix
    );
    ignoreLineAction.edit = new vscode.WorkspaceEdit();
    if (range.start.line === 0) {
      const firstLine = new vscode.Range(
        range.start.line,
        0,
        range.start.line,
        range.start.character
      );
      ignoreLineAction.edit.replace(
        document.uri,
        firstLine,
        "// vulnguard-disable-*all* \n" + document.getText(firstLine)
      );
    } else {
      const commentLine = document.lineAt(range.start.line - 1);
      const commentLineRange = commentLine.range;
      const commentLineText = commentLine.text;
      if (
        commentLineText.trimStart().startsWith("//") &&
        commentLineText.includes("vulnguard-disable")
      ) {
        ignoreLineAction.edit.replace(
          document.uri,
          commentLineRange,
          "// vulnguard-disable-*all*"
        );
      } else {
        ignoreLineAction.edit.replace(
          document.uri,
          commentLineRange,
          commentLineText + "\n // vulnguard-disable-*all*"
        );
      }
    }
    outputActions.push(ignoreLineAction);

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
    ignoreLineRuleAction.edit = new vscode.WorkspaceEdit();
    if (diagnostic.range.start.line === 0) {
      const firstLine = new vscode.Range(
        diagnostic.range.start.line,
        0,
        diagnostic.range.start.line,
        diagnostic.range.start.character
      );
      ignoreLineRuleAction.edit.replace(
        document.uri,
        firstLine,
        `// vulnguard-disable-${diagnostic.code.value} \n` +
          document.getText(firstLine)
      );
    } else {
      const commentLine = document.lineAt(diagnostic.range.start.line - 1);
      const commentLineRange = commentLine.range;
      const commentLineText = commentLine.text;
      if (
        commentLineText.trimStart().startsWith("//") &&
        commentLineText.includes("vulnguard-disable")
      ) {
        ignoreLineRuleAction.edit.replace(
          document.uri,
          commentLineRange,
          commentLineText + ` vulnguard-disable-${diagnostic.code.value}`
        );
      } else {
        ignoreLineRuleAction.edit.replace(
          document.uri,
          commentLineRange,
          commentLineText + `\n// vulnguard-disable-${diagnostic.code.value}`
        );
      }
    }

    // const ignoreLineAction = new vscode.CodeAction(
    //   `Disable all VulnGuard checks for this line`,
    //   vscode.CodeActionKind.QuickFix
    // );
    // const firstLine = new vscode.Range(
    //   diagnostic.range.start.line,
    //   0,
    //   diagnostic.range.start.line,
    //   diagnostic.range.start.character
    // );
    // ignoreLineAction.edit = new vscode.WorkspaceEdit();
    // ignoreLineAction.edit.replace(
    //   document.uri,
    //   firstLine,
    //   `// vulnguard-disable-${diagnostic.code.value} \n` +
    //     document.getText(firstLine)
    // );

    return diagnostic.tags
      ? [fixAction, ignoreLineRuleAction]
      : [ignoreLineRuleAction];
  }
}

module.exports = {
  FixVulnCodeActionProvider,
};
