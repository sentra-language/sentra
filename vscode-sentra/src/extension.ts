import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { spawn, exec } from 'child_process';

let outputChannel: vscode.OutputChannel;
let sentraPath: string = 'sentra';

export function activate(context: vscode.ExtensionContext) {
    console.log('Sentra extension is now active');
    
    outputChannel = vscode.window.createOutputChannel('Sentra');
    
    // Auto-detect Sentra interpreter
    if (vscode.workspace.getConfiguration('sentra').get('autoDetectInterpreter')) {
        detectSentraInterpreter();
    } else {
        sentraPath = vscode.workspace.getConfiguration('sentra').get('interpreterPath') || 'sentra';
    }
    
    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('sentra.run', runCurrentFile),
        vscode.commands.registerCommand('sentra.runSelection', runSelection),
        vscode.commands.registerCommand('sentra.checkSyntax', checkSyntax),
        vscode.commands.registerCommand('sentra.installPackage', installPackage),
        vscode.commands.registerCommand('sentra.openRepl', openRepl)
    );
    
    // Register code lens provider for running functions
    context.subscriptions.push(
        vscode.languages.registerCodeLensProvider(
            { language: 'sentra' },
            new SentraCodeLensProvider()
        )
    );
    
    // Register hover provider for function documentation
    context.subscriptions.push(
        vscode.languages.registerHoverProvider(
            { language: 'sentra' },
            new SentraHoverProvider()
        )
    );
    
    // Register completion provider
    context.subscriptions.push(
        vscode.languages.registerCompletionItemProvider(
            { language: 'sentra' },
            new SentraCompletionProvider(),
            '.'
        )
    );
    
    // Register diagnostic provider for syntax errors
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('sentra');
    context.subscriptions.push(diagnosticCollection);
    
    // Lint on save
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument((document) => {
            if (document.languageId === 'sentra' && 
                vscode.workspace.getConfiguration('sentra.linting').get('lintOnSave')) {
                lintDocument(document, diagnosticCollection);
            }
        })
    );
    
    // Lint open documents
    vscode.workspace.textDocuments.forEach((document) => {
        if (document.languageId === 'sentra') {
            lintDocument(document, diagnosticCollection);
        }
    });
}

function detectSentraInterpreter() {
    // Try to find Sentra in PATH
    exec('where sentra', (error, stdout, stderr) => {
        if (!error && stdout) {
            sentraPath = stdout.trim().split('\n')[0];
            vscode.window.showInformationMessage(`Sentra interpreter found: ${sentraPath}`);
        } else {
            // Try common locations
            const commonPaths = [
                'C:\\Users\\pc\\Projects\\sentra\\sentra.exe',
                'C:\\Program Files\\Sentra\\sentra.exe',
                '/usr/local/bin/sentra',
                '/usr/bin/sentra',
                './sentra.exe',
                './sentra'
            ];
            
            for (const path of commonPaths) {
                if (fs.existsSync(path)) {
                    sentraPath = path;
                    vscode.window.showInformationMessage(`Sentra interpreter found: ${sentraPath}`);
                    break;
                }
            }
        }
    });
}

async function runCurrentFile() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showErrorMessage('No active editor');
        return;
    }
    
    if (editor.document.languageId !== 'sentra') {
        vscode.window.showErrorMessage('Current file is not a Sentra file');
        return;
    }
    
    const filePath = editor.document.fileName;
    await editor.document.save();
    
    outputChannel.clear();
    outputChannel.show();
    outputChannel.appendLine(`Running: ${path.basename(filePath)}`);
    outputChannel.appendLine('─'.repeat(50));
    
    const process = spawn(sentraPath, ['run', filePath], {
        cwd: path.dirname(filePath)
    });
    
    process.stdout.on('data', (data) => {
        outputChannel.append(data.toString());
    });
    
    process.stderr.on('data', (data) => {
        outputChannel.append(`[ERROR] ${data.toString()}`);
    });
    
    process.on('close', (code) => {
        outputChannel.appendLine('─'.repeat(50));
        outputChannel.appendLine(`Process exited with code ${code}`);
    });
}

async function runSelection() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showErrorMessage('No active editor');
        return;
    }
    
    const selection = editor.document.getText(editor.selection);
    if (!selection) {
        vscode.window.showErrorMessage('No code selected');
        return;
    }
    
    // Create temporary file
    const tempFile = path.join(require('os').tmpdir(), `sentra_temp_${Date.now()}.sn`);
    fs.writeFileSync(tempFile, selection);
    
    outputChannel.clear();
    outputChannel.show();
    outputChannel.appendLine('Running selected code...');
    outputChannel.appendLine('─'.repeat(50));
    
    const process = spawn(sentraPath, ['run', tempFile]);
    
    process.stdout.on('data', (data) => {
        outputChannel.append(data.toString());
    });
    
    process.stderr.on('data', (data) => {
        outputChannel.append(`[ERROR] ${data.toString()}`);
    });
    
    process.on('close', (code) => {
        fs.unlinkSync(tempFile);
        outputChannel.appendLine('─'.repeat(50));
        outputChannel.appendLine(`Process exited with code ${code}`);
    });
}

async function checkSyntax() {
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.document.languageId !== 'sentra') {
        vscode.window.showErrorMessage('No active Sentra file');
        return;
    }
    
    await editor.document.save();
    const filePath = editor.document.fileName;
    
    exec(`${sentraPath} check "${filePath}"`, (error, stdout, stderr) => {
        if (error) {
            vscode.window.showErrorMessage(`Syntax error: ${stderr || error.message}`);
        } else {
            vscode.window.showInformationMessage('Syntax is valid');
        }
    });
}

async function installPackage() {
    const packageName = await vscode.window.showInputBox({
        prompt: 'Enter package name (e.g., github.com/user/package)',
        placeHolder: 'github.com/sentra-packages/example'
    });
    
    if (!packageName) {
        return;
    }
    
    outputChannel.show();
    outputChannel.appendLine(`Installing package: ${packageName}`);
    
    // For now, using git clone approach similar to Go
    const packageDir = path.join(
        vscode.workspace.rootPath || '.',
        'sentra_modules',
        packageName.replace(/[\/\\]/g, '_')
    );
    
    exec(`git clone https://${packageName} "${packageDir}"`, (error, stdout, stderr) => {
        if (error) {
            outputChannel.appendLine(`Error: ${stderr || error.message}`);
            vscode.window.showErrorMessage(`Failed to install package: ${packageName}`);
        } else {
            outputChannel.appendLine(`Package installed: ${packageName}`);
            vscode.window.showInformationMessage(`Package installed: ${packageName}`);
        }
    });
}

function openRepl() {
    const terminal = vscode.window.createTerminal('Sentra REPL');
    terminal.show();
    terminal.sendText(`${sentraPath} repl`);
}

function lintDocument(document: vscode.TextDocument, diagnosticCollection: vscode.DiagnosticCollection) {
    if (!vscode.workspace.getConfiguration('sentra.linting').get('enabled')) {
        return;
    }
    
    const diagnostics: vscode.Diagnostic[] = [];
    const text = document.getText();
    const lines = text.split('\n');
    
    // Basic linting rules
    lines.forEach((line, i) => {
        // Check for undefined variables (simplified)
        const undefinedVarMatch = /\b(undefined|nil)\b/.exec(line);
        if (undefinedVarMatch) {
            const diagnostic = new vscode.Diagnostic(
                new vscode.Range(i, undefinedVarMatch.index!, i, undefinedVarMatch.index! + undefinedVarMatch[0].length),
                'Possible use of undefined variable',
                vscode.DiagnosticSeverity.Warning
            );
            diagnostics.push(diagnostic);
        }
        
        // Check for missing semicolons (if required)
        if (line.trim() && !line.trim().endsWith(';') && !line.trim().endsWith('{') && !line.trim().endsWith('}')) {
            // This is optional based on Sentra's syntax rules
        }
    });
    
    diagnosticCollection.set(document.uri, diagnostics);
}

class SentraCodeLensProvider implements vscode.CodeLensProvider {
    provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
        const codeLenses: vscode.CodeLens[] = [];
        const text = document.getText();
        const functionRegex = /fn\s+(\w+)\s*\([^)]*\)\s*{/g;
        
        let match;
        while ((match = functionRegex.exec(text)) !== null) {
            const line = document.positionAt(match.index).line;
            const range = new vscode.Range(line, 0, line, 0);
            
            const codeLens = new vscode.CodeLens(range, {
                title: '▶ Run Function',
                command: 'sentra.runFunction',
                arguments: [match[1]]
            });
            
            codeLenses.push(codeLens);
        }
        
        return codeLenses;
    }
}

class SentraHoverProvider implements vscode.HoverProvider {
    private functionDocs: Map<string, string> = new Map([
        ['port_scan', '**port_scan**(host: string, start: int, end: int, protocol: string) → array\n\nScans ports on the specified host.\n\n**Parameters:**\n- host: Target IP or hostname\n- start: Starting port number\n- end: Ending port number\n- protocol: "TCP" or "UDP"\n\n**Returns:** Array of port scan results'],
        ['sha256', '**sha256**(data: string) → string\n\nCalculates SHA-256 hash of the input data.\n\n**Parameters:**\n- data: Input string to hash\n\n**Returns:** Hexadecimal hash string'],
        ['fs_create_baseline', '**fs_create_baseline**(path: string, recursive: bool) → bool\n\nCreates a filesystem baseline for integrity monitoring.\n\n**Parameters:**\n- path: Directory path to baseline\n- recursive: Include subdirectories\n\n**Returns:** Success status'],
        ['conc_create_worker_pool', '**conc_create_worker_pool**(id: string, size: int, capacity: int) → bool\n\nCreates a new worker pool for parallel processing.\n\n**Parameters:**\n- id: Unique pool identifier\n- size: Number of workers\n- capacity: Job queue capacity\n\n**Returns:** Success status']
    ]);
    
    provideHover(document: vscode.TextDocument, position: vscode.Position): vscode.Hover | null {
        const range = document.getWordRangeAtPosition(position);
        if (!range) {
            return null;
        }
        
        const word = document.getText(range);
        const doc = this.functionDocs.get(word);
        
        if (doc) {
            return new vscode.Hover(new vscode.MarkdownString(doc));
        }
        
        return null;
    }
}

class SentraCompletionProvider implements vscode.CompletionItemProvider {
    provideCompletionItems(document: vscode.TextDocument, position: vscode.Position): vscode.CompletionItem[] {
        const completions: vscode.CompletionItem[] = [];
        
        // Security functions
        const securityFunctions = [
            { label: 'port_scan', detail: 'Scan network ports' },
            { label: 'sha256', detail: 'Calculate SHA-256 hash' },
            { label: 'fs_create_baseline', detail: 'Create filesystem baseline' },
            { label: 'web_scan_xss', detail: 'Scan for XSS vulnerabilities' },
            { label: 'db_scan_injection', detail: 'Scan for SQL injection' },
            { label: 'crypto_analyze_tls', detail: 'Analyze TLS configuration' },
            { label: 'conc_create_worker_pool', detail: 'Create worker pool' },
            { label: 'report_create', detail: 'Create security report' }
        ];
        
        securityFunctions.forEach(func => {
            const item = new vscode.CompletionItem(func.label, vscode.CompletionItemKind.Function);
            item.detail = func.detail;
            completions.push(item);
        });
        
        return completions;
    }
}

export function deactivate() {
    if (outputChannel) {
        outputChannel.dispose();
    }
}