---
layout: default
title: Reference
nav_order: 3
has_children: true
permalink: /reference/
---

# Reference
{: .fs-9 }

Complete technical reference for the Sentra programming language, standard library, and security modules.
{: .fs-6 .fw-300 }

---

## Documentation Sections

### Language Reference
{: .text-delta }

Complete documentation of Sentra's syntax, grammar, and language features.

[Language Reference](language/){: .btn .btn-outline .mr-2 }
[Quick Reference](quick/){: .btn .btn-outline }

### Standard Library
{: .text-delta }

Detailed API documentation for all built-in functions and modules.

[Standard Library](stdlib/){: .btn .btn-outline .mr-2 }

## Quick Links

| Topic | Description |
|:------|:------------|
| [Language Reference](language/) | Syntax, operators, control flow, functions |
| [Standard Library](stdlib/) | Built-in functions, file I/O, string operations |
| [Quick Reference](quick/) | Cheat sheet for common operations |

## Need Help?

- Browse [Examples](https://github.com/sentra-language/sentra/tree/main/examples)
- Check the [Tutorial]({{ site.baseurl }}/tutorial/) for guided learning
- Open an [Issue on GitHub](https://github.com/sentra-language/sentra/issues)

# Sentra Language Reference

This reference manual describes the Sentra programming language. It describes the syntax and semantics of the language, providing a complete specification.

## Table of Contents

### 1. [Lexical Analysis](/reference/lexical/)
- [Tokens](/reference/lexical/#tokens)
- [Comments](/reference/lexical/#comments)
- [Identifiers](/reference/lexical/#identifiers)
- [Keywords](/reference/lexical/#keywords)
- [Literals](/reference/lexical/#literals)
- [Operators](/reference/lexical/#operators)

### 2. [Data Model](/reference/datamodel/)
- [Objects and Types](/reference/datamodel/#objects)
- [Numbers](/reference/datamodel/#numbers)
- [Strings](/reference/datamodel/#strings)
- [Arrays](/reference/datamodel/#arrays)
- [Maps](/reference/datamodel/#maps)
- [Functions](/reference/datamodel/#functions)
- [Null](/reference/datamodel/#null)

### 3. [Expressions](/reference/expressions/)
- [Arithmetic Operations](/reference/expressions/#arithmetic)
- [Comparison Operations](/reference/expressions/#comparison)
- [Logical Operations](/reference/expressions/#logical)
- [Function Calls](/reference/expressions/#calls)
- [Indexing](/reference/expressions/#indexing)
- [Lambda Expressions](/reference/expressions/#lambda)

### 4. [Statements](/reference/statements/)
- [Simple Statements](/reference/statements/#simple)
- [Assignment](/reference/statements/#assignment)
- [Control Flow](/reference/statements/#control-flow)
- [Loops](/reference/statements/#loops)
- [Function Definitions](/reference/statements/#functions)
- [Import Statements](/reference/statements/#import)

### 5. [Functions](/reference/functions/)
- [Function Definitions](/reference/functions/#definitions)
- [Parameters](/reference/functions/#parameters)
- [Return Values](/reference/functions/#return)
- [Closures](/reference/functions/#closures)
- [Lambda Functions](/reference/functions/#lambda)
- [Built-in Functions](/reference/functions/#builtin)

### 6. [Modules](/reference/modules/)
- [Module System](/reference/modules/#system)
- [Import Mechanism](/reference/modules/#import)
- [Export Mechanism](/reference/modules/#export)
- [Module Search Path](/reference/modules/#search)
- [Standard Modules](/reference/modules/#standard)

### 7. [Error Handling](/reference/errors/)
- [Exceptions](/reference/errors/#exceptions)
- [Try-Catch-Finally](/reference/errors/#try-catch)
- [Throwing Errors](/reference/errors/#throw)
- [Error Types](/reference/errors/#types)
- [Stack Traces](/reference/errors/#traces)

### 8. [Concurrency](/reference/concurrency/)
- [Goroutines](/reference/concurrency/#goroutines)
- [Channels](/reference/concurrency/#channels)
- [Select Statement](/reference/concurrency/#select)
- [Synchronization](/reference/concurrency/#sync)

## Language Grammar

### BNF Notation

The grammar is specified using Extended Backus-Naur Form (EBNF):

```ebnf
program        ::= statement*
statement      ::= simple_stmt | compound_stmt
simple_stmt    ::= expression_stmt | assignment_stmt | return_stmt
compound_stmt  ::= if_stmt | while_stmt | for_stmt | function_def

expression     ::= term (('+' | '-') term)*
term           ::= factor (('*' | '/' | '%') factor)*
factor         ::= primary | '-' factor | '!' factor
primary        ::= NUMBER | STRING | IDENTIFIER | '(' expression ')'

assignment_stmt ::= ('let' | 'var' | 'const') IDENTIFIER '=' expression
if_stmt        ::= 'if' expression '{' statement* '}' ('else' '{' statement* '}')?
while_stmt     ::= 'while' expression '{' statement* '}'
for_stmt       ::= 'for' IDENTIFIER 'in' expression '{' statement* '}'
function_def   ::= 'fn' IDENTIFIER '(' parameters? ')' '{' statement* '}'
```

## Type System

Sentra is dynamically typed with the following built-in types:

| Type | Description | Example |
|------|-------------|---------|
| `Number` | 64-bit floating point | `42`, `3.14`, `-0.5` |
| `String` | UTF-8 text | `"hello"`, `'world'` |
| `Boolean` | True or false | `true`, `false` |
| `Null` | Absence of value | `null` |
| `Array` | Ordered collection | `[1, 2, 3]` |
| `Map` | Key-value pairs | `{"key": "value"}` |
| `Function` | Callable object | `fn(x) => x * 2` |

## Operator Precedence

From highest to lowest precedence:

| Precedence | Operators | Description |
|------------|-----------|-------------|
| 1 | `()` `[]` `.` | Grouping, indexing, member access |
| 2 | `!` `-` (unary) | Logical NOT, negation |
| 3 | `*` `/` `%` | Multiplication, division, modulo |
| 4 | `+` `-` | Addition, subtraction |
| 5 | `<` `<=` `>` `>=` | Comparison |
| 6 | `==` `!=` | Equality |
| 7 | `&&` | Logical AND |
| 8 | `\|\|` | Logical OR |
| 9 | `=` | Assignment |

## Memory Model

Sentra uses automatic memory management with garbage collection:

- **Stack**: Local variables and function calls
- **Heap**: Dynamic allocations (arrays, maps, closures)
- **Constants Pool**: Compile-time constants
- **Global Space**: Global variables and functions

## Execution Model

1. **Lexical Analysis**: Source → Tokens
2. **Parsing**: Tokens → AST
3. **Compilation**: AST → Bytecode
4. **Execution**: VM runs bytecode

### Virtual Machine

- Stack-based architecture
- 70+ opcodes
- Call frames for function invocation
- Upvalues for closures
- Thread-safe operations

## Security Features

Built-in security capabilities:

- **Sandboxing**: Restricted execution environment
- **Resource Limits**: Memory and CPU constraints
- **Safe Defaults**: Secure-by-default operations
- **Input Validation**: Automatic sanitization
- **Crypto Primitives**: Hardware-accelerated when available

## Standard Library

Core modules included:

- **I/O**: File and network operations
- **Security**: Cryptography and scanning
- **Data**: JSON, CSV, XML processing
- **System**: OS and process interaction
- **Network**: HTTP, TCP, UDP protocols
- **Testing**: Unit testing framework

## Implementation Notes

- **Written in**: Go 1.20+
- **Performance**: ~450μs per operation
- **Memory**: ~1.2MB base usage
- **Concurrency**: Goroutine-based
- **Platform**: Cross-platform (Windows, macOS, Linux)

## Version History

- **1.0.0** (2024-12) - First stable release
- **0.9.0** (2024-11) - Beta release
- **0.8.0** (2024-10) - Alpha release

## See Also

- [Tutorial](/tutorial/) - Learn Sentra step by step
- [Library Reference](/library/) - Standard library documentation
- [How-to Guides](/guide/) - Practical recipes
- [Examples](https://github.com/sentra-language/examples) - Sample code

---

<div class="reference-nav">
    <a href="/" class="nav-home">← Home</a>
    <a href="/reference/lexical/" class="nav-next">Lexical Analysis →</a>
</div>