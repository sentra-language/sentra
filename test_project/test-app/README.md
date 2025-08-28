# test-app

A command-line tool built with Sentra.

## Installation

Build the tool:
```bash
sentra build
```

## Usage

```bash
sentra run main.sn <command> [args...]
```

### Commands

- help - Show help message
- version - Show version information
- process - Process input files
- analyze - Analyze data

## Examples

```bash
sentra run main.sn process input.txt
sentra run main.sn analyze --verbose
```

## License

MIT
