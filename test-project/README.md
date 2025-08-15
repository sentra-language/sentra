# test-project

A Sentra security automation project.

## Getting Started

### Prerequisites

- Sentra runtime installed
- Go 1.21+ (for building from source)

### Installation

1. Install dependencies:
   ```bash
   sentra mod install
   ```

2. Run the project:
   ```bash
   sentra run main.sn
   ```

### Building

To build a distributable bundle:

```bash
sentra build
```

This will create a compiled bundle in the `dist/` directory.

## Project Structure

- `main.sn` - Entry point
- `sentra.json` - Project manifest
- `vendor/` - Dependencies (auto-generated)
- `dist/` - Build output (auto-generated)

## License

MIT
