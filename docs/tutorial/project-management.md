---
layout: default
title: Project Management
parent: Tutorial
nav_order: 5
---

# Project Management with Sentra

Sentra provides powerful tools for creating, managing, and deploying projects. This guide covers everything from project initialization to dependency management.

## Creating a New Project

### Using the Project Generator

```bash
# Create a new project
sentra init my-awesome-app
cd my-awesome-app

# Create with template
sentra init --template web-api my-api-project
sentra init --template security-tool security-scanner
sentra init --template cli-tool my-cli

# List available templates
sentra templates list
```

### Project Structure

A typical Sentra project looks like this:

```
my-awesome-app/
├── sentra.toml          # Project configuration
├── main.sn              # Entry point
├── src/                 # Source files
│   ├── lib.sn          # Library modules
│   ├── utils.sn        # Utilities
│   └── modules/        # Custom modules
│       ├── auth.sn
│       └── database.sn
├── tests/              # Test files
│   ├── main_test.sn
│   └── utils_test.sn
├── examples/           # Example code
│   └── basic_usage.sn
├── docs/              # Documentation
│   └── README.md
├── assets/            # Static assets
└── dist/              # Build output
```

## Project Configuration

### sentra.toml

The `sentra.toml` file is the heart of your project configuration:

```toml
[package]
name = "my-awesome-app"
version = "1.0.0"
description = "An awesome Sentra application"
author = "Your Name <email@example.com>"
license = "MIT"
homepage = "https://github.com/yourname/my-awesome-app"
repository = "https://github.com/yourname/my-awesome-app"
keywords = ["sentra", "security", "networking"]

[dependencies]
# External dependencies will be supported in future versions
# http-client = "1.0"
# json-parser = "2.1"

[dev-dependencies]
# Development-only dependencies
# test-framework = "1.0"

[build]
target = "dist/"
optimize = true
include_assets = true

[test]
directory = "tests/"
pattern = "*.test.sn"
timeout = 30

[scripts]
start = "sentra run main.sn"
test = "sentra test"
build = "sentra build --optimize"
clean = "sentra clean"

[metadata]
# Custom metadata for your project
app_id = "com.example.my-awesome-app"
minimum_sentra_version = "1.0.0"
```

## Building and Running Projects

### Development Mode

```bash
# Run the main file
sentra run

# Run with arguments
sentra run -- --port 8080 --debug

# Run specific file
sentra run src/server.sn

# Run with environment variables
SENTRA_ENV=development sentra run

# Watch mode (auto-restart on changes)
sentra dev
```

### Building for Production

```bash
# Build optimized version
sentra build

# Build with specific target
sentra build --target dist/

# Build with optimization
sentra build --optimize --minify

# Cross-platform build (future feature)
sentra build --target windows --arch amd64
sentra build --target linux --arch arm64
```

### Cleaning Build Artifacts

```bash
# Clean build directory
sentra clean

# Clean everything including cache
sentra clean --all
```

## Testing

### Writing Tests

Create test files in the `tests/` directory:

```sentra
// tests/math_test.sn
import "../src/math.sn" as math_lib

fn test_addition() {
    let result = math_lib.add(2, 3)
    assert_eq(result, 5, "2 + 3 should equal 5")
}

fn test_division() {
    let result = math_lib.divide(10, 2)
    assert_eq(result, 5, "10 / 2 should equal 5")
}

fn test_division_by_zero() {
    let result = math_lib.divide(10, 0)
    assert_eq(result, null, "Division by zero should return null")
}

// Test with async/network operations
fn test_http_request() {
    let response = http_get("https://api.example.com/test")
    assert_eq(response["status_code"], 200, "Should get 200 response")
    assert_contains(response["body"], "success", "Response should contain success")
}
```

### Running Tests

```bash
# Run all tests
sentra test

# Run specific test file
sentra test tests/math_test.sn

# Run tests with pattern
sentra test --pattern "*_integration_*"

# Run tests with coverage
sentra test --coverage

# Run tests in watch mode
sentra test --watch

# Run tests with verbose output
sentra test --verbose
```

### Test Framework Functions

```sentra
// Assertion functions
assert_eq(actual, expected, message)
assert_ne(actual, expected, message)
assert_true(condition, message)
assert_false(condition, message)
assert_null(value, message)
assert_not_null(value, message)
assert_contains(container, item, message)
assert_type(value, expected_type, message)

// Setup and teardown
fn setup() {
    // Run before each test
    log("Setting up test environment")
}

fn teardown() {
    // Run after each test
    log("Cleaning up test environment")
}

fn setup_suite() {
    // Run once before all tests in file
    log("Setting up test suite")
}

fn teardown_suite() {
    // Run once after all tests in file
    log("Tearing down test suite")
}
```

## Module System

### Creating Modules

Create reusable modules in your `src/` directory:

```sentra
// src/modules/logger.sn
let log_level = "INFO"

fn set_level(level) {
    log_level = level
}

fn info(message) {
    if (should_log("INFO")) {
        log("[INFO] " + message)
    }
}

fn error(message) {
    if (should_log("ERROR")) {
        log("[ERROR] " + message)
    }
}

fn debug(message) {
    if (should_log("DEBUG")) {
        log("[DEBUG] " + message)
    }
}

fn should_log(level) {
    let levels = {"DEBUG": 0, "INFO": 1, "WARN": 2, "ERROR": 3}
    return levels[level] >= levels[log_level]
}

// Export functions for use in other files
export {
    "set_level": set_level,
    "info": info,
    "error": error,
    "debug": debug
}
```

### Using Modules

```sentra
// main.sn
import "src/modules/logger.sn" as logger
import "src/modules/database.sn" as db

fn main() {
    logger.set_level("DEBUG")
    logger.info("Application starting...")
    
    // Connect to database
    let connection = db.connect("localhost", 5432)
    if (connection) {
        logger.info("Database connected successfully")
    } else {
        logger.error("Failed to connect to database")
        return
    }
    
    // Application logic here
    run_application()
    
    logger.info("Application shutting down...")
}

main()
```

## Dependency Management (Future Feature)

### Adding Dependencies

```bash
# Add a dependency
sentra add http-client@1.0.0

# Add development dependency
sentra add --dev test-framework@2.0.0

# Add from Git repository
sentra add --git https://github.com/sentra-lang/awesome-lib

# Add local dependency
sentra add --path ../my-local-lib
```

### Managing Dependencies

```bash
# Install all dependencies
sentra install

# Update dependencies
sentra update

# Remove dependency
sentra remove http-client

# List dependencies
sentra list

# Show dependency tree
sentra tree
```

### Lock File

Dependencies are locked in `sentra.lock`:

```toml
[[package]]
name = "http-client"
version = "1.0.0"
source = "registry"
checksum = "abc123..."

[[package]]
name = "json-parser"
version = "2.1.0"
source = "registry"
checksum = "def456..."
dependencies = ["string-utils"]

[[package]]
name = "string-utils"
version = "1.5.0"
source = "registry"
checksum = "ghi789..."
```

## Environment Management

### Environment Variables

```sentra
// config.sn
fn get_config() {
    return {
        "port": env("PORT") || "8080",
        "database_url": env("DATABASE_URL") || "localhost:5432",
        "debug": env("DEBUG") == "true",
        "api_key": env("API_KEY") || "development-key"
    }
}

let config = get_config()
log("Running on port: " + config["port"])
```

### Environment Files

Create `.env` files for different environments:

```bash
# .env.development
PORT=3000
DEBUG=true
DATABASE_URL=localhost:5432
API_KEY=dev-key-123

# .env.production
PORT=80
DEBUG=false
DATABASE_URL=prod-db:5432
API_KEY=prod-key-456

# .env.test
PORT=3001
DEBUG=true
DATABASE_URL=localhost:5433
API_KEY=test-key-789
```

Load environment files:

```bash
# Load development environment
sentra run --env development

# Load specific env file
sentra run --env-file .env.custom

# Override with environment variables
SENTRA_ENV=production sentra run
```

## Scripts and Automation

### Custom Scripts

Define scripts in `sentra.toml`:

```toml
[scripts]
start = "sentra run main.sn"
dev = "sentra dev --watch"
test = "sentra test --coverage"
build = "sentra build --optimize"
deploy = "sentra build && ./deploy.sh"
lint = "sentra lint src/"
format = "sentra fmt src/"
docs = "sentra doc generate"
```

Run scripts:

```bash
# Run predefined scripts
sentra script start
sentra script test
sentra script deploy

# Or use the shorthand
sentra start
sentra test
sentra deploy
```

### Build Scripts

Create custom build scripts:

```sentra
// scripts/build.sn
import "src/builder.sn" as builder

fn main() {
    log("Starting custom build process...")
    
    // Clean previous build
    builder.clean_dist()
    
    // Compile source files
    builder.compile_sources()
    
    // Copy assets
    builder.copy_assets()
    
    // Generate documentation
    builder.generate_docs()
    
    // Create distribution package
    builder.create_package()
    
    log("Build completed successfully!")
}

main()
```

## Documentation Generation

### Automatic Documentation

```bash
# Generate documentation from comments
sentra doc generate

# Generate with custom template
sentra doc generate --template custom.html

# Generate API documentation
sentra doc api --output docs/api/

# Serve documentation locally
sentra doc serve --port 8000
```

### Documentation Comments

Write documentation in your code:

```sentra
/**
 * Calculates the area of a circle
 * @param radius The radius of the circle
 * @returns The area of the circle
 * @example
 *   let area = calculate_circle_area(5)
 *   log("Area: " + str(area))  // Area: 78.54
 */
fn calculate_circle_area(radius) {
    const PI = 3.14159
    return PI * radius * radius
}

/**
 * HTTP server for handling API requests
 * @class APIServer
 */
let APIServer = {
    /**
     * Starts the HTTP server
     * @param port The port to listen on
     * @param host The host to bind to
     */
    "start": fn(port, host) {
        let server = http_server_create(host, port)
        // Implementation here
    }
}
```

## Deployment

### Packaging

```bash
# Create distribution package
sentra package

# Create platform-specific packages
sentra package --target windows
sentra package --target linux
sentra package --target macos

# Create installer
sentra package --installer
```

### Docker Support

Create a `Dockerfile`:

```dockerfile
FROM sentra:latest

WORKDIR /app
COPY . .

RUN sentra install
RUN sentra build --optimize

EXPOSE 8080
CMD ["sentra", "start"]
```

Build and run:

```bash
# Build Docker image
docker build -t my-sentra-app .

# Run container
docker run -p 8080:8080 my-sentra-app
```

## Best Practices

### Project Structure

1. **Keep source files organized** - Use subdirectories for different concerns
2. **Separate tests** - Keep tests in dedicated `tests/` directory
3. **Version your dependencies** - Use specific versions in `sentra.toml`
4. **Document your code** - Use comments and generate documentation
5. **Use meaningful names** - Make file and directory names descriptive

### Configuration Management

1. **Use environment variables** - For configuration that changes between environments
2. **Don't commit secrets** - Use `.env` files and `.gitignore` them
3. **Validate configuration** - Check required settings on startup
4. **Provide defaults** - Have sensible defaults for optional configuration

### Testing Strategy

1. **Write tests early** - Start with simple tests and expand
2. **Test edge cases** - Include error conditions and boundary values
3. **Use descriptive test names** - Make test failures easy to understand
4. **Keep tests isolated** - Each test should be independent
5. **Mock external dependencies** - Don't rely on external services in tests

## Next Steps

- [Review Network Programming](../network-module/) - Build network-based projects
- [Review Security Tools](../security-module/) - Build security applications
- [Language Reference](../../reference/language/) - Complete syntax guide
- [View example projects](https://github.com/sentra-language/sentra/tree/main/examples) - Real-world applications

---

{: .fs-6 .fw-300 }
Congratulations! You've completed the Sentra tutorial. You now have the knowledge to build security tools, network applications, and automation scripts with Sentra.

[← Previous: Security Module](../security-module/){: .btn .btn-outline .mr-2 }
[View Examples on GitHub →](https://github.com/sentra-language/sentra/tree/main/examples){: .btn .btn-primary }

---

## What's Next?

Now that you've completed the tutorial:

- **[Browse Examples](https://github.com/sentra-language/sentra/tree/main/examples)** - See real-world Sentra applications
- **[Language Reference](../../reference/language/)** - Complete technical documentation  
- **[Join the Community](https://github.com/sentra-language/sentra)** - Contribute or get help
- **[Quick Reference](../../reference/quick/)** - Keep handy while coding