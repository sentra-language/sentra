# Task Management System

A comprehensive multi-file Sentra project demonstrating real-world application structure with imports, modules, and proper separation of concerns.

## Project Structure

```
example-project/
├── main.sn                 # Entry point
├── sentra.toml            # Project configuration
├── config/
│   └── settings.sn        # Application configuration
├── src/
│   ├── app.sn            # Application core logic
│   ├── controllers/      # Business logic controllers
│   │   ├── task_controller.sn
│   │   └── user_controller.sn
│   ├── models/           # Data models
│   │   ├── task.sn
│   │   └── user.sn
│   ├── services/         # External services
│   │   ├── auth.sn
│   │   └── database.sn
│   └── utils/            # Utility functions
│       ├── hash.sn
│       ├── id_generator.sn
│       ├── logger.sn
│       └── validator.sn
├── tests/                # Unit tests
│   └── task_controller_test.sn
└── lib/                  # Shared libraries
```

## Import System Demonstration

This project showcases Sentra's import system:

### 1. **Named Imports** (import as alias)
```sentra
import "./src/app.sn" as app
import "./config/settings.sn" as config
```

### 2. **Relative Imports**
```sentra
import "../models/task.sn" as Task
import "../services/database.sn" as db
```

### 3. **Deep Directory Imports**
```sentra
import "./controllers/task_controller.sn" as TaskController
import "./utils/logger.sn" as logger
```

### 4. **Export System**
Each module exports functions and variables:
```sentra
// In task_controller.sn
export fn create_task(title, priority, user_id) { ... }
export fn get_all_tasks() { ... }

// Used in app.sn
let task = TaskController.create_task("New Task", "High", user_id)
```

## Features

### Application Features
- User authentication and management
- Task creation and management
- Priority-based task organization
- Task statistics and reporting
- Mock database with CRUD operations
- Structured logging system
- Input validation and sanitization

### Code Organization
- **Models**: Define data structures (User, Task)
- **Controllers**: Handle business logic
- **Services**: External service integration (auth, database)
- **Utils**: Reusable utility functions
- **Config**: Centralized configuration management

## Running the Project

### Run the application
```bash
sentra run main.sn
```

### Run tests
```bash
sentra test tests/task_controller_test.sn
```

### Build executable
```bash
sentra build
./task-manager  # or task-manager.exe on Windows
```

### Format code
```bash
sentra fmt src/**/*.sn
```

### Check syntax
```bash
sentra check main.sn
```

## Key Concepts Demonstrated

1. **Module System**: Each file is a module that can export functions and variables
2. **Namespace Management**: Using aliases to avoid naming conflicts
3. **Separation of Concerns**: Clear separation between models, controllers, and services
4. **Mock Services**: Database service demonstrates how external services would be integrated
5. **Error Handling**: Try-catch blocks for error handling
6. **Validation**: Input validation before processing
7. **Logging**: Structured logging with different log levels
8. **Configuration**: Centralized configuration management
9. **Testing**: Unit tests for controllers

## Import Resolution

Sentra resolves imports in the following order:
1. Relative paths (starting with `./ `or `../`)
2. Project root paths
3. Standard library modules
4. External packages (from sentra.mod)

## Best Practices

1. **Use clear module aliases**: `import "./long/path/to/module.sn" as Module`
2. **Export only what's needed**: Keep internal functions private
3. **Organize by feature**: Group related functionality together
4. **Validate inputs**: Always validate external inputs
5. **Handle errors gracefully**: Use try-catch for error handling
6. **Log important events**: Use structured logging for debugging
7. **Write tests**: Test critical business logic

## Extending the Project

To add new features:

1. Create new model in `src/models/`
2. Add controller in `src/controllers/`
3. Update services if needed
4. Import and use in `app.sn`
5. Add tests in `tests/`

Example: Adding a Comment feature
```sentra
// src/models/comment.sn
export fn new(id, task_id, user_id, text) {
    return {
        "id": id,
        "task_id": task_id,
        "user_id": user_id,
        "text": text,
        "created_at": now()
    }
}

// src/controllers/comment_controller.sn
import "../models/comment.sn" as Comment

export fn create_comment(task_id, user_id, text) {
    return Comment.new(generate_id(), task_id, user_id, text)
}
```

## License

MIT License - Feel free to use this as a template for your Sentra projects!