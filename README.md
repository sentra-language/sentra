# Sentra VM

Sentra VM is a virtual machine designed to execute bytecode instructions efficiently. This project defines a set of opcodes that represent various operations that can be performed by the virtual machine.

## Project Structure

```
sentra_vm
├── internal
│   └── bytecode
│       └── opcodes.go
├── go.mod
└── README.md
```

## OpCodes

The `internal/bytecode/opcodes.go` file defines the `OpCode` type and a set of constants representing various opcodes used in the bytecode, including:

- `OpConstant`: Load a constant value.
- `OpAdd`: Add two values.
- `OpSub`: Subtract one value from another.
- `OpMul`: Multiply two values.
- `OpDiv`: Divide one value by another.
- `OpNegate`: Negate a value.
- `OpPrint`: Print a value.
- `OpReturn`: Return from a function.

## Getting Started

To get started with the project, clone the repository and run the following commands:

```bash
go mod tidy
```

This will ensure that all dependencies are properly installed.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.