# Contributing to ddnstoextdns

Thank you for your interest in contributing to ddnstoextdns! This document provides guidelines and information for contributors.

## Getting Started

### Prerequisites

- Go 1.21 or later
- Docker (for building containers)
- kubectl (for Kubernetes deployment)
- Access to a Kubernetes cluster (for testing)

### Setting Up Development Environment

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/ddnstoextdns.git
   cd ddnstoextdns
   ```

2. Install dependencies:
   ```bash
   make install-deps
   ```

3. Run tests to verify setup:
   ```bash
   make test
   ```

## Development Workflow

### Making Changes

1. Create a new branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following the coding standards below

3. Add tests for new functionality

4. Run tests and linters:
   ```bash
   make test
   make lint
   ```

5. Build to ensure everything compiles:
   ```bash
   make build
   ```

### Coding Standards

- Follow standard Go conventions and idioms
- Use `gofmt` for formatting (run `make fmt`)
- Run `go vet` to catch common mistakes (run `make vet`)
- Write clear, descriptive commit messages
- Add comments for exported functions and types
- Keep functions focused and testable

### Testing

- Write unit tests for all new functionality
- Ensure all tests pass before submitting a PR
- Aim for good test coverage
- Use table-driven tests where appropriate

Example test structure:
```go
func TestFeature(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected string
    }{
        {"case1", "input1", "output1"},
        {"case2", "input2", "output2"},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := YourFunction(tt.input)
            if result != tt.expected {
                t.Errorf("got %v, want %v", result, tt.expected)
            }
        })
    }
}
```

### Commit Messages

Follow conventional commit format:

```
type(scope): subject

body

footer
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Test changes
- `refactor`: Code refactoring
- `style`: Code style changes (formatting, etc.)
- `chore`: Maintenance tasks

Example:
```
feat(tsig): add support for HMAC-SHA512

Add HMAC-SHA512 algorithm support for TSIG validation.
This allows better security for TSIG signatures.

Closes #123
```

## Pull Request Process

1. Update documentation if needed (README.md, EXAMPLES.md)

2. Add or update tests for your changes

3. Ensure all tests pass and code is formatted:
   ```bash
   make test
   make lint
   ```

4. Update CHANGELOG.md if applicable

5. Create a pull request with:
   - Clear title and description
   - Reference to related issues
   - Screenshots for UI changes (if applicable)

6. Wait for review and address feedback

7. Once approved, a maintainer will merge your PR

## Project Structure

```
.
├── cmd/
│   └── server/          # Main application entry point
├── pkg/                 # Public packages
│   ├── config/          # Configuration management
│   ├── tsig/            # TSIG validation
│   ├── update/          # DNS UPDATE parser
│   └── k8s/             # Kubernetes client
├── internal/            # Private packages
│   └── handler/         # DNS request handler
├── deploy/              # Deployment manifests
│   └── kubernetes/
├── .github/             # GitHub workflows
└── docs/                # Additional documentation
```

## Code Review Guidelines

Reviewers should check for:

- Code follows project conventions
- Tests are included and pass
- Documentation is updated
- No security vulnerabilities introduced
- Performance implications considered
- Error handling is appropriate
- Code is maintainable and readable

## Security

### Reporting Security Issues

Please DO NOT file public issues for security vulnerabilities. Instead, email the maintainers directly.

### Security Considerations

When contributing, consider:

- Input validation
- TSIG authentication
- Zone authorization
- Error messages (don't leak sensitive info)
- Dependency vulnerabilities

## Questions?

- Open an issue for bugs or feature requests
- Start a discussion for questions or ideas
- Check existing issues before creating new ones

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (MIT License).

## Thank You!

Your contributions make this project better. We appreciate your time and effort!
