# Contributing to Toonami Aftermath Downlink

Thank you for your interest in contributing! This guide will help you get started with development and ensure your contributions align with the project's standards.

## 🚀 Quick Start

### Prerequisites

- **Python 3.11+** (3.12 recommended)
- **Node.js 18+** (20 recommended)
- **Docker** (for testing containers)
- **Git**

### Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/zachyzissou/toonamiaftermath-downlink.git
   cd toonamiaftermath-downlink
   ```

2. **Set up Python environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Install Node.js dependencies**
   ```bash
   npm install
   ```

4. **Run the development server**
   ```bash
   npm run dev
   # or
   python run_dev.py
   ```

5. **Access the application**
   - Web UI: http://localhost:7004
   - API Documentation: http://localhost:7004/docs

## 🧪 Testing

### Running Tests

```bash
# Run all tests
npm test

# Run specific test suites
npm run test:unit        # Core logic tests
npm run test:integration # API endpoint tests  
npm run test:frontend    # UI/UX tests

# Run tests in Docker
docker build -t toonami-downlink:test .
docker run --rm toonami-downlink:test python test_logic.py
```

### Writing Tests

- **Unit tests**: Add to `test_logic.py` for core functionality
- **Integration tests**: Add to `test_integration.py` for API endpoints
- **Frontend tests**: Add to `test_frontend.py` for UI/accessibility

## 🎨 Code Quality

### Linting and Formatting

```bash
# Check code quality
npm run lint

# Auto-fix formatting
npm run format

# Individual tools
npm run lint:python      # Ruff + Black
npm run lint:js          # ESLint
npm run lint:md          # Markdownlint
```

### Code Style Guidelines

**Python**
- Follow PEP 8 (enforced by Black and Ruff)
- Use type hints for function parameters and returns
- Add docstrings for modules, classes, and public functions
- Maximum line length: 88 characters

**JavaScript**
- Use ES2022+ features
- 2-space indentation
- Single quotes for strings
- Semicolons required
- Use `const` for immutable variables

**CSS**
- Use CSS custom properties (variables)
- Follow BEM methodology for class names
- Mobile-first responsive design
- Optimize for accessibility

## 📁 Project Structure

```
toonamiaftermath-downlink/
├── app/                     # Python FastAPI backend
│   ├── server.py           # Main application server
│   ├── xtreme_codes.py     # Xtreme Codes API compatibility
│   └── __init__.py
├── web/                     # Frontend assets
│   ├── assets/             # CSS, JS, images
│   └── index.html          # Main UI template
├── .github/                # GitHub workflows and templates
├── docs/                   # Documentation
├── test_*.py              # Test files
├── Dockerfile             # Container definition
├── docker-compose.yml     # Local development setup
└── requirements.txt       # Python dependencies
```

## 🔄 Development Workflow

### Making Changes

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Follow the code style guidelines
   - Add tests for new functionality
   - Update documentation if needed

3. **Test your changes**
   ```bash
   npm test
   npm run lint
   ```

4. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: add your feature description"
   ```

5. **Push and create a PR**
   ```bash
   git push origin feature/your-feature-name
   ```

### Commit Message Format

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): short description

Longer description if needed

Fixes #123
```

**Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

## 🐛 Bug Reports

When reporting bugs, include:
- **Environment**: OS, Python version, Docker version
- **Steps to reproduce**
- **Expected vs actual behavior**
- **Logs/screenshots** if applicable
- **Configuration** (sanitized)

## ✨ Feature Requests

For new features:
- **Use case**: Why is this needed?
- **Proposed solution**: How should it work?
- **Alternatives considered**
- **Breaking changes**: Will this affect existing users?

## 🏗️ Architecture Guidelines

### Backend (FastAPI)

- **Keep it simple**: Avoid unnecessary abstractions
- **Security first**: Validate all inputs, sanitize outputs
- **Performance**: Use async/await, implement caching where beneficial
- **Monitoring**: Add structured logging for important events

### Frontend (Vanilla JS)

- **Progressive enhancement**: Work without JavaScript when possible
- **Accessibility**: WCAG AA compliance required
- **Performance**: Minimize bundle size, optimize loading
- **Mobile first**: Design for touch interfaces

### Docker

- **Multi-stage builds**: Optimize image size
- **Security**: Use non-root user, minimal base images
- **Caching**: Leverage layer caching effectively

## 🔒 Security

### Reporting Security Issues

**Do not open public issues for security vulnerabilities.**

Instead, email security concerns to the maintainers or use GitHub's private vulnerability reporting.

### Security Guidelines

- **Input validation**: Sanitize all user inputs
- **Output encoding**: Prevent XSS attacks
- **Authentication**: Secure credential generation and storage
- **Dependencies**: Keep dependencies updated
- **Secrets**: Never commit secrets to the repository

## 📚 Documentation

### Writing Documentation

- **Clear and concise**: Write for users of all skill levels
- **Examples**: Include practical examples
- **Up to date**: Update docs when changing functionality
- **Accessibility**: Use proper heading structure, alt text for images

### Documentation Types

- **README.md**: Project overview and quick start
- **CONTRIBUTING.md**: This file - development guidelines
- **API docs**: Auto-generated from FastAPI
- **Code comments**: Explain complex logic
- **CHANGELOG.md**: Track changes between versions

## 🤝 Getting Help

### Resources

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and community chat
- **Code Review**: PR feedback and suggestions

### Questions?

- Check existing issues and discussions first
- Provide context and details when asking questions
- Be patient and respectful in all interactions

## 📋 Release Process

### Version Numbering

We follow [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

- [ ] All tests passing
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version bumped in relevant files
- [ ] Docker images built and tested
- [ ] Release notes prepared

## 🎯 Project Goals

### Core Principles

1. **Simplicity**: Easy to use and maintain
2. **Reliability**: Robust error handling and fallbacks
3. **Performance**: Fast response times and efficient resource usage
4. **Accessibility**: Usable by everyone
5. **Security**: Protect user data and system integrity

### Non-Goals

- Complex configuration management
- Multi-tenant support
- Advanced streaming features
- Third-party integrations beyond Xtreme Codes

## 📄 License

By contributing, you agree that your contributions will be licensed under the same license as the project (MIT License).

---

Thank you for contributing to Toonami Aftermath Downlink! 🚀✨