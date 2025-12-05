# Contributing to cSploit

Thank you for your interest in contributing to cSploit! This document provides guidelines and instructions for contributing.

## Code of Conduct

- Be respectful and constructive in all interactions
- Follow responsible disclosure practices for security issues
- Use cSploit only for legal and authorized purposes
- Help create a welcoming environment for all contributors

## How to Contribute

### Reporting Bugs

Before creating a bug report:
1. Check the [existing issues](https://github.com/cSploit/android/issues) to avoid duplicates
2. Update to the latest version to see if the issue persists
3. Collect relevant information (Android version, device model, logs)

When filing a bug report, include:
- Clear, descriptive title
- Steps to reproduce the issue
- Expected vs actual behavior
- Screenshots or logs if applicable
- Device and Android version information

### Suggesting Features

Feature requests should include:
- Clear description of the feature
- Use case and benefits
- Potential implementation approach (optional)
- Any security or legal considerations

### Security Vulnerabilities

**Do not open public issues for security vulnerabilities.**

Instead:
1. Email security concerns to the maintainers privately
2. Include detailed steps to reproduce
3. Wait for acknowledgment before public disclosure
4. Follow responsible disclosure practices (90-day disclosure window)

## Development Setup

### Prerequisites

- Android Studio Arctic Fox or newer
- JDK 17 or newer
- Android SDK API 33+
- Git
- A rooted Android device for testing (recommended)

### Setting Up Development Environment

1. **Fork and Clone**
   ```bash
   git clone https://github.com/YOUR_USERNAME/android.git
   cd android
   ```

2. **Install Dependencies**
   ```bash
   ./gradlew build
   ```

3. **Import in Android Studio**
   - Open Android Studio
   - File → Open → Select the project directory
   - Wait for Gradle sync to complete

4. **Configure Signing (Optional)**
   Create `keystore.properties` in project root:
   ```properties
   storeFile=/path/to/keystore.jks
   storePassword=your_password
   keyAlias=your_alias
   keyPassword=your_key_password
   ```

### Running the Project

1. **Debug Build**
   ```bash
   ./gradlew assembleDebug
   ```

2. **Install on Device**
   ```bash
   ./gradlew installDebug
   ```

3. **Run Tests**
   ```bash
   ./gradlew test
   ```

## Coding Standards

### Code Style

- Follow Android Kotlin/Java style guide
- Use meaningful variable and method names
- Keep methods focused and concise (< 50 lines when possible)
- Add comments for complex logic
- Use proper indentation (4 spaces for Java)

### Architecture

- Follow SOLID principles
- Use MVP or MVVM patterns for new features
- Keep business logic separate from UI
- Use dependency injection where appropriate
- Write testable code

### Git Commit Messages

Follow conventional commits format:

```
type(scope): subject

body (optional)

footer (optional)
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, no logic change)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks
- `perf`: Performance improvements
- `security`: Security improvements

Examples:
```
feat(mitm): add TLS interception support

Implements TLS/SSL interception for MITM attacks.
Includes certificate generation and installation.

Closes #123
```

```
fix(portscanner): handle timeout exceptions

Previously, timeout exceptions would crash the app.
Now they are caught and displayed to the user.

Fixes #456
```

### Code Review Guidelines

All contributions require code review:

1. **For Contributors:**
   - Keep pull requests focused and small
   - Write clear PR descriptions
   - Respond to feedback promptly
   - Update documentation as needed
   - Ensure CI passes

2. **For Reviewers:**
   - Be constructive and respectful
   - Focus on code quality and maintainability
   - Check for security issues
   - Verify functionality
   - Suggest improvements

## Pull Request Process

1. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Changes**
   - Write clean, documented code
   - Follow coding standards
   - Add tests if applicable
   - Update documentation

3. **Test Your Changes**
   ```bash
   ./gradlew test
   ./gradlew lint
   ```

4. **Commit Changes**
   ```bash
   git add .
   git commit -m "feat(scope): description"
   ```

5. **Push to Fork**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Create Pull Request**
   - Go to GitHub repository
   - Click "New Pull Request"
   - Select your branch
   - Fill in PR template
   - Submit for review

### Pull Request Checklist

- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex code
- [ ] Documentation updated
- [ ] No new warnings generated
- [ ] Tests added/updated
- [ ] All tests pass
- [ ] Lint checks pass
- [ ] PR description is clear and complete

## Testing

### Unit Tests

Write unit tests for:
- Business logic
- Utility functions
- Data transformations
- Edge cases

Location: `cSploit/src/test/java/`

### Integration Tests

Test interactions between components:
- Network operations
- Database operations
- Service integrations

### Manual Testing

Always test on:
- Different Android versions (minimum supported to latest)
- Various screen sizes
- Different network conditions
- Rooted and non-rooted devices

## Documentation

### Code Documentation

- Add JavaDoc comments for public classes and methods
- Document complex algorithms
- Explain non-obvious code decisions
- Include usage examples for APIs

### User Documentation

Update relevant documentation:
- README.md for major features
- Wiki for tutorials
- SECURITY.md for security-related changes
- CHANGELOG.md for all changes

## Legal Considerations

### Licensing

- All contributions must be compatible with GPL v3
- By contributing, you agree to license your code under GPL v3
- Include license header in new files

### Ethical Usage

- Features should not facilitate illegal activities
- Include appropriate warnings and disclaimers
- Follow responsible disclosure for vulnerabilities
- Consider legal implications of new features

## Project Structure

```
android/
├── .github/          # GitHub Actions workflows
├── cSploit/
│   ├── src/
│   │   ├── main/
│   │   │   ├── java/         # Java source code
│   │   │   ├── res/          # Resources (layouts, drawables, etc.)
│   │   │   └── AndroidManifest.xml
│   │   └── test/             # Unit tests
│   ├── build.gradle          # Module build configuration
│   └── proguard-rules.pro    # ProGuard rules
├── gradle/           # Gradle wrapper
├── build.gradle      # Root build configuration
└── settings.gradle   # Project settings
```

## Communication

### Getting Help

- **GitHub Issues**: Bug reports and feature requests
- **Pull Request Comments**: Code review discussions
- **Wiki**: Tutorials and guides

### Stay Updated

- Watch the repository for updates
- Check pull requests for ongoing work
- Read the changelog for recent changes

## Recognition

Contributors are recognized in:
- GitHub contributors page
- Release notes (for significant contributions)
- Project documentation

## Questions?

If you have questions:
1. Check existing documentation
2. Search closed issues
3. Ask in a new issue with "question" label

Thank you for contributing to cSploit!
