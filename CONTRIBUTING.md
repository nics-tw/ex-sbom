# Contributing to ex-s

Again, thank you for your interest in contributing to ex-s! We appreciate your willingness to help us improve the project. Before you start contributing, please take a moment to read through our guidelines to ensure a smooth collaboration.

## Code of Conduct

We expect all contributors to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md). This document outlines the standards of behavior we expect from everyone involved in the project. By participating in this project, you agree to abide by these guidelines.

## Getting Started

### Prerequisites

- Install [Go](https://golang.org/doc/install/source) (version 1.24 or later).
- Git installed on your machine.

### Development Setup

- Fork the repository on GitHub.
- Clone your forked repository to your local machine:
  ```bash
  git clone https://github.com/YOUR-USERNAME/ex-s.git
  cd ex-s
  ```
- Add the original repository as an upstream remote:
  ```bash
  git remote add upstream https://github.com/nics-ra/ex-s.git
    ```
- Install Go dependencies:
  ```bash
  go mod tidy
  ```
- Build the project:
  ```bash
  go build -o ex-s
  ```
- Or just run on local for testing:
  ```bash
  go run main.go
  ```

## Making Contributions

### Branching Strategy

Please use descriptive branch names that reflect the changes you're making:

- For feature implementation: `feature/your-feature-name`
- For bug fixes: `fix/issue-description`
- For documentation updates: `docs/update-description`
- For refactoring: `refactor/description`
- For anything you're not sure or not in the above categories: `chore/description`

### Commit Messages

Follow these guidelines for commit messages:

- Declare the type of change (e.g., `fix`, `feat`, `docs`, `refactor`, etc.).
- Add category of the util modified in the commit (e.g., `sbom`, `vuln`, `graph`, etc.).
- Clearly describe the changes made. (e.g., `fix the mapping logic from scanning result to defined struct, since the version of the osv-scanner has been updated`)
- We do not set any strict limit on the length of the commit message, but please keep it concise and informative.

### Pull Requests

When you're ready to submit your changes, please create a pull request (PR) against the `main` branch of the original repository. Kindly using the default PR template provided in the repository. This will help us understand the changes you've made and why they are necessary.

### Code Standards

We follow the Go code style guidelines. Please ensure your code adheres to these standards before submitting a PR. You can use `go fmt` to format your code automatically.

### Testing

We encourage you to write tests for your code. If you're adding new features or fixing bugs, please include relevant tests to ensure the functionality works as expected.

Aside from unit tests, we also accept manual testing. Whiling applying manual test as the proof of your changes functioning as expected, please include the steps to reproduce the test in the PR description, image or video for the process and the result would be helpful.

### Documentation

If you are adding new features or making significant changes, please update the documentation accordingly. This includes updating the README file and any relevant API documentation.

### Review Process

Once you submit your PR, our team will review it. We may request changes or provide feedback. Please be responsive to comments and suggestions during the review process. The whole process may take a few days, so please be patient. We appreciate your understanding and cooperation.

## License

By contributing to this project, you agree that your contributions will be licensed under the [MIT License](LICENSE).

## Acknowledgments

We appreciate your interest in contributing to ex-s! Your contributions help us improve the project and make it more useful for everyone. If you have any questions or need assistance, feel free to reach out to the maintainers. Thanks in advance for your contributions!
