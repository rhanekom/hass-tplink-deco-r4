# Contribution guidelines

Contributing to this project should be as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features

## Github is used for everything

Github is used to host code, to track issues and feature requests, as well as accept pull requests.

Pull requests are the best way to propose changes to the codebase.

1. Fork the repo and create your branch from `main`.
2. If you've changed something, update the documentation.
3. Make sure your code lints (using `.devcontainer/scripts/lint`).
4. Test your contribution: new or changed code lands with tests (`uv run pytest tests/`).
5. Issue that pull request!

## Any contributions you make will be under the Apache License 2.0

In short, when you submit code changes, your submissions are understood to be under the same [Apache License 2.0](./LICENSE) that covers the project. Feel free to contact the maintainers if that's a concern.

## Report bugs using Github's [issues](../../issues)

GitHub issues are used to track public bugs.
Report a bug by [opening a new issue](../../issues/new/choose); it's that easy!

## Write bug reports with detail, background, and sample code

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
    - Be specific!
    - Give sample code if you can.
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening, or stuff you tried that didn't work)

People *love* thorough bug reports. I'm not even kidding.

## Never include credentials or captures

This project talks to a router. HAR and pcap captures of the web UI contain admin
credentials, session tokens and your household's device list, and they are
gitignored for that reason. Redact tokens, passwords and MAC addresses before
attaching logs or captures to an issue or pull request.

## Use a consistent coding style

Style is enforced mechanically: [ruff](https://docs.astral.sh/ruff/) formats and lints the code, and a pre-commit hook is installed with the development environment to keep commits consistent. Run `uv run pre-commit run --all-files` to check everything.

## Test your code modification

This custom component is based on the [integration_blueprint template](https://github.com/ludeeus/integration_blueprint).

It comes with a development environment in a container, easy to launch
if you use Visual Studio Code. With this container you will have a stand alone
Home Assistant instance running and already configured with the included
[`configuration.yaml`](./config/configuration.yaml)
file.

- `.devcontainer/scripts/develop` will start an instance of Home Assistant for testing purposes.
- Running `.devcontainer/scripts/clean` will remove all Home Assistant created files if you'd like to start afresh.

## License

By contributing, you agree that your contributions will be licensed under the project's Apache License 2.0.
