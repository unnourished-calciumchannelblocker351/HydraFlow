# Contributing to HydraFlow

Thank you for your interest in contributing to HydraFlow. This project exists to help people access the open internet, and every contribution matters.

## Getting Started

### Prerequisites

- Go 1.22+
- Docker (for integration tests)
- Make

### Building from Source

```bash
git clone https://github.com/Evr1kys/HydraFlow.git
cd HydraFlow
make build
```

### Running Tests

```bash
# Unit tests
make test

# Integration tests (requires Docker)
make test-integration

# Probe engine tests (requires network access)
make test-probe
```

## Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Write code and tests
4. Run `make lint` and `make test`
5. Commit with a descriptive message
6. Push and open a Pull Request

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(probe): add ISP detection via AS number lookup
fix(reality): handle TLS 1.2 fallback on older servers
docs(subscription): add .hydra.yml format specification
test(selector): add protocol fallback integration tests
```

### Code Style

- Follow standard Go conventions (`gofmt`, `golint`)
- Keep functions focused and under 50 lines where possible
- Document exported types and functions
- Write table-driven tests

## What to Work On

### High Priority
- **Protocol implementations** — Adding support for new bypass techniques
- **Probe modules** — Detecting different DPI systems and their capabilities
- **Client platforms** — Android, iOS, desktop applications

### Medium Priority
- **Blocking map** — ISP-specific data collection and analysis
- **Documentation** — Setup guides, protocol descriptions, translations
- **Performance** — Connection establishment time, throughput optimization

### Always Welcome
- Bug reports with reproduction steps
- Test coverage improvements
- CI/CD pipeline improvements
- Security audit findings (see [SECURITY.md](SECURITY.md))

## Adding a New Protocol

1. Create a new package under `protocols/`:
```
protocols/myprotocol/
├── myprotocol.go      # Protocol implementation
├── config.go          # Configuration types
├── myprotocol_test.go # Tests
└── README.md          # Protocol description
```

2. Implement the `Protocol` interface:
```go
type Protocol interface {
    Name() string
    Dial(ctx context.Context, target string) (net.Conn, error)
    Listen(ctx context.Context, addr string) (net.Listener, error)
    ProbeSupport() []probe.Test
}
```

3. Register in `protocols/registry.go`
4. Add subscription format support in `subscription/compat.go`
5. Write tests and documentation

## Adding a Probe Module

1. Implement the `probe.Test` interface:
```go
type Test interface {
    Name() string
    Run(ctx context.Context, target string) (*Result, error)
    Weight() float64
}
```

2. Add to the default test suite in `discovery/defaults.go`
3. Document what the probe detects and how

## Reporting Censorship Data

If you have access to a censored network, you can help by:

1. Running `hf-probe` from your network and sharing results
2. Documenting which protocols work on your ISP
3. Noting any time-based patterns (protocols blocked only at certain hours)

All data is anonymized before submission. See [docs/blocking-map.md](docs/blocking-map.md) for details.

## Security

If you discover a security vulnerability, please report it privately. See [SECURITY.md](SECURITY.md) for our disclosure policy.

## Code of Conduct

Be respectful. We're building tools for internet freedom — let's keep our community open and welcoming.

## License

By contributing, you agree that your contributions will be licensed under the [MPL-2.0 License](LICENSE).
