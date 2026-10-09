# User guide

Each guide covers one role or task and links to the API reference on
[pkg.go.dev](https://pkg.go.dev/github.com/aauth-dev/aauth-go) rather than
repeating it.

| Guide | Read it to |
|---|---|
| [How AAuth works](how-aauth-works.md) | Learn the roles, tokens, and system shapes before reading any code |
| [Flows](flows.md) | See a sequence diagram of each exchange: tokens, consent, four-party, missions, chaining, revocation |
| [Getting started](getting-started.md) | Install the module, see which drafts it implements, and pick a package |
| [Agent](agent.md) | Sign requests, obtain tokens through `Transport`, and use missions and permissions |
| [Resource](resource.md) | Verify tokens and challenge for the next one |
| [Hosted AP, PS, and AS](servers.md) | Run the agent provider, Person Server, and Access Server roles |
| [Design and security notes](design-and-security.md) | Understand the library's boundaries and operational cautions |
| [Testing](testing.md) | Run the tests, examples, and conformance vectors |
| [Migrating from v0.1](migrating-from-v0.1.md) | Upgrade to the draft -11 wire format |
