# Issues
### Warnung

Before opening Issue, if it is more question than problem or bug - ask about that [in our chat](https://t.me/telemtrs)

***Each of your Issues triggers attempts to reproduce problems and analyze them, which are done manually by people***

Issues is **NOT** about:
- Question and Answer
- Helpdesk
- Configuration or Intergraion Support

---

# Pull Requests

### General
- ONLY signed and verified commits
- ONLY from your name
- DO NOT commit with `codex`, `claude`, or other AI tools as author/committer
- PREFER `flow` branch for development, not `main`

---

### Definition of Ready (MANDATORY)

A Pull Request WILL be ignored or closed if:

- it does NOT build
- it does NOT pass tests
- it does NOT follow formatting rules
- it contains unrelated or excessive changes
- the author cannot clearly explain the change

---

### Blessed Principles
- PR must build
- PR must pass tests
- PR must be understood by author

---

### AI Usage Policy

AI tools (Claude, ChatGPT, Codex, DeepSeek, etc.) are allowed as **assistants**, NOT as decision-makers.

By submitting a PR, you confirm that:

- you fully understand the code you submit
- you verified correctness manually
- you reviewed architecture and dependencies
- you take full responsibility for the change

AI-generated code is treated as **draft** and must be validated like any other external contribution.

The problem isn’t AI as a tool, but the dilution of responsibility. If the commit history says "Claude/GPT authored this", then who is accountable for the bug? Claude? GPT? Anthropic? OpenAI? Samuel Altman?

The user who didn’t read the diff? No one? But, in a sensitive system, *"no one"* is an unacceptable maintainer model.

PRs that look like unverified AI dumps WILL be closed

---

### Maintainer Policy

Maintainers reserve the right to:

- close PRs that do not meet basic quality requirements
- request explanations before review
- ignore low-effort contributions

Respect the reviewers time

---

### Enforcement

Pull Requests that violate project standards may be closed without review.

This includes (but is not limited to):

- non-building code
- failing tests
- unverified or low-effort changes
- inability to explain the change

These actions follow the Code of Conduct and are intended to preserve signal, quality, and Telemt's integrity
