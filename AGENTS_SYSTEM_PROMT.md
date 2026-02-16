## System Prompt - Modification and Architecture Guidelines

You are working on a production-grade Rust codebase: follow these rules strictly!

### 1. Comments and Documentation

- All comments MUST be written in English.
- Comments MUST be concise, precise, and technical.
- Comments MUST describe architecture, intent, invariants, and non-obvious implementation details.
- DO NOT add decorative, conversational, or redundant comments.
- DO NOT add trailing comments at the end of code lines.
- Place comments on separate lines above the relevant code.

Correct example:

```rust
// Handles MTProto client authentication and establishes encrypted session state.
fn handle_authenticated_client(...) { ... }
```

Incorrect example:

```rust
let x = 5; // set x to 5 lol
```

---

### 2. File Size and Module Structure

- DO NOT create files larger than 350–550 lines.
- If a file exceeds this limit, split it into submodules.
- Organize submodules logically by responsibility (e.g., protocol, transport, state, handlers).
- Parent modules MUST declare and describe submodules.
- Use local git for versioning and diffs, write CORRECT and FULL comments to commits with descriptions

Correct example:

```rust
// Client connection handling logic.
// Submodules:
// - handshake: MTProto handshake implementation
// - relay: traffic forwarding logic
// - state: client session state machine

pub mod handshake;
pub mod relay;
pub mod state;
```

* Maintain clear architectural boundaries between modules.

---

### 3. Formatting

- DO NOT run `cargo fmt`.
- DO NOT reformat existing code unless explicitly instructed.
- Preserve the existing formatting style of the project.

---

### 4. Change Safety and Validation

- DO NOT guess intent, behavior, or missing requirements.
- If anything is unclear, STOP and ask questions.
- Actively ask questions before making architectural or behavioral changes.
- Prefer clarification over assumptions.

---

### 5. Warnings and Unused Code

- DO NOT fix warnings unless explicitly instructed.
- DO NOT remove:

  - unused variables
  - unused functions
  - unused imports
  - dead code

These may be intentional.

---

### 6. Architectural Integrity

- Preserve existing architecture unless explicitly instructed to refactor.
- DO NOT introduce hidden behavioral changes.
- DO NOT introduce implicit refactors.
- Keep changes minimal, isolated, and intentional.

---

### 7. When Modifying Code

You MUST:

- Maintain architectural consistency.
- Document non-obvious logic.
- Avoid unrelated changes.
- Avoid speculative improvements.

You MUST NOT:

- Refactor unrelated code.
- Rename symbols without explicit reason.
- Change formatting globally.

---

If requirements are ambiguous, ask questions BEFORE implementing changes.
