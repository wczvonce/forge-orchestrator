# Product specification

## 1. Goal
Describe the real problem the application must solve and who will use it.

## 2. Required user flows
- User can ...
- User can ...
- Administrator can ...

## 3. Functional requirements
- Authentication:
- Data model:
- Search/filtering:
- Notifications:
- Imports/exports:

## 4. Non-functional requirements
- Supported devices and browsers:
- Performance expectations:
- Accessibility:
- Security and privacy:
- Language/localization:

## 5. Preferred technology
- Frontend:
- Backend:
- Database:
- Testing:
- Local start command:

## 6. Acceptance criteria
- [ ] Fresh clone can be installed and started using documented commands.
- [ ] Automated tests pass.
- [ ] Lint, type-check, and production build pass.
- [ ] Main user flows work on mobile and desktop.
- [ ] Error states and empty states are handled.
- [ ] README explains setup, architecture, and limitations.

## 7. Screens and states
- Screens:
- Loading states:
- Empty states:
- Error states:
- Form validation:
- Responsive behavior:

## 8. Data and permissions
- Entities and relationships:
- Validation rules:
- User roles:
- Authorization boundaries:
- Offline/local storage behavior:

## 9. Safe assumptions
- Record every safely inferred product or technical assumption here.
- Never infer legal, financial, production, privacy, credential, or irreversible choices.
- Forge also persists accepted assumptions in `ASSUMPTIONS.md`.

## 10. Adaptive work plan
- Forge creates and persists 4–12 coherent work packets in `.forge/project-plan.json`.
- Each packet has dependencies, 1–4 verifiable acceptance criteria, risk, difficulty,
  a logical worker profile, a review profile, and a check tier.
- Completed packets are immutable evidence and must not be regenerated on continuation.

## 11. Verification contract
- Smoke: diff/syntax/static checks for small mechanical changes.
- Targeted: relevant lint, type-check, and affected tests for routine packets.
- Milestone: full lint/type-check and broader unit/integration tests.
- Release: all mandatory checks, main E2E flow, error/empty states, security checks,
  test counts, and a fresh production/release build.
- `done` requires a fresh release suite and a strong final read-only Codex review.

## 12. Explicit exclusions
- No production deployment.
- No real payment processing.
- No real personal data.
- No push or merge without human review.
