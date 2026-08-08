# Translation Skill

Automated Django translation workflow using specialized translator subagents.

## Quick Usage

```bash
/translate                      # Full workflow, 4 parallel translator subagents
/translate --parallel 6         # Full workflow, 6 parallel translator subagents
/translate --resume             # Skip extraction, continue translation
/translate --resume --parallel 3  # Resume with custom parallelism
```

## Architecture

Uses a dedicated `translator` subagent (`.claude/agents/translator.md`) for each batch file:

1. **Skill** (`/translate`) orchestrates the workflow
2. **Translator subagents** handle individual batch file translations
3. **Context isolation**: Each translation stays in its own subagent context
4. **True parallelism**: Subagents run concurrently without blocking

## Workflow

1. **Extract** (skipped with --resume):
   - Run `makemessages --all`
   - Clean and extract untranslated strings to `temp/extracted/`

2. **Translate** (parallel):
   - Spawn N translator subagents (default: 4, max: 10)
   - Each subagent translates one batch file independently
   - Semaphore pattern: maintain N active subagents
   - Resume capability: skip already-translated files

3. **Apply**:
   - Run `py_apply_translations.py`
   - Generate MO files

## Files

- `SKILL.md` - Main skill definition (orchestration logic)
- `README.md` - This file
- `IMPLEMENTATION_NOTES.md` - Technical details
- `../../agents/translator.md` - Translator subagent definition

## Resume Capability

If translation is interrupted (rate limit, error, etc.):

1. Completed batch files are already in `temp/translated/`
2. Run `/translate --resume` to continue
3. Skill compares `temp/extracted/` vs `temp/translated/` and only translates missing files

## Advantages Over Previous Approach

1. **No context pollution**: Translation output stays in subagent contexts
2. **Clean completion**: No late agent notifications
3. **True parallelism**: Subagents are independent
4. **Better isolation**: Each batch file gets its own context window
5. **Simpler progress tracking**: Just check files on disk
