---
name: translate
description: Run Django translation workflow - extract untranslated strings, translate them to 59 languages using parallel translator subagents, and apply back to PO files. Use when adding new translatable strings or when user asks to translate.
argument-hint: [--resume] [--parallel N]
allowed-tools: Bash, Read, Write, Glob, Task
disable-model-invocation: false
user-invocable: true
---

# Django Translation Workflow

Automates Django translation with parallel translator subagents and resume capability.

## Arguments

Parse `$ARGUMENTS` for:
- `--resume`: Skip extraction, continue from existing temp/extracted/
- `--parallel N`: Number of parallel translator subagents (default: 4, range: 1-10)

Example: `$ARGUMENTS` = "--resume --parallel 6" means resume mode with 6 parallel agents

## Working Directory

Ensure we're in the drf-auth-kit directory:
```bash
pwd
```

## Phase 0: Clean Temp (Skip if --resume)

If `--resume` NOT in arguments:

1. Remove existing temp folder to start fresh:
```bash
rm -rf temp/
```

If `--resume` IS in arguments:
- Skip cleanup
- Report: "⏭️  Keeping existing temp/ (--resume mode)"

## Phase 1: Extraction (Skip if --resume)

If `--resume` NOT in arguments:

1. Run makemessages:
```bash
python sandbox/manage.py makemessages --all
```

2. Clean and extract:
```bash
./scripts/py_clean_and_extract.py
```

3. Report extraction results

If `--resume` IS in arguments:
- Skip extraction
- Report: "⏭️  Skipping extraction (--resume mode)"

## Phase 2: Identify Work

1. List all batch files in temp/extracted/ (use single bash command):
```bash
ls temp/extracted/*.json | xargs -n 1 basename
```

2. List already-translated files in temp/translated/ (use single bash command):
```bash
ls temp/translated/*.json 2>/dev/null | xargs -n 1 basename || echo ""
```

3. Determine pending files:
   - pending = extracted files NOT in translated/
   - If no pending files: "✅ All translations complete!"
   - Otherwise: Continue to Phase 3

4. Report:
```
📊 Translation Status:
   - Total batch files: X
   - Already translated: Y
   - Pending translation: Z
```

## Phase 3: Parallel Translation with Translator Subagents

### Parse Arguments

Extract parallel count from `$ARGUMENTS`:
- If `--parallel N` found: use N (clamp to 1-10)
- If not found: use 4 (default)

### Spawn Translator Subagents

For each pending batch file, spawn a `translator` subagent:

```
parallel_limit = parsed from arguments (default: 4)
pending_files = [list of pending batch files]
active_agents = []  # [(agent_id, filename), ...]
completed = []
failed = []

# Spawn all agents up to parallel limit
FOR each file in pending_files (up to parallel_limit):
    agent_id = Task(
        subagent_type: "translator",
        description: f"Translate {file}",
        run_in_background: true,
        prompt: f"""
Translate the Django message batch file: temp/extracted/{file}

Read the input file, translate ALL strings for ALL languages, and write to: temp/translated/{file}

Follow your translation guidelines for quality, placeholder preservation, and JSON formatting.
"""
    )

    active_agents.append((agent_id, file))
    Report: "⏳ Spawned translator for {file}"

# Report initial status
Report: "📊 Status: 0/{len(pending_files)} completed, {len(active_agents)} active, {len(pending_files) - len(active_agents)} pending"

# Monitor completion by checking temp/translated/
WHILE active_agents:
    Wait 10 seconds

    # Check which files now exist in temp/translated/
    completed_files_on_disk = list files in temp/translated/*.json (basenames only)

    # Find newly completed agents
    newly_completed = []
    FOR each (agent_id, file) in active_agents:
        IF file in completed_files_on_disk:
            completed.append(file)
            newly_completed.append(file)
            active_agents.remove((agent_id, file))

    # Report newly completed
    IF newly_completed:
        FOR each file in newly_completed:
            Report: "✅ Completed {file}"

    # Spawn next batch of agents if we have pending files
    files_to_spawn = pending_files[len(completed):]
    WHILE len(active_agents) < parallel_limit AND files_to_spawn:
        file = files_to_spawn.pop(0)

        agent_id = Task(
            subagent_type: "translator",
            description: f"Translate {file}",
            run_in_background: true,
            prompt: f"""
Translate the Django message batch file: temp/extracted/{file}

Read the input file, translate ALL strings for ALL languages, and write to: temp/translated/{file}

Follow your translation guidelines for quality, placeholder preservation, and JSON formatting.
"""
        )

        active_agents.append((agent_id, file))
        Report: "⏳ Spawned translator for {file}"

    # Progress report
    total = len(pending_files)
    Report: "📊 Progress: {len(completed)}/{total} completed, {len(active_agents)} active, {total - len(completed) - len(active_agents)} pending"
END WHILE

# Final verification
all_expected_files = pending_files
completed_files_on_disk = list files in temp/translated/*.json (basenames only)
failed = [file for file in all_expected_files if file not in completed_files_on_disk]

IF failed:
    Report: "❌ Failed to translate: {failed}"
    Report: "Run '/translate --resume' to retry failed files"
ELSE:
    Report: "✅ All {len(completed)} batch files translated successfully!"
```

## Phase 4: Apply Translations

After all translations complete (no failed files):

1. Apply translations to PO files:
```bash
./scripts/py_apply_translations.py
```

2. Report results from script output

3. Final summary:
```
🎉 Translation Complete!
   ✅ Translated: X batch files
   ✅ Updated: Y languages
   ✅ Applied: Z strings
```

4. **END OF WORKFLOW** - Stop here immediately. Do not wait for or respond to any subsequent "Agent completed" notifications. The translations are done and applied. Any background agents still finishing up are irrelevant since we've already verified all output files exist and applied them.

## Error Handling

- **Extraction fails**: Report error, suggest manual run
- **Translator subagent fails**: File won't appear in temp/translated/, tracked as failed
- **Application fails**: Report error, show script output
- **Rate limited / partial completion**: User can run `/translate --resume` to continue

## Progress Reporting

Provide clear, emoji-rich progress updates throughout:

```
📦 Extraction Phase
⏳ Running makemessages...
✅ Extracted messages for 59 languages

⏳ Cleaning and extracting untranslated strings...
✅ Created 12 batch files in temp/extracted/
   - Total untranslated: 1,234 strings
   - Languages: 45

🌐 Translation Phase (parallel: 4)
📊 Status: 0/12 completed, 0 active, 12 pending

⏳ Spawned translator for af-ar-az-be.json
⏳ Spawned translator for bg-bs-ca-cs.json
⏳ Spawned translator for cy-da-de-el.json
⏳ Spawned translator for es-et-fa-fi.json
📊 Status: 0/12 completed, 4 active, 8 pending

[Wait 10 seconds...]

Checking temp/translated/ for completed files...
✅ Completed af-ar-az-be.json
✅ Completed bg-bs-ca-cs.json
📊 Status: 2/12 completed, 2 active, 8 pending

⏳ Spawned translator for fr-gl-he-hi.json
⏳ Spawned translator for hr-hu-hy-id.json
📊 Status: 2/12 completed, 4 active, 6 pending

[Wait 10 seconds...]

Checking temp/translated/ for completed files...
✅ Completed cy-da-de-el.json
✅ Completed es-et-fa-fi.json
✅ Completed fr-gl-he-hi.json
📊 Status: 5/12 completed, 3 active, 4 pending

... (continue until all done) ...

Final verification: checking temp/translated/...
✅ All 12 batch files translated successfully!

📥 Application Phase
⏳ Applying translations to PO files...
✅ Applied 1,234 translations to 45 languages
✅ Generated MO files

🎉 Translation Complete!
   ✅ Translated: 12 batch files
   ✅ Updated: 45 languages
   ✅ Applied: 1,234 strings
```

## Implementation Tips

1. **Use translator subagent**: Spawn with `Task(subagent_type: "translator", ...)`
2. **Background execution**: Use `run_in_background: true` for parallel work
3. **Check files on disk**: Completion is verified by checking temp/translated/, not task status
4. **Semaphore pattern**: Maintain parallel_limit active agents, spawn next when one completes
5. **Resume capability**: Compare temp/extracted/ vs temp/translated/ to find pending work
6. **Simple prompts to subagents**: Just pass the filename, the subagent knows the workflow

## Example Invocations

```
/translate
→ Full workflow, 4 parallel translator subagents

/translate --parallel 6
→ Full workflow, 6 parallel translator subagents

/translate --resume
→ Skip extraction, translate remaining files with 4 parallel translator subagents

/translate --resume --parallel 8
→ Skip extraction, translate remaining files with 8 parallel translator subagents
```

---

## Critical: Handling Agent Completion Notifications

After the final summary is shown and the workflow completes, **DO NOT RESPOND** to any "Agent completed" notifications that arrive afterward. The work is verified complete by checking files on disk. Background subagents may report completion late, but:

1. All files have been verified to exist in temp/translated/
2. All translations have been applied via py_apply_translations.py
3. The final summary has been shown
4. **The conversation is complete** - do not add any further messages

Any agent completion notifications after this point are informational only and require no response or acknowledgment.

---

**Note**: This skill uses the `translator` subagent defined in `.claude/agents/translator.md`. The subagent handles all translation logic, quality standards, and file I/O.
