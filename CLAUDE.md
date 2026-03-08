# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Single-file PowerShell script that cross-references local movie folders with Trakt.tv watch history. It identifies watched/unwatched movies and supports cleanup operations (delete/move watched content).

## Running

```powershell
# Basic usage
.\Watched-Movies-Folder-Checker.ps1 -RootFolder "E:\Movies"

# Dry-run cleanup
.\Watched-Movies-Folder-Checker.ps1 -RootFolder "E:\Movies" -CleanupWatched -WhatIf

# Generate config file
.\Watched-Movies-Folder-Checker.ps1 -CreateConfig
```

Requires Windows PowerShell 5.1+ or PowerShell 7+. PowerShell is available locally for testing.

## Architecture

The entire application is a single script: `Watched-Movies-Folder-Checker.ps1` (~1300 lines), organized into regions:

- **CONFIGURATION** (line ~125) — Defaults, Trakt API constants, watch status enums, runtime state
- **CONFIGURATION FILE** (line ~171) — Loading/creating `movies-config.json`, merging with CLI params
- **TOKEN MANAGEMENT** (line ~283) — Trakt OAuth flow: device code auth, token refresh, `tokens.json` persistence
- **CACHE MANAGEMENT** (line ~444) — Smart caching in `movies-cache.json` with TTL and disk-change invalidation
- **TRAKT API** (line ~589) — API calls: search, watched history, movie metadata, rate limiting
- **FOLDER & FILE PROCESSING** (line ~770) — Folder name parsing (title/year extraction, trailing article handling), video file size calculation
- **MOVIE PROCESSING** (line ~847) — Core matching logic: folder → Trakt search → watch status lookup, with manual mapping support
- **CLEANUP** (line ~1068) — Delete (Recycle Bin or permanent) and move operations for watched movies
- **OUTPUT** (line ~1162) — GridView, CSV, JSON, Console table formatting with summary statistics
- **MAIN** (line ~1252) — Entry point: orchestrates config → auth → scan → process → output

## Key Design Patterns

- **Config cascade**: `$script:Defaults` → `movies-config.json` → CLI parameters (later overrides earlier)
- **Cache invalidation**: Cache stores a hash of folder names; if disk content changes, cache is invalidated regardless of TTL
- **Manual mappings**: `manualMappings` in config allows overriding Trakt search for folders that don't match automatically
- **Trailing articles**: Folder names like `Matrix, The (1999)` are normalized to `The Matrix` for Trakt search
- **Rate limiting**: `RequestDelayMs` (200ms default) between Trakt API calls

## Workflow Skills

This project has **superpowers skills** available. Always invoke relevant skills before starting work — especially `brainstorming` before creative/feature work, `systematic-debugging` before fixing bugs, `test-driven-development` before implementing features, and `verification-before-completion` before claiming work is done. See the skills list in the system prompt for the full set.

## Files Created at Runtime

- `movies-config.json` — User configuration (gitignored as `config.json`)
- `movies-cache.json` — Cached Trakt data (gitignored)
- `tokens.json` — OAuth tokens (gitignored)
