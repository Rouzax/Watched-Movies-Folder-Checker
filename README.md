# Watched Movies Folder Checker

A PowerShell script that cross-references your local movie folders with your Trakt.tv watch history to identify watched and unwatched content, helping you make informed cleanup decisions.

<img width="991" height="688" alt="image" src="https://github.com/user-attachments/assets/eb1598b2-a709-4eb8-a1f2-92dd206c3e94" />

## Features

- **Trakt Integration** - OAuth authentication with automatic token refresh
- **Smart Caching** - Results cached locally to minimize API calls; cache invalidates when disk content changes
- **Movie Metadata** - Displays runtime, genres, rating, and release year
- **Multiple Output Formats** - GridView, CSV, JSON, or Console table
- **Cleanup Actions** - Delete or move watched movies with Recycle Bin safety
- **Interactive Mode** - Select movies for cleanup via GridView
- **Multi-Language Support** - Configurable article handling (The, A, An, De, Het, Een, etc.)
- **Multiple Root Folders** - Scan movies from multiple locations

## Requirements

- Windows PowerShell 5.1+ or PowerShell 7+
- A [Trakt.tv](https://trakt.tv) account
- A Trakt API application ([create one here](https://trakt.tv/oauth/applications/new))

## Installation

1. Download `Watched-Movies-Folder-Checker.ps1` to your preferred location
2. Create a Trakt API application:
   - Go to https://trakt.tv/oauth/applications/new
   - Name: Any name (e.g., "Movie Cleanup Script")
   - Redirect URI: `urn:ietf:wg:oauth:2.0:oob`
   - Save and note your Client ID and Client Secret

## Quick Start

```powershell
# First run - will prompt for Trakt credentials and authorization
.\Watched-Movies-Folder-Checker.ps1 -RootFolder "E:\Movies"

# Generate a config file for persistent settings
.\Watched-Movies-Folder-Checker.ps1 -CreateConfig
```

## Usage

### Basic Usage

```powershell
# Scan movies and display in GridView
.\Watched-Movies-Folder-Checker.ps1 -RootFolder "E:\Movies"

# Scan multiple folders
.\Watched-Movies-Folder-Checker.ps1 -RootFolder "E:\Movies", "F:\Films"

# Output to console table
.\Watched-Movies-Folder-Checker.ps1 -RootFolder "E:\Movies" -OutputFormat Console

# Export to CSV
.\Watched-Movies-Folder-Checker.ps1 -RootFolder "E:\Movies" -OutputFormat CSV -OutputPath "movies.csv"

# Export to JSON
.\Watched-Movies-Folder-Checker.ps1 -RootFolder "E:\Movies" -OutputFormat JSON -OutputPath "movies.json"
```

### Cleanup Operations

```powershell
# Preview cleanup of watched movies (dry run)
.\Watched-Movies-Folder-Checker.ps1 -RootFolder "E:\Movies" -CleanupWatched -WhatIf

# Delete watched movies (sends to Recycle Bin)
.\Watched-Movies-Folder-Checker.ps1 -RootFolder "E:\Movies" -CleanupWatched

# Move watched movies to archive folder
.\Watched-Movies-Folder-Checker.ps1 -RootFolder "E:\Movies" -CleanupWatched -MoveToPath "X:\Archive"

# Permanently delete (skip Recycle Bin)
.\Watched-Movies-Folder-Checker.ps1 -RootFolder "E:\Movies" -CleanupWatched -SkipRecycleBin

# Interactive selection via GridView
.\Watched-Movies-Folder-Checker.ps1 -RootFolder "E:\Movies" -Interactive
```

### Cache Management

```powershell
# Force refresh all data from Trakt (ignore cache)
.\Watched-Movies-Folder-Checker.ps1 -RootFolder "E:\Movies" -ForceRefresh

# Set custom cache TTL (hours)
.\Watched-Movies-Folder-Checker.ps1 -RootFolder "E:\Movies" -CacheTTLHours 24
```

## Configuration

Run with `-CreateConfig` to generate a `movies-config.json` file:

```json
{
  "rootFolders": ["E:\\Movies"],
  "excludePatterns": ["Sample", "Trailer", "SAMPLE", "sample", "trailer"],
  "cacheTTLHours": 168,
  "outputFormat": "GridView",
  "videoExtensions": [".mkv", ".mp4", ".avi", ".mov", ".m4v", ".wmv", ".ts", ".flv", ".webm"],
  "trailingArticles": ["The", "A", "An", "De", "Het", "Een"],
  "clientId": "your-client-id",
  "clientSecret": "your-client-secret",
  "manualMappings": {}
}
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `rootFolders` | Array of paths to scan for movie folders | `[]` |
| `excludePatterns` | Filename patterns to exclude from size calculations | `["Sample", "Trailer", ...]` |
| `cacheTTLHours` | Hours before cached data expires | `168` (7 days) |
| `outputFormat` | Default output format: GridView, CSV, JSON, Console | `GridView` |
| `videoExtensions` | File extensions to consider as video files | `[".mkv", ".mp4", ...]` |
| `trailingArticles` | Articles that may appear at end of folder names | `["The", "A", "An", ...]` |
| `clientId` | Trakt API Client ID | `""` |
| `clientSecret` | Trakt API Client Secret | `""` |
| `manualMappings` | Manual folder-to-Trakt mappings for edge cases | `{}` |

### Manual Mappings

For movies that don't match automatically, add manual mappings:

```json
{
  "manualMappings": {
    "Some Weird Movie Title (2020)": {
      "trakt_id": 123456,
      "trakt_slug": "some-weird-movie-2020",
      "imdb_id": "tt1234567"
    }
  }
}
```

## Folder Naming

The script expects movie folders in the format: `Movie Title (Year)`

Examples:
- `The Matrix (1999)`
- `Matrix, The (1999)` - trailing articles are automatically handled
- `Confess, Fletch (2022)` - punctuation is handled

## Output Columns

| Column | Description |
|--------|-------------|
| Title | Folder name |
| Status | Watched, Unwatched, or Unknown |
| Year | Release year |
| Runtime | Movie duration (e.g., "2h 15m") |
| Rating | Trakt rating (0-10) |
| Genres | Comma-separated genre list |
| WatchedAt | Date/time when marked as watched on Trakt |
| SizeGB | Total size of video files in GB |
| TraktUrl | Link to movie on Trakt.tv |

## Files Created

The script creates the following files in its directory:

| File | Purpose |
|------|---------|
| `movies-config.json` | Configuration settings |
| `movies-cache.json` | Cached movie data (reduces API calls) |
| `tokens.json` | Trakt OAuth tokens (shared with TV show script) |

## Parameters

| Parameter | Description |
|-----------|-------------|
| `-RootFolder` | One or more root folders containing movie subfolders |
| `-ClientId` | Trakt API Client ID |
| `-ClientSecret` | Trakt API Client Secret |
| `-OutputFormat` | Output format: GridView, CSV, JSON, or Console |
| `-OutputPath` | File path for CSV/JSON output |
| `-CacheTTLHours` | Hours before cached data expires (1-8760) |
| `-ForceRefresh` | Bypass cache and fetch fresh data |
| `-ExcludePattern` | Filename patterns to exclude |
| `-CleanupWatched` | Delete or move watched movies |
| `-MoveToPath` | Move movies here instead of deleting |
| `-SkipRecycleBin` | Permanently delete instead of using Recycle Bin |
| `-CreateConfig` | Generate default config file and exit |
| `-Interactive` | Select movies for cleanup via GridView |
| `-WhatIf` | Preview changes without making them |
| `-Verbose` | Show detailed processing information |
