<#
.SYNOPSIS
    Lists movies with Trakt watch status and disk usage for cleanup decisions.

.DESCRIPTION
    Cross-references local movie folders with Trakt watch history to identify
    watched and unwatched content with accurate size accounting.

    Features:
    - Trakt OAuth with automatic token refresh
    - Result caching with configurable TTL and smart invalidation
    - Movie metadata (runtime, genres, rating, release year)
    - Multiple output formats (GridView, CSV, JSON, Console)
    - Configuration file support
    - Cleanup actions with Recycle Bin support
    - Exclusion patterns for samples/trailers
    - Summary statistics
    - Multiple root folder support

.PARAMETER RootFolder
    One or more root folders containing movie subfolders.
    Can also be set in config.json.

.PARAMETER ClientId
    Trakt API Client ID. Optional if tokens.json or config.json exists.

.PARAMETER ClientSecret
    Trakt API Client Secret. Optional if tokens.json or config.json exists.

.PARAMETER OutputFormat
    Output format: GridView (default), CSV, JSON, or Console.

.PARAMETER OutputPath
    File path for CSV/JSON output. Required when OutputFormat is CSV or JSON.

.PARAMETER CacheTTLHours
    Hours before cached Trakt data expires. Default: 168 (7 days).

.PARAMETER ForceRefresh
    Bypass cache entirely and fetch fresh data from Trakt.

.PARAMETER ExcludePattern
    File name patterns to exclude from size calculations.

.PARAMETER CleanupWatched
    Delete or move movies that are watched.

.PARAMETER MoveToPath
    Move movies to this path instead of deleting. Creates archive folders.

.PARAMETER SkipRecycleBin
    Permanently delete instead of sending to Recycle Bin.
    Default behavior uses Recycle Bin for safety.

.PARAMETER CreateConfig
    Generate a default config.json file and exit.

.PARAMETER Interactive
    Use Out-GridView to select movies for cleanup interactively.

.EXAMPLE
    .\Watched-Movies-Folder-Checker.ps1 -RootFolder "E:\Movies"

.EXAMPLE
    .\Watched-Movies-Folder-Checker.ps1 -CleanupWatched -WhatIf

.EXAMPLE
    .\Watched-Movies-Folder-Checker.ps1 -CleanupWatched -MoveToPath "X:\Archive"

.EXAMPLE
    .\Watched-Movies-Folder-Checker.ps1 -Interactive

.EXAMPLE
    .\Watched-Movies-Folder-Checker.ps1 -CreateConfig

.NOTES
    Configuration is loaded from config.json if present. Command-line parameters override config values.
    Requires Windows PowerShell 5.1+ or PowerShell 7+ with Microsoft.PowerShell.GraphicalTools for GridView.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param (
    [Parameter(Mandatory = $false)]
    [string[]]$RootFolder,

    [Parameter(Mandatory = $false)]
    [string]$ClientId,

    [Parameter(Mandatory = $false)]
    [string]$ClientSecret,

    [Parameter(Mandatory = $false)]
    [ValidateSet('GridView', 'CSV', 'JSON', 'Console')]
    [string]$OutputFormat,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 8760)]
    [int]$CacheTTLHours,

    [Parameter(Mandatory = $false)]
    [switch]$ForceRefresh,

    [Parameter(Mandatory = $false)]
    [string[]]$ExcludePattern,

    [Parameter(Mandatory = $false)]
    [switch]$CleanupWatched,

    [Parameter(Mandatory = $false)]
    [string]$MoveToPath,

    [Parameter(Mandatory = $false)]
    [switch]$SkipRecycleBin,

    [Parameter(Mandatory = $false)]
    [switch]$CreateConfig,

    [Parameter(Mandatory = $false)]
    [switch]$Interactive
)

#region ===== CONFIGURATION =====

$script:Paths = @{
    Config = Join-Path -Path $PSScriptRoot -ChildPath 'movies-config.json'
    Tokens = Join-Path -Path $PSScriptRoot -ChildPath 'tokens.json'
    Cache  = Join-Path -Path $PSScriptRoot -ChildPath 'movies-cache.json'
}

$script:Defaults = @{
    RootFolders      = @()
    ExcludePatterns  = @('Sample', 'Trailer', 'SAMPLE', 'sample', 'trailer')
    CacheTTLHours    = 168  # 7 days - movies don't change watch status often
    OutputFormat     = 'GridView'
    VideoExtensions  = @('.mkv', '.mp4', '.avi', '.mov', '.m4v', '.wmv', '.ts', '.flv', '.webm')
    TrailingArticles = @('The', 'A', 'An', 'De', 'Het', 'Een')
    RequestDelayMs   = 200
}

$script:TraktApi = @{
    Version     = '2'
    RedirectUri = 'urn:ietf:wg:oauth:2.0:oob'
    BaseUrl     = 'https://api.trakt.tv'
    AuthUrl     = 'https://trakt.tv/oauth/authorize'
}

# Watch status constants
$script:WatchStatus = @{
    Watched   = 'Watched'
    Unwatched = 'Unwatched'
    Unknown   = 'Unknown'
    NoMatch   = 'Unknown (no Trakt match)'
    Error     = 'Unknown (error)'
}

# Runtime state
$script:State = @{
    AccessToken      = $null
    ClientId         = $null
    Cache            = @{}
    Config           = @{}
    WatchedByTraktId = @{}
    WatchedByImdbId  = @{}
}

#endregion

#region ===== CONFIGURATION FILE =====

function New-DefaultConfig {
    <#
    .SYNOPSIS
        Creates a default configuration file.
    #>
    $defaultConfig = [ordered]@{
        rootFolders      = @('C:\Movies')
        excludePatterns  = $script:Defaults.ExcludePatterns
        cacheTTLHours    = $script:Defaults.CacheTTLHours
        outputFormat     = $script:Defaults.OutputFormat
        videoExtensions  = $script:Defaults.VideoExtensions
        trailingArticles = $script:Defaults.TrailingArticles
        clientId         = ''
        clientSecret     = ''
        manualMappings   = @{
            '_Example Movie Name (2020)' = @{
                trakt_id   = 0
                trakt_slug = 'example-slug'
                imdb_id    = 'tt0000000'
            }
        }
    }

    $json = $defaultConfig | ConvertTo-Json -Depth 5
    $json | Set-Content -LiteralPath $script:Paths.Config -Encoding UTF8

    Write-Host "Created default config file: $($script:Paths.Config)" -ForegroundColor Green
    Write-Host "Please edit the file to configure your settings." -ForegroundColor Yellow
}

function Import-Configuration {
    <#
    .SYNOPSIS
        Loads configuration from config.json, with command-line overrides.
    #>
    param(
        [hashtable]$ScriptParameters
    )

    $config = @{
        RootFolders      = $script:Defaults.RootFolders
        ExcludePatterns  = $script:Defaults.ExcludePatterns
        CacheTTLHours    = $script:Defaults.CacheTTLHours
        OutputFormat     = $script:Defaults.OutputFormat
        VideoExtensions  = $script:Defaults.VideoExtensions
        TrailingArticles = $script:Defaults.TrailingArticles
        ManualMappings   = @{}
        ClientId         = $null
        ClientSecret     = $null
    }

    # Load from config file if exists
    if (Test-Path -LiteralPath $script:Paths.Config) {
        try {
            $fileConfig = Get-Content -LiteralPath $script:Paths.Config -Raw | ConvertFrom-Json

            if ($fileConfig.rootFolders) { $config.RootFolders = @($fileConfig.rootFolders) }
            if ($fileConfig.excludePatterns) { $config.ExcludePatterns = @($fileConfig.excludePatterns) }
            if ($fileConfig.cacheTTLHours) { $config.CacheTTLHours = [int]$fileConfig.cacheTTLHours }
            if ($fileConfig.outputFormat) { $config.OutputFormat = $fileConfig.outputFormat }
            if ($fileConfig.videoExtensions) { $config.VideoExtensions = @($fileConfig.videoExtensions) }
            if ($fileConfig.trailingArticles) { $config.TrailingArticles = @($fileConfig.trailingArticles) }
            if ($fileConfig.clientId) { $config.ClientId = $fileConfig.clientId }
            if ($fileConfig.clientSecret) { $config.ClientSecret = $fileConfig.clientSecret }

            # Load manual mappings (skip example entries starting with _)
            if ($fileConfig.manualMappings) {
                foreach ($prop in $fileConfig.manualMappings.PSObject.Properties) {
                    if (-not $prop.Name.StartsWith('_')) {
                        $config.ManualMappings[$prop.Name.ToLowerInvariant()] = @{
                            trakt_id   = $prop.Value.trakt_id
                            trakt_slug = $prop.Value.trakt_slug
                            imdb_id    = $prop.Value.imdb_id
                        }
                    }
                }
            }

            Write-Verbose "Loaded configuration from movies-config.json"
        }
        catch {
            Write-Warning "Could not parse movies-config.json: $_"
        }
    }

    # Command-line parameters override config file
    if ($ScriptParameters.ContainsKey('RootFolder') -and $ScriptParameters.RootFolder) {
        $config.RootFolders = @($ScriptParameters.RootFolder)
    }
    if ($ScriptParameters.ContainsKey('ExcludePattern') -and $ScriptParameters.ExcludePattern) {
        $config.ExcludePatterns = @($ScriptParameters.ExcludePattern)
    }
    if ($ScriptParameters.ContainsKey('CacheTTLHours') -and $ScriptParameters.CacheTTLHours) {
        $config.CacheTTLHours = $ScriptParameters.CacheTTLHours
    }
    if ($ScriptParameters.ContainsKey('OutputFormat') -and $ScriptParameters.OutputFormat) {
        $config.OutputFormat = $ScriptParameters.OutputFormat
    }
    if ($ScriptParameters.ContainsKey('ClientId') -and $ScriptParameters.ClientId) {
        $config.ClientId = $ScriptParameters.ClientId
    }
    if ($ScriptParameters.ContainsKey('ClientSecret') -and $ScriptParameters.ClientSecret) {
        $config.ClientSecret = $ScriptParameters.ClientSecret
    }

    return $config
}

#endregion

#region ===== TOKEN MANAGEMENT =====

function Import-TraktTokens {
    <#
    .SYNOPSIS
        Loads saved tokens from disk.
    #>
    if (-not (Test-Path -LiteralPath $script:Paths.Tokens)) {
        return $null
    }
    try {
        $content = Get-Content -LiteralPath $script:Paths.Tokens -Raw -ErrorAction Stop
        return $content | ConvertFrom-Json
    }
    catch {
        Write-Warning "Could not parse tokens.json: $_"
        return $null
    }
}

function Export-TraktTokens {
    <#
    .SYNOPSIS
        Saves tokens to disk.
    #>
    param(
        [Parameter(Mandatory)][string]$AccessToken,
        [Parameter(Mandatory)][string]$RefreshToken,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$ClientSecret
    )

    $data = [ordered]@{
        access_token  = $AccessToken
        refresh_token = $RefreshToken
        client_id     = $ClientId
        client_secret = $ClientSecret
        saved_at_utc  = (Get-Date).ToUniversalTime().ToString('o')
    }

    $data | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:Paths.Tokens -Encoding UTF8
}

function Initialize-TraktAuth {
    <#
    .SYNOPSIS
        Ensures valid authentication is available, prompting if necessary.
    #>
    $stored = Import-TraktTokens

    # Use stored credentials if available
    if ($stored -and $stored.access_token -and $stored.refresh_token) {
        $script:State.AccessToken = $stored.access_token
        $script:State.ClientId = if ($script:State.Config.ClientId) { $script:State.Config.ClientId } else { $stored.client_id }

        if ($script:State.ClientId -and $stored.client_secret) {
            Write-Verbose "Loaded existing tokens from tokens.json"
            return
        }
    }

    # Use config values or prompt with helpful instructions
    if (-not $script:State.Config.ClientId -or -not $script:State.Config.ClientSecret) {
        Write-Host ""
        Write-Host ("=" * 70) -ForegroundColor Cyan
        Write-Host "TRAKT API SETUP" -ForegroundColor Cyan
        Write-Host ("=" * 70) -ForegroundColor Cyan
        Write-Host ""
        Write-Host "To use this script, you need a Trakt API application:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  1. Go to: https://trakt.tv/oauth/applications/new" -ForegroundColor White
        Write-Host "  2. Fill in the form:" -ForegroundColor White
        Write-Host "     - Name: Any name (e.g., 'Movie Cleanup Script')" -ForegroundColor Gray
        Write-Host "     - Redirect URI: urn:ietf:wg:oauth:2.0:oob" -ForegroundColor Gray
        Write-Host "     - Leave other fields default" -ForegroundColor Gray
        Write-Host "  3. Click 'Save App'" -ForegroundColor White
        Write-Host "  4. Copy the Client ID and Client Secret shown" -ForegroundColor White
        Write-Host ""
        Write-Host "Tip: Add these to movies-config.json to skip this step next time." -ForegroundColor DarkGray
        Write-Host ""
    }

    $cid = if ($script:State.Config.ClientId) { $script:State.Config.ClientId } else { Read-Host "Enter your Trakt API Client ID" }
    $csec = if ($script:State.Config.ClientSecret) { $script:State.Config.ClientSecret } else { Read-Host "Enter your Trakt API Client Secret" }

    $script:State.ClientId = $cid

    # Build authorization URL
    $authUrl = "{0}?response_type=code&client_id={1}&redirect_uri={2}" -f `
        $script:TraktApi.AuthUrl, $cid, [uri]::EscapeDataString($script:TraktApi.RedirectUri)

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "AUTHORIZATION REQUIRED" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "This script needs permission to access your Trakt watch history." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  1. Open this URL in your browser:" -ForegroundColor White
    Write-Host "     $authUrl" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  2. Log in to Trakt if prompted" -ForegroundColor White
    Write-Host "  3. Click 'Accept' to authorize the app" -ForegroundColor White
    Write-Host "  4. Copy the PIN code shown on the page" -ForegroundColor White
    Write-Host ""
    $authCode = Read-Host "Enter the PIN code from Trakt"

    # Exchange code for tokens
    $tokenBody = @{
        code          = $authCode
        client_id     = $cid
        client_secret = $csec
        redirect_uri  = $script:TraktApi.RedirectUri
        grant_type    = 'authorization_code'
    }

    try {
        $resp = Invoke-TraktRequest -Endpoint '/oauth/token' -Method POST -Body $tokenBody -SkipAuth
        $script:State.AccessToken = $resp.access_token
        Export-TraktTokens -AccessToken $resp.access_token -RefreshToken $resp.refresh_token `
            -ClientId $cid -ClientSecret $csec
        Write-Host "Authentication successful. Tokens saved." -ForegroundColor Green
    }
    catch {
        throw "Failed to authenticate with Trakt: $_"
    }
}

function Update-TraktAccessToken {
    <#
    .SYNOPSIS
        Refreshes the access token using the stored refresh token.
    #>
    $stored = Import-TraktTokens
    if (-not $stored -or -not $stored.refresh_token) {
        throw "No refresh token available. Please re-authenticate."
    }

    $refreshBody = @{
        refresh_token = $stored.refresh_token
        client_id     = $stored.client_id
        client_secret = $stored.client_secret
        redirect_uri  = $script:TraktApi.RedirectUri
        grant_type    = 'refresh_token'
    }

    try {
        $resp = Invoke-TraktRequest -Endpoint '/oauth/token' -Method POST -Body $refreshBody -SkipAuth
        $script:State.AccessToken = $resp.access_token
        Export-TraktTokens -AccessToken $resp.access_token -RefreshToken $resp.refresh_token `
            -ClientId $stored.client_id -ClientSecret $stored.client_secret
        Write-Verbose "Access token refreshed successfully"
        return $resp.access_token
    }
    catch {
        throw "Failed to refresh access token: $_"
    }
}

#endregion

#region ===== CACHE MANAGEMENT =====

function Import-MovieCache {
    <#
    .SYNOPSIS
        Loads the movie results cache from disk.
    #>
    if (-not (Test-Path -LiteralPath $script:Paths.Cache)) {
        return @{}
    }
    try {
        $content = Get-Content -LiteralPath $script:Paths.Cache -Raw -ErrorAction Stop
        $parsed = $content | ConvertFrom-Json

        # Convert PSObject to hashtable
        $cache = @{}
        foreach ($prop in $parsed.PSObject.Properties) {
            $cache[$prop.Name] = $prop.Value
        }
        return $cache
    }
    catch {
        Write-Warning "Could not parse cache file: $_"
        return @{}
    }
}

function Export-MovieCache {
    <#
    .SYNOPSIS
        Saves the movie results cache to disk.
    #>
    param([Parameter(Mandatory)][hashtable]$Cache)

    $Cache | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $script:Paths.Cache -Encoding UTF8
}

function Sync-MovieCache {
    <#
    .SYNOPSIS
        Removes cache entries for movies whose folders no longer exist on disk.
    #>
    param(
        [Parameter(Mandatory)][hashtable]$Cache
    )

    $keysToRemove = [System.Collections.Generic.List[string]]::new()

    foreach ($key in $Cache.Keys) {
        $entry = $Cache[$key]

        # If entry has a folder path, verify it still exists
        if ($entry.folder_path) {
            if (-not (Test-Path -LiteralPath $entry.folder_path -PathType Container)) {
                $keysToRemove.Add($key)
            }
        }
    }

    foreach ($key in $keysToRemove) {
        $Cache.Remove($key)
        Write-Verbose "Removed stale cache entry (folder deleted): $key"
    }

    if ($keysToRemove.Count -gt 0) {
        Write-Verbose "Pruned $($keysToRemove.Count) stale cache entries"
    }

    return $keysToRemove.Count
}

function ConvertTo-DateTime {
    <#
    .SYNOPSIS
        Robustly parses a datetime string, handling multiple formats.
    #>
    param([string]$DateString)

    if ([string]::IsNullOrWhiteSpace($DateString)) {
        return $null
    }

    try {
        return [datetime]::ParseExact($DateString, 'o', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    catch { }

    try {
        return [datetime]::Parse($DateString, [System.Globalization.CultureInfo]::InvariantCulture)
    }
    catch { }

    try {
        return [datetime]::Parse($DateString)
    }
    catch { }

    try {
        return Get-Date -Date $DateString
    }
    catch {
        return $null
    }
}

function Test-CacheValid {
    <#
    .SYNOPSIS
        Checks if a cache entry is still valid based on TTL.
    #>
    param(
        $CacheEntry,
        [Parameter(Mandatory)][int]$TTLHours
    )

    if ($null -eq $CacheEntry) {
        return $false
    }

    if (-not $CacheEntry.cached_at) {
        return $false
    }

    # Check TTL
    $cachedAt = ConvertTo-DateTime -DateString $CacheEntry.cached_at
    if (-not $cachedAt) {
        return $false
    }
    $expiresAt = $cachedAt.AddHours($TTLHours)

    return (Get-Date) -lt $expiresAt
}

function Get-CacheKey {
    <#
    .SYNOPSIS
        Generates a consistent cache key for a movie folder.
    #>
    param([Parameter(Mandatory)][string]$FolderName)

    return $FolderName.Trim().ToLowerInvariant()
}

#endregion

#region ===== TRAKT API =====

function New-TraktHeaders {
    <#
    .SYNOPSIS
        Builds standard Trakt API headers.
    #>
    param([switch]$IncludeAuth)

    $headers = @{
        'Content-Type'      = 'application/json'
        'trakt-api-version' = $script:TraktApi.Version
        'trakt-api-key'     = $script:State.ClientId
    }

    if ($IncludeAuth -and $script:State.AccessToken) {
        $headers['Authorization'] = "Bearer $($script:State.AccessToken)"
    }

    return $headers
}

function Invoke-TraktRequest {
    <#
    .SYNOPSIS
        Makes a request to the Trakt API with automatic retry on 401.
    #>
    param(
        [Parameter(Mandatory)][string]$Endpoint,
        [ValidateSet('GET', 'POST')][string]$Method = 'GET',
        [object]$Body = $null,
        [switch]$SkipAuth
    )

    # Rate limiting
    Start-Sleep -Milliseconds $script:Defaults.RequestDelayMs

    $uri = if ($Endpoint.StartsWith('http')) { $Endpoint } else { $script:TraktApi.BaseUrl + $Endpoint }
    $headers = New-TraktHeaders -IncludeAuth:(-not $SkipAuth)

    $invokeParams = @{
        Uri         = $uri
        Method      = $Method
        Headers     = $headers
        ErrorAction = 'Stop'
    }

    if ($Body) {
        $invokeParams['Body'] = $Body | ConvertTo-Json -Depth 10
    }

    try {
        return Invoke-RestMethod @invokeParams
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }

        # Retry once on 401 with refreshed token
        if (-not $SkipAuth -and $statusCode -eq 401) {
            Write-Verbose "Token expired, refreshing..."
            $null = Update-TraktAccessToken

            # Rebuild headers with new token and retry
            $invokeParams['Headers'] = New-TraktHeaders -IncludeAuth
            return Invoke-RestMethod @invokeParams
        }

        throw
    }
}

function Get-TraktWatchedMovies {
    <#
    .SYNOPSIS
        Gets all watched movies for the authenticated user.
    #>
    Write-Verbose "Fetching watched movies from Trakt..."
    return Invoke-TraktRequest -Endpoint '/sync/watched/movies'
}

function Find-TraktMovie {
    <#
    .SYNOPSIS
        Searches Trakt for a movie and returns the best match.
        Checks manual mappings first.
    #>
    param(
        [Parameter(Mandatory)][string]$Title,
        [int]$Year,
        [string]$FolderName
    )

    # Check manual mappings first
    $cacheKey = Get-CacheKey -FolderName $FolderName
    if ($script:State.Config.ManualMappings.ContainsKey($cacheKey)) {
        $mapping = $script:State.Config.ManualMappings[$cacheKey]
        Write-Verbose "  Using manual mapping for: $FolderName"
        return @{
            movie = @{
                ids = @{
                    trakt = $mapping.trakt_id
                    slug  = $mapping.trakt_slug
                    imdb  = $mapping.imdb_id
                }
                title = $Title
                year  = $Year
            }
        }
    }

    # Search with original title
    $encoded = [uri]::EscapeDataString($Title)
    Write-Verbose "  Searching Trakt for: $Title"
    $results = Invoke-TraktRequest -Endpoint "/search/movie?query=$encoded"
    $candidates = @($results)

    # If no results and title contains punctuation, try without it
    if ($candidates.Count -eq 0 -and $Title -match '[,;:!?]') {
        $cleanTitle = $Title -replace '[,;:!?]', ' ' -replace '\s+', ' '
        $encoded = [uri]::EscapeDataString($cleanTitle.Trim())
        Write-Verbose "  Retrying search without punctuation: $cleanTitle"
        $results = Invoke-TraktRequest -Endpoint "/search/movie?query=$encoded"
        $candidates = @($results)
    }

    if ($candidates.Count -eq 0) {
        return $null
    }

    # Normalize function for comparison (lowercase, remove punctuation)
    $normalize = { param($s) ($s -replace '[^a-zA-Z0-9\s]', '' -replace '\s+', ' ').Trim().ToLowerInvariant() }

    $normalizedTitle = & $normalize $Title

    # Priority: exact title+year > normalized title+year > year match > title match > first result
    if ($Year) {
        # Exact match
        $exact = $candidates | Where-Object { $_.movie.title -eq $Title -and $_.movie.year -eq $Year }
        if ($exact) { return $exact[0] }

        # Normalized match with year
        $normalizedMatch = $candidates | Where-Object { 
            (& $normalize $_.movie.title) -eq $normalizedTitle -and $_.movie.year -eq $Year 
        }
        if ($normalizedMatch) { return $normalizedMatch[0] }

        # Just year match
        $yearMatch = $candidates | Where-Object { $_.movie.year -eq $Year }
        if ($yearMatch) { return $yearMatch[0] }
    }

    # Title match (exact)
    $titleMatch = $candidates | Where-Object { $_.movie.title -eq $Title }
    if ($titleMatch) { return $titleMatch[0] }

    # Title match (normalized)
    $normalizedTitleMatch = $candidates | Where-Object { 
        (& $normalize $_.movie.title) -eq $normalizedTitle 
    }
    if ($normalizedTitleMatch) { return $normalizedTitleMatch[0] }

    # Fall back to first result
    return $candidates[0]
}

function Get-TraktMovieDetails {
    <#
    .SYNOPSIS
        Gets extended movie details (runtime, genres, rating, etc.).
    #>
    param([Parameter(Mandatory)][int]$TraktMovieId)

    Write-Verbose "  Fetching movie details..."
    return Invoke-TraktRequest -Endpoint "/movies/$TraktMovieId`?extended=full"
}

#endregion

#region ===== FOLDER & FILE PROCESSING =====

function Restore-ArticlePrefix {
    <#
    .SYNOPSIS
        Moves trailing article back to the front of a title.
        "Amateur, The" -> "The Amateur"
        "Big Bold Beautiful Journey, A" -> "A Big Bold Beautiful Journey"
        Only matches configured articles, leaves other commas alone.
    #>
    param([Parameter(Mandatory)][string]$Title)

    $articles = $script:State.Config.TrailingArticles
    if (-not $articles) { $articles = $script:Defaults.TrailingArticles }

    # Check each article explicitly (case-insensitive)
    foreach ($article in $articles) {
        $suffix = ", $article"
        if ($Title.EndsWith($suffix, [StringComparison]::OrdinalIgnoreCase)) {
            $main = $Title.Substring(0, $Title.Length - $suffix.Length)
            return "{0} {1}" -f $article, $main
        }
    }

    return $Title
}

function ConvertFrom-FolderName {
    <#
    .SYNOPSIS
        Parses "Movie Name (YYYY)" format into title and year components.
        Also handles trailing articles like "Movie, The (2020)".
    #>
    param([Parameter(Mandatory)][string]$FolderName)

    if ($FolderName -match '^(?<title>.+?)\s*\((?<year>\d{4})\)\s*$') {
        $title = Restore-ArticlePrefix -Title $Matches['title'].Trim()
        return [PSCustomObject]@{
            Title = $title
            Year  = [int]$Matches['year']
        }
    }

    $title = Restore-ArticlePrefix -Title $FolderName.Trim()
    return [PSCustomObject]@{
        Title = $title
        Year  = $null
    }
}

function Get-VideoFiles {
    <#
    .SYNOPSIS
        Gets all video files in a folder, optionally excluding patterns.
    #>
    param(
        [Parameter(Mandatory)][System.IO.DirectoryInfo]$Folder,
        [string[]]$ExcludePatterns
    )

    $extensions = $script:State.Config.VideoExtensions
    if (-not $extensions) { $extensions = $script:Defaults.VideoExtensions }

    $files = Get-ChildItem -Path $Folder.FullName -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $extensions -contains $_.Extension.ToLowerInvariant() }

    if ($ExcludePatterns) {
        foreach ($pattern in $ExcludePatterns) {
            $files = $files | Where-Object { $_.Name -notmatch $pattern }
        }
    }

    return $files
}

#endregion

#region ===== MOVIE PROCESSING =====

function Test-MovieWatched {
    <#
    .SYNOPSIS
        Checks if a movie is in the watched list based on Trakt ID or IMDB ID.
        Uses pre-built hashtables for O(1) lookup.
    #>
    param(
        [Parameter(Mandatory)]$TraktMatch
    )

    $traktId = $TraktMatch.movie.ids.trakt
    $imdbId = $TraktMatch.movie.ids.imdb

    # Try Trakt ID first
    if ($traktId -and $script:State.WatchedByTraktId.ContainsKey($traktId)) {
        $watched = $script:State.WatchedByTraktId[$traktId]
        return @{
            IsWatched = $true
            WatchedAt = $watched.last_watched_at
        }
    }
    
    # Try IMDB ID as fallback
    if ($imdbId -and $script:State.WatchedByImdbId.ContainsKey($imdbId)) {
        $watched = $script:State.WatchedByImdbId[$imdbId]
        return @{
            IsWatched = $true
            WatchedAt = $watched.last_watched_at
        }
    }

    return @{
        IsWatched = $false
        WatchedAt = $null
    }
}

function Format-Runtime {
    <#
    .SYNOPSIS
        Formats runtime in minutes to a friendly string.
    #>
    param([int]$Minutes)

    if ($Minutes -le 0) {
        return $null
    }

    $hours = [math]::Floor($Minutes / 60)
    $mins = $Minutes % 60

    if ($hours -gt 0) {
        return "{0}h {1}m" -f $hours, $mins
    }
    return "{0}m" -f $mins
}

function Get-MovieData {
    <#
    .SYNOPSIS
        Processes a single movie folder, using cache when valid.
    #>
    param(
        [Parameter(Mandatory)][System.IO.DirectoryInfo]$Folder,
        [Parameter(Mandatory)][hashtable]$Cache,
        [int]$CacheTTLHours,
        [switch]$ForceRefresh,
        [string[]]$ExcludePatterns
    )

    $cacheKey = Get-CacheKey -FolderName $Folder.Name
    $parsed = ConvertFrom-FolderName -FolderName $Folder.Name
    $displayTitle = if ($parsed.Year) {
        "{0} ({1})" -f $parsed.Title, $parsed.Year
    }
    else {
        $parsed.Title
    }

    Write-Verbose "Processing: $displayTitle"

    # Check cache
    $cached = $Cache[$cacheKey]

    # Quick size check - get current total bytes from disk
    $currentTotalBytes = 0L
    $videoFiles = Get-VideoFiles -Folder $Folder -ExcludePatterns $ExcludePatterns
    if ($videoFiles) {
        $sum = ($videoFiles | Measure-Object -Property Length -Sum).Sum
        if ($sum) { $currentTotalBytes = [long]$sum }
    }

    # Invalidate cache if disk size changed
    $sizeChanged = $false
    if ($cached -and $cached.total_bytes -and $cached.total_bytes -ne $currentTotalBytes) {
        $sizeChanged = $true
        Write-Verbose "  Disk content changed (cached: $($cached.total_bytes) bytes, current: $currentTotalBytes bytes)"
    }

    $useCache = -not $ForceRefresh -and -not $sizeChanged -and (Test-CacheValid -CacheEntry $cached -TTLHours $CacheTTLHours)

    $traktMatch = $null
    $status = $script:WatchStatus.Unknown
    $watchedAt = $null
    $traktUrl = $null

    # Metadata fields
    $runtime = $null
    $genres = $null
    $rating = $null
    $year = $parsed.Year

    if ($useCache) {
        Write-Verbose "  Using cached data"
        $status = $cached.status
        $watchedAt = if ($cached.watched_at) { ConvertTo-DateTime -DateString $cached.watched_at } else { $null }
        $traktUrl = $cached.trakt_url
        $runtime = $cached.runtime
        $genres = $cached.genres
        $rating = $cached.rating
        if ($cached.year) { $year = $cached.year }
    }
    else {
        # Fetch from Trakt
        try {
            $traktMatch = Find-TraktMovie -Title $parsed.Title -Year $parsed.Year -FolderName $Folder.Name

            if ($traktMatch) {
                $movie = $traktMatch.movie
                Write-Verbose "  Matched: $($movie.title) ($($movie.year))"

                $traktId = $movie.ids.trakt
                $traktUrl = "https://trakt.tv/movies/$($movie.ids.slug)"
                $year = $movie.year

                # Check if watched
                $watchResult = Test-MovieWatched -TraktMatch $traktMatch
                if ($watchResult.IsWatched) {
                    $status = $script:WatchStatus.Watched
                    $watchedAt = ConvertTo-DateTime -DateString $watchResult.WatchedAt
                }
                else {
                    $status = $script:WatchStatus.Unwatched
                }

                # Fetch extended details
                $details = Get-TraktMovieDetails -TraktMovieId $traktId
                if ($details) {
                    $runtime = Format-Runtime -Minutes $details.runtime
                    $genres = if ($details.genres) { ($details.genres -join ', ') } else { $null }
                    $rating = if ($details.rating) { [math]::Round($details.rating, 1) } else { $null }
                }

                # Update cache
                $Cache[$cacheKey] = @{
                    trakt_id    = $traktId
                    trakt_slug  = $movie.ids.slug
                    imdb_id     = $movie.ids.imdb
                    trakt_url   = $traktUrl
                    status      = $status
                    watched_at  = if ($watchedAt) { $watchedAt.ToString('o') } else { $null }
                    cached_at   = (Get-Date).ToUniversalTime().ToString('o')
                    total_bytes = $currentTotalBytes
                    folder_path = $Folder.FullName
                    runtime     = $runtime
                    genres      = $genres
                    rating      = $rating
                    year        = $year
                }
            }
            else {
                Write-Warning "  No Trakt match found for: $($parsed.Title)"
                $status = $script:WatchStatus.NoMatch
            }
        }
        catch {
            Write-Error "  Failed to fetch Trakt data for $($Folder.Name): $_"
            $status = $script:WatchStatus.Error
        }
    }

    # Always update folder_path and total_bytes in cache
    $existingEntry = $Cache[$cacheKey]
    if ($existingEntry -and ($existingEntry.folder_path -ne $Folder.FullName -or $existingEntry.total_bytes -ne $currentTotalBytes)) {
        $Cache[$cacheKey] = @{
            trakt_id    = $existingEntry.trakt_id
            trakt_slug  = $existingEntry.trakt_slug
            imdb_id     = $existingEntry.imdb_id
            trakt_url   = $existingEntry.trakt_url
            status      = $existingEntry.status
            watched_at  = $existingEntry.watched_at
            cached_at   = $existingEntry.cached_at
            total_bytes = $currentTotalBytes
            folder_path = $Folder.FullName
            runtime     = $existingEntry.runtime
            genres      = $existingEntry.genres
            rating      = $existingEntry.rating
            year        = $existingEntry.year
        }
    }

    $totalGB = [math]::Round($currentTotalBytes / 1GB, 2)

    return [PSCustomObject]@{
        Title      = $Folder.Name
        Status     = $status
        Year       = $year
        Runtime    = $runtime
        Rating     = $rating
        Genres     = $genres
        WatchedAt  = $watchedAt
        SizeGB     = $totalGB
        TraktUrl   = $traktUrl
        FolderPath = $Folder.FullName
    }
}

#endregion

#region ===== CLEANUP =====

function Remove-ToRecycleBin {
    <#
    .SYNOPSIS
        Moves a folder to the Recycle Bin.
    #>
    param([Parameter(Mandatory)][string]$Path)

    Add-Type -AssemblyName Microsoft.VisualBasic
    [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory(
        $Path,
        [Microsoft.VisualBasic.FileIO.UIOption]::OnlyErrorDialogs,
        [Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin
    )
}

function Invoke-MovieCleanup {
    <#
    .SYNOPSIS
        Performs cleanup actions on selected movies.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][array]$Movies,
        [string]$MoveToPath,
        [switch]$SkipRecycleBin
    )

    $cleanedCount = 0
    $cleanedSize = 0.0

    foreach ($movie in $Movies) {
        $folderPath = $movie.FolderPath

        if (-not (Test-Path -LiteralPath $folderPath)) {
            Write-Warning "Folder not found: $folderPath"
            continue
        }

        $actionDescription = if ($MoveToPath) { "Move" } else { "Delete" }
        $targetDescription = if ($MoveToPath) { " to $MoveToPath" } else { "" }

        if ($PSCmdlet.ShouldProcess("$($movie.Title) ($($movie.SizeGB) GB)", "$actionDescription$targetDescription")) {
            try {
                if ($MoveToPath) {
                    # Move to archive
                    $destination = Join-Path -Path $MoveToPath -ChildPath (Split-Path $folderPath -Leaf)
                    if (-not (Test-Path -LiteralPath $MoveToPath)) {
                        $null = New-Item -Path $MoveToPath -ItemType Directory -Force
                    }
                    Move-Item -LiteralPath $folderPath -Destination $destination -Force
                    Write-Host "  Moved: $($movie.Title)" -ForegroundColor Green
                }
                elseif ($SkipRecycleBin) {
                    # Permanent delete
                    Remove-Item -LiteralPath $folderPath -Recurse -Force
                    Write-Host "  Deleted: $($movie.Title)" -ForegroundColor Yellow
                }
                else {
                    # Recycle Bin
                    Remove-ToRecycleBin -Path $folderPath
                    Write-Host "  Recycled: $($movie.Title)" -ForegroundColor Green
                }

                $cleanedCount++
                $cleanedSize += $movie.SizeGB
            }
            catch {
                Write-Error "  Failed to process $($movie.Title): $_"
            }
        }
    }

    return [PSCustomObject]@{
        Count  = $cleanedCount
        SizeGB = $cleanedSize
    }
}

function Get-CleanupCandidates {
    <#
    .SYNOPSIS
        Filters movies based on cleanup criteria (watched status).
    #>
    param(
        [Parameter(Mandatory)][array]$Movies
    )

    return $Movies | Where-Object { $_.Status -eq $script:WatchStatus.Watched }
}

#endregion

#region ===== OUTPUT =====

function Write-Summary {
    <#
    .SYNOPSIS
        Displays summary statistics.
    #>
    param([Parameter(Mandatory)][array]$MoviesData)

    $totalMovies = $MoviesData.Count
    $watched = ($MoviesData | Where-Object { $_.Status -eq $script:WatchStatus.Watched }).Count
    $unwatched = ($MoviesData | Where-Object { $_.Status -eq $script:WatchStatus.Unwatched }).Count
    $unknown = ($MoviesData | Where-Object { $_.Status -like "Unknown*" }).Count

    $totalSize = ($MoviesData | Measure-Object -Property SizeGB -Sum).Sum
    $watchedSize = ($MoviesData | Where-Object { $_.Status -eq $script:WatchStatus.Watched } | Measure-Object -Property SizeGB -Sum).Sum
    $unwatchedSize = ($MoviesData | Where-Object { $_.Status -eq $script:WatchStatus.Unwatched } | Measure-Object -Property SizeGB -Sum).Sum

    if (-not $watchedSize) { $watchedSize = 0 }
    if (-not $unwatchedSize) { $unwatchedSize = 0 }

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "SUMMARY" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ("Movies: {0} total | {1} watched | {2} unwatched | {3} unknown" -f $totalMovies, $watched, $unwatched, $unknown)
    Write-Host ("Size:   {0:N2} TB total | {1:N2} TB watched | {2:N2} TB unwatched" -f ($totalSize / 1024), ($watchedSize / 1024), ($unwatchedSize / 1024))
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
}

function Export-Results {
    <#
    .SYNOPSIS
        Exports results in the specified format.
    #>
    param(
        [Parameter(Mandatory)][array]$MoviesData,
        [Parameter(Mandatory)][string]$Format,
        [string]$Path,
        [switch]$Interactive
    )

    # Sort by watched date (oldest first), then by size (largest first)
    $sorted = $MoviesData | Sort-Object @{Expression = 'WatchedAt'; Ascending = $true }, @{Expression = 'SizeGB'; Descending = $true }

    # Select columns for display (exclude FolderPath from normal view)
    $displayColumns = @('Title', 'Status', 'Year', 'Runtime', 'Rating', 'Genres', 'WatchedAt', 'SizeGB', 'TraktUrl')

    switch ($Format) {
        'GridView' {
            if ($sorted.Count -gt 0) {
                if ($Interactive) {
                    return $sorted | Select-Object $displayColumns | Out-GridView -Title 'Select movies for cleanup (Ctrl+Click for multiple)' -PassThru
                }
                else {
                    $sorted | Select-Object $displayColumns | Out-GridView -Title 'Movies - Trakt Watch Status & Disk Usage'
                    return $null
                }
            }
            else {
                Write-Warning "No movies to display."
                return $null
            }
        }
        'CSV' {
            if (-not $Path) {
                throw "OutputPath is required for CSV format."
            }
            $sorted | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
            Write-Host "Results exported to: $Path" -ForegroundColor Green
            return $null
        }
        'JSON' {
            if (-not $Path) {
                throw "OutputPath is required for JSON format."
            }
            $sorted | ConvertTo-Json -Depth 5 | Set-Content -Path $Path -Encoding UTF8
            Write-Host "Results exported to: $Path" -ForegroundColor Green
            return $null
        }
        'Console' {
            $sorted | Format-Table -AutoSize -Property Title, Status, Year, Runtime, WatchedAt, SizeGB
            return $null
        }
    }
}

#endregion

#region ===== MAIN =====

# Handle -CreateConfig first
if ($CreateConfig) {
    New-DefaultConfig
    return
}

try {
    # Load configuration (config file + parameter overrides)
    $script:State.Config = Import-Configuration -ScriptParameters $PSBoundParameters

    # Validate we have root folders
    if (-not $script:State.Config.RootFolders -or $script:State.Config.RootFolders.Count -eq 0) {
        throw "No root folders specified. Use -RootFolder parameter or configure rootFolders in movies-config.json"
    }

    # Initialize authentication
    Initialize-TraktAuth

    # Load cache
    $script:State.Cache = Import-MovieCache

    # Fetch watched movies list once (used for all movies)
    Write-Host "Fetching watched movies from Trakt..." -ForegroundColor Cyan
    $watchedMoviesRaw = @(Get-TraktWatchedMovies)
    Write-Host "Found $($watchedMoviesRaw.Count) watched movies on Trakt" -ForegroundColor Gray
    
    # Build lookup hashtables for fast matching
    $script:State.WatchedByTraktId = @{}
    $script:State.WatchedByImdbId = @{}
    
    foreach ($watched in $watchedMoviesRaw) {
        $traktId = $watched.movie.ids.trakt
        $imdbId = $watched.movie.ids.imdb
        
        if ($traktId) {
            $script:State.WatchedByTraktId[$traktId] = $watched
        }
        if ($imdbId) {
            $script:State.WatchedByImdbId[$imdbId] = $watched
        }
    }
    
    Write-Verbose "Built lookup: $($script:State.WatchedByTraktId.Count) by Trakt ID, $($script:State.WatchedByImdbId.Count) by IMDB ID"

    # Collect all movie folders from all root paths
    $allMovieFolders = [System.Collections.Generic.List[System.IO.DirectoryInfo]]::new()

    foreach ($root in $script:State.Config.RootFolders) {
        if (-not (Test-Path -LiteralPath $root)) {
            Write-Warning "Root folder not found: $root"
            continue
        }

        $folders = Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue
        if ($folders) {
            foreach ($f in $folders) {
                $allMovieFolders.Add($f)
            }
        }
    }

    if ($allMovieFolders.Count -eq 0) {
        Write-Warning "No movie folders found in the specified root folder(s)."
        return
    }

    Write-Host "Processing $($allMovieFolders.Count) movies..." -ForegroundColor Cyan

    # Process movies
    $moviesData = [System.Collections.Generic.List[PSCustomObject]]::new()
    $total = $allMovieFolders.Count
    $idx = 0

    foreach ($folder in $allMovieFolders) {
        $idx++
        Write-Progress -Activity "Processing Movies" -Status "$idx of $total" -PercentComplete (100 * $idx / $total)

        $movieResult = Get-MovieData -Folder $folder -Cache $script:State.Cache `
            -CacheTTLHours $script:State.Config.CacheTTLHours -ForceRefresh:$ForceRefresh `
            -ExcludePatterns $script:State.Config.ExcludePatterns

        $moviesData.Add($movieResult)
    }

    Write-Progress -Activity "Processing Movies" -Completed

    # Prune cache entries for movies that no longer exist on disk, then save
    $null = Sync-MovieCache -Cache $script:State.Cache
    Export-MovieCache -Cache $script:State.Cache

    # Display summary
    Write-Summary -MoviesData $moviesData

    # Handle cleanup operations
    $cleanupRequested = $CleanupWatched -or $Interactive

    # Watched movie cleanup
    if ($CleanupWatched) {
        $candidates = Get-CleanupCandidates -Movies $moviesData

        if ($candidates.Count -gt 0) {
            $totalSize = ($candidates | Measure-Object -Property SizeGB -Sum).Sum
            Write-Host ""
            Write-Host "Watched movie candidates: $($candidates.Count) movies ($([math]::Round($totalSize, 2)) GB)" -ForegroundColor Yellow

            $result = Invoke-MovieCleanup -Movies $candidates -MoveToPath $MoveToPath -SkipRecycleBin:$SkipRecycleBin

            if ($result.Count -gt 0) {
                Write-Host ""
                Write-Host "Cleanup complete: $($result.Count) movies ($([math]::Round($result.SizeGB, 2)) GB)" -ForegroundColor Green
            }
        }
        else {
            Write-Host ""
            Write-Host "No watched movies found." -ForegroundColor Yellow
        }
    }

    # Interactive mode (standalone - when -CleanupWatched is not set)
    if ($Interactive -and -not $CleanupWatched) {
        Write-Host "Opening interactive selection..." -ForegroundColor Cyan
        $selected = Export-Results -MoviesData $moviesData -Format 'GridView' -Interactive

        if ($selected) {
            $candidates = $moviesData | Where-Object { $selected.Title -contains $_.Title }

            if ($candidates.Count -gt 0) {
                $totalSize = ($candidates | Measure-Object -Property SizeGB -Sum).Sum
                Write-Host ""
                Write-Host "Selected movies: $($candidates.Count) movies ($([math]::Round($totalSize, 2)) GB)" -ForegroundColor Yellow

                $result = Invoke-MovieCleanup -Movies $candidates -MoveToPath $MoveToPath -SkipRecycleBin:$SkipRecycleBin

                if ($result.Count -gt 0) {
                    Write-Host ""
                    Write-Host "Cleanup complete: $($result.Count) movies ($([math]::Round($result.SizeGB, 2)) GB)" -ForegroundColor Green
                }
            }
        }
    }

    # Normal output (no cleanup requested)
    if (-not $cleanupRequested) {
        Export-Results -MoviesData $moviesData -Format $script:State.Config.OutputFormat -Path $OutputPath
    }
}
catch {
    Write-Error "Script failed: $_"
    exit 1
}

#endregion