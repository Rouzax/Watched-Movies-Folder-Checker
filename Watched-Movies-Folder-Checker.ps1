# Main script
param (
    [Parameter(Mandatory = $true)]
    [string]$TraktUser,    # Trakt.tv username

    [Parameter(Mandatory = $true)]
    [string]$apiKey,       # API Key for Trakt.tv

    [Parameter(Mandatory = $true)]
    [string]$rootFolder    # Root folder to search for watched movies
)

# Function to retrieve Trakt.tv watched state
function Get-TraktWatchedState {
    <#
    .SYNOPSIS
    Retrieves watched movies from Trakt.tv API.

    .DESCRIPTION
    Retrieves the list of watched movies for a specified Trakt user.

    .PARAMETER apiKey
    Trakt API key required for authentication.

    .PARAMETER TraktUser
    Trakt username for which the watched movies are retrieved.

    .EXAMPLE
    Get-TraktWatchedState -apiKey "YOUR_API_KEY" -TraktUser "username"

    #>

    param (
        [Parameter(Mandatory = $true)]
        [string]$apiKey,
        [Parameter(Mandatory = $true)]
        [string]$TraktUser
    )

    try {
        $traktUrl = "https://api.trakt.tv/users/$TraktUser/watched/movies"
        $response = Invoke-RestMethod -Uri $traktUrl -Headers @{
            "Content-Type"      = "application/json"
            "trakt-api-version" = "2"
            "trakt-api-key"     = $apiKey
        }
        return $response
    }
    catch {
        Write-Error "Failed to retrieve watched movies from Trakt.tv. $_"
        return @()
    }
}

# Function to normalize movie titles by moving the article to the end
function Normalize-MovieTitle {
    <#
    .SYNOPSIS
    Normalizes movie titles by moving articles to the end.

    .DESCRIPTION
    Moves the article (The, An, A) to the end of the movie title.

    .PARAMETER title
    Movie title to be normalized.

    .EXAMPLE
    Normalize-MovieTitle -title "The Dark Knight"
    #>

    param([string]$title)

    $words = $title -split ' '
    if ($words.Count -gt 1 -and ($words[0] -eq "The" -or $words[0] -eq "An" -or $words[0] -eq "A")) {
        $normalizedTitle = "$($words[1..($words.Count - 1)] -join ' '), $($words[0])"
    } else {
        $normalizedTitle = $title
    }
    return $normalizedTitle
}

# Function to sanitize titles for comparison
function Sanitize-Title {
    param([string]$title)
    return -join ($title -replace '[^a-zA-Z0-9]', '').ToLower()
}

# Function to list folders with matching watched movies
function List-FoldersWithWatchedMovies {
    <#
    .SYNOPSIS
    Lists folders containing watched movies.

    .DESCRIPTION
    Compares watched movie titles with folders in the root directory to find matches.

    .PARAMETER rootFolder
    Root folder where movie folders are located.

    .PARAMETER watchedMovies
    Array containing watched movies from Trakt.tv.

    .EXAMPLE
    List-FoldersWithWatchedMovies -rootFolder "C:\Movies" -watchedMovies $watchedMovies
    #>

    param(
        [Parameter(Mandatory = $true)]
        [string]$rootFolder,

        [Parameter(Mandatory = $true)]
        [array]$watchedMovies
    )

    try {
        $folderNames = Get-ChildItem -Path $rootFolder -Directory | Select-Object -ExpandProperty Name

        foreach ($folder in $folderNames) {
            $sanitizedFolder = Sanitize-Title -title $folder

            foreach ($watchedMovie in $watchedMovies) {
                $movieTitle = Normalize-MovieTitle -title $watchedMovie.movie.title
                $movieYear = $watchedMovie.movie.year
                $sanitizedMovieTitle = Sanitize-Title -title "$movieTitle ($movieYear)"

                if ($sanitizedFolder -eq $sanitizedMovieTitle) {
                    Write-Output $folder
                    break
                }
            }
        }
    }
    catch {
        Write-Error "Failed to list folders with watched movies. $_"
    }
}

Write-Output "Folders with matching watched movies:"
$watchedMovies = Get-TraktWatchedState -apiKey $apiKey -TraktUser $TraktUser
List-FoldersWithWatchedMovies -rootFolder $rootFolder -watchedMovies $watchedMovies

Write-Host -NoNewLine 'Press any key to continue...';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
