# Watched Movies Folder Checker

This script checks which movie folders in your specified root directory have been watched according to your Trakt.tv account.

## Features

- Retrieves watched movies from Trakt.tv.
- Normalizes and compares movie titles to folders in the specified root directory.
- Accounts for minor deviations in folder names (e.g., punctuation, articles, etc.).
- Outputs a list of folders that match watched movies.

## Requirements

- PowerShell 5.0 or higher
- Trakt.tv account and API key

## Installation

1. Clone this repository to your local machine:
    ```sh
    git clone https://github.com/Rouzax/Watched-Movies-Folder-Checker.git
    ```

2. Navigate to the directory:
    ```sh
    cd Watched-Movies-Folder-Checker
    ```

## Usage

Run the script with the following parameters:

- `TraktUser`: Your Trakt.tv username.
- `apiKey`: Your Trakt.tv API key.
- `rootFolder`: The root folder where your movie folders are located.

Example usage:
```sh
.\WatchedMoviesFolderChecker.ps1 -TraktUser "yourusername" -apiKey "yourapikey" -rootFolder "C:\Movies"
```

### Script Parameters

- `TraktUser` (string, mandatory): Your Trakt.tv username.
- `apiKey` (string, mandatory): Your Trakt.tv API key.
- `rootFolder` (string, mandatory): The root folder where movie folders are located.

### Example

```sh
.\WatchedMoviesFolderChecker.ps1 -TraktUser "john_doe" -apiKey "123456789abcdef" -rootFolder "D:\Movies"
```

This will output a list of folders in `D:\Movies` that correspond to the watched movies in your Trakt.tv account.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

- [Trakt.tv API](https://trakt.docs.apiary.io/)
