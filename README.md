# JShunter

**JShunter** is a command-line tool designed for scanning code and web resources to detect sensitive information and secrets. This tool specializes in identifying API keys, credentials, tokens, and other sensitive data that could lead to security vulnerabilities, making it an essential resource for developers, security researchers, and bug bounty hunters.

## Features

- **Secrets Detection**: Scans for over 80 different types of sensitive data including API keys, access tokens, private keys, and credentials
- **Multiple Input Methods**: Scan individual files, entire directories, URLs, or lists of URLs
- **Recursive Scanning**: Option to recursively scan directories for a comprehensive analysis
- **Web Resource Support**: Fetch and analyze JavaScript, configuration files, and other resources from web URLs
- **Customizable Options**: Configure threads for concurrent processing, use cookies for authenticated sessions, and set up proxy settings
- **Flexible Output**: Save results to a specified output file for further analysis
- **Filter Support**: Use regular expressions to filter the results

![image](https://github.com/user-attachments/assets/563a36f0-3d68-4870-9f4a-4342aea2fa5f)

## Installation

You can either install using go:

```
go install -v github.com/cc1a2b/jshunter@latest
```

Or download a [binary release](https://github.com/cc1a2b/jshunter/releases) for your platform.

## Usage Examples

### Scan a Local File

```bash
jshunter -f config.js
```

### Scan a Directory

```bash
jshunter -d ./src
```

### Scan a Directory Recursively

```bash
jshunter -d ./project --recursive
```

### Scan a URL

```bash
jshunter -u "https://example.com/javascript.js"
```

### Scan Multiple URLs from a File

```bash
jshunter -l urls.txt
```

### Scan from Stdin

```bash
cat urls.txt | grep "\.js" | jshunter
```

### Save Results to a File

```bash
jshunter -f config.js -o results.txt
```

### Use Proxy

```bash
jshunter -u "https://example.com/config.js" -p 127.0.0.1:8080
```

### Add Authentication Cookies

```bash
jshunter -u "https://example.com/app.js" -c "session=abc123"
```

## Command-Line Options

- `-u, --url <URL>`: Input a URL to scan for secrets
- `-l, --list <file>`: Input a file with URLs (.txt) to scan
- `-f, --file <file>`: Path to any file to scan for secrets
- `-d, --dir <directory>`: Path to directory to scan for secrets
- `--recursive`: Recursively scan directories
- `-o, --output <file>`: Output file path (default: output.txt)
- `-t, --threads <number>`: Number of concurrent threads (default: 5)
- `-c, --cookies <cookies>`: Add cookies for authenticated resources
- `-p, --proxy <host:port>`: Set proxy (host:port)
- `-r, --regex <pattern>`: RegEx for filtering
- `-q, --quiet`: Suppress ASCII art output
- `-h, --help`: Display help message

## License

JShunter is released under MIT license. See [LICENSE](https://github.com/cc1a2b/jshunter/blob/master/LICENSE).

## Support Development

<a href="https://www.buymeacoffee.com/cc1a2b" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="41" width="174"></a>