package main

import (
    "bufio"
    "flag"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "os"
    "path/filepath"
    "regexp"
    "strings"
    "sync"
    "time"
)


var colors = map[string]string{
    "RED":    "\033[0;31m",
    "GREEN":  "\033[0;32m",
    "BLUE":   "\033[0;34m",
    "YELLOW": "\033[0;33m",
    "CYAN":   "\033[0;36m",
    "PURPLE": "\033[0;35m",
    "NC":     "\033[0m",
}

// Define colors for output
var filter = []string{
    "SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED",
    "SECRET_DO_NOT_PASS_THIS_OR_YOU_WILL_BE_FIRED",
    "ReactDOMHydrationRoot.prototype.unstable_scheduleHydration",
    "apiKey)&&!isUndefined",
    // Add more strings or patterns to exclude as needed
}

var (
    //regex patterns
    regexPatterns = map[string]*regexp.Regexp{
    "aws_identity_pool_id": regexp.MustCompile(`(?:aws_cognito_identity_pool_id|identityPoolId|cognitoIdentityPoolId)["']?\s*(?::|=)\s*["']([^"']+)`),
	"aws_user_pool_id":     regexp.MustCompile(`(?:userPoolId|aws_user_pools_id)["']?\s*(?::|=)\s*["']([^"']+)`),
	"aws_client_id":        regexp.MustCompile(`(?:userPoolWebClientId|client-id|clientId)["']?\s*(?::|=)\s*["']([^"']+)`),
	"aws_cognito_region":           regexp.MustCompile(`(?:aws_cognito_region|awsRegion|cognito_region)["']?\s*(?::|=)\s*["']([a-z]{2}-[a-z]+-[0-9])["']`),
	"aws_rum_role":         regexp.MustCompile(`(?:RoleArn=|roleArn"|roleArn=|role-arn)["']?([^"'&\s]{20,})["']?`),    
    "aws_cognito_user_pool_id": regexp.MustCompile(`(us(-gov)?|ap|ca|cn|eu|sa)-(central|(north|south)?(east|west)?)-\d:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`),
    "aws_generic_id": regexp.MustCompile(`(?i)[a-z]{2}-[a-z]+-\d:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
    "aws_rum_role_generic":         regexp.MustCompile(`(arn:(?:aws(?:-[a-z]+)?):iam::\d{12}:role(?:\/[A-Za-z0-9_+=,.@-]+)+)`),
	"google_api":                    regexp.MustCompile(`AIza[0-9A-Za-z-_]{35}`),
	"firebase":                      regexp.MustCompile(`AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`),
	// "google_captcha":                regexp.MustCompile(`6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$`),
	"amazon_aws_access_key_id":      regexp.MustCompile(`A[SK]IA[0-9A-Z]{16}`),
	"amazon_mws_auth_token":         regexp.MustCompile(`amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
	"amazon_aws_url":                regexp.MustCompile(`s3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com`),
	"amazon_aws_url2":               regexp.MustCompile(`([a-zA-Z0-9-._]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9-._]+|s3\.[a-zA-Z0-9-._/]+|s3.amazonaws.com/[a-zA-Z0-9-._]+|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-._]+)`),
	"facebook__access_token":        regexp.MustCompile(`EAACEdEose0cBA[0-9A-Za-z]+`),
	// "authorization_basic":           regexp.MustCompile(`basic [a-zA-Z0-9=:_\+\/-]{5,100}`),
	"authorization_Basic":           regexp.MustCompile(`Basic [a-zA-Z0-9=:_\+\/-]{5,100}`),
	"authorization_bearer":          regexp.MustCompile(`bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}`),
	"authorization_Bearer":          regexp.MustCompile(`Bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}`),
    // Pattern 1: Full connection string with DefaultEndpointsProtocol and EndpointSuffix.
    "azure_blob_storage_key_1": regexp.MustCompile(`DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+;EndpointSuffix=core\.windows\.net`),
    // Pattern 2: Connection string without protocol and endpoint explicit prefix, but containing core.windows.net.
    "azure_blob_storage_key_2": regexp.MustCompile(`AccountName=[^;]+;AccountKey=[^;]+;[^;]*core\.windows\.net`),
    // Pattern 3: A specific pattern matching AccountKey of exactly 88 characters (using allowed Base64 characters).
    "azure_blob_storage_key_3": regexp.MustCompile(`AccountKey=[A-Za-z0-9+/=]{88}`),
    // Pattern 4: A more flexible AccountKey pattern matching between 80 and 100 allowed characters.
    "azure_blob_storage_key_4": regexp.MustCompile(`AccountKey=[A-Za-z0-9+/=]{80,100}`),
        "authorization_api":             regexp.MustCompile(`(?i)\bapi(?:[_\s]*key|[\s]*[\=\:])\s*["']?[a-zA-Z0-9_\-]{5,100}\b`),
	"twilio_api_key":                regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
	//"twilio_account_sid":            regexp.MustCompile(`AC[a-zA-Z0-9_\-]{32}`),
	//"twilio_app_sid":                regexp.MustCompile(`AP[a-zA-Z0-9_\-]{32}`),
	"paypal_braintre_access_token":  regexp.MustCompile(`access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`),
	"square_oauth_secret":           regexp.MustCompile(`sq0csp-[0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}`),
	"square_access_token":           regexp.MustCompile(`sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}`),
	"stripe_standard_api":           regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`),
	"stripe_restricted_api":         regexp.MustCompile(`rk_live_[0-9a-zA-Z]{24}`),
	"authorization_github_token":    regexp.MustCompile(`\bghp_[a-zA-Z0-9]{36}\b`),
	"github_access_token":           regexp.MustCompile(`[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*`),
	"rsa_private_key":               regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
	"ssh_dsa_private_key":           regexp.MustCompile(`-----BEGIN DSA PRIVATE KEY-----`),
	"ssh_dc_private_key":            regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
	"pgp_private_block":             regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
	"ssh_private_key":               regexp.MustCompile(`(?s)-----BEGIN OPENSSH PRIVATE KEY-----[a-zA-Z0-9+\/=\n]+-----END OPENSSH PRIVATE KEY-----`),
	"json_web_token":                regexp.MustCompile(`ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$`),
        "putty_private_key":             regexp.MustCompile(`(?s)PuTTY-User-Key-File-2.*?-----END`),
        "ssh2_encrypted_private_key":    regexp.MustCompile(`(?s)-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----[a-zA-Z0-9+\/=\n]+-----END SSH2 ENCRYPTED PRIVATE KEY-----`),
        "generic_private_key":           regexp.MustCompile(`(?s)-----BEGIN.*PRIVATE KEY-----[a-zA-Z0-9+\/=\n]+-----END.*PRIVATE KEY-----`),
        "username_password_combo":       regexp.MustCompile(`(?i)^[a-z]+:\/\/[^\/]*:[^@]+@`),
        //"facebook_oauth":                regexp.MustCompile(`(?i)[fF][aA][cC][eE][bB][oO][oO][kK].*['\"]?[0-9a-f]{32}['\"]?`),
        //"twitter_oauth":                 regexp.MustCompile(`(?i)[tT][wW][iI][tT][tT][eE][rR].*['\"]?[0-9a-zA-Z]{35,44}['\"]?`),
        //"github_token":                  regexp.MustCompile(`(?i)[gG][iI][tT][hH][uU][bB].*['\"]?[0-9a-zA-Z]{35,40}['\"]?`),
        "google_oauth_client_secret":    regexp.MustCompile(`\"client_secret\":\"[a-zA-Z0-9-_]{24}\"`),
        "aws_api_key":                   regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	"slack_token":                   regexp.MustCompile(`\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"`),
	"SSH_privKey":                   regexp.MustCompile(`([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)`),
	//"Heroku API KEY":                regexp.MustCompile(`(?i)(?:^|[^/])([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:$|[^/])`),
	"slack_webhook_url":             regexp.MustCompile(`https://hooks.slack.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+`),
	"heroku_api_key":                regexp.MustCompile(`[hH]eroku[a-zA-Z0-9]{32}`),
	"dropbox_access_token":          regexp.MustCompile(`(?i)^sl\.[A-Za-z0-9_-]{16,50}$`),
	"salesforce_access_token":       regexp.MustCompile(`00D[0-9A-Za-z]{15,18}![A-Za-z0-9]{40}`),
	"twitter_bearer_token":          regexp.MustCompile(`(?i)^AAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9]{30,45}$`),
	"firebase_url":                  regexp.MustCompile(`https://[a-z0-9-]+\.firebaseio\.com`),
	"pem_private_key":               regexp.MustCompile(`-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----`),
	"google_cloud_sa_key":           regexp.MustCompile(`"type": "service_account"`),
	"stripe_publishable_key":        regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24}`),
	"azure_storage_account_key":     regexp.MustCompile(`(?i)^[A-Za-z0-9]{44}=[A-Za-z0-9+/=]{0,43}$`),
	"instagram_access_token":        regexp.MustCompile(`IGQV[A-Za-z0-9._-]{10,}`),
	"stripe_test_publishable_key":   regexp.MustCompile(`pk_test_[0-9a-zA-Z]{24}`),
	"stripe_test_secret_key":        regexp.MustCompile(`sk_test_[0-9a-zA-Z]{24}`),
	"slack_bot_token":               regexp.MustCompile(`xoxb-[A-Za-z0-9-]{24,34}`),
	"slack_user_token":              regexp.MustCompile(`xoxp-[A-Za-z0-9-]{24,34}`),
        "google_gmail_api_key":          regexp.MustCompile(`AIza[0-9A-Za-z\\-_]{35}`),
        "google_gmail_oauth":            regexp.MustCompile(`\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b`),
        "google_oauth_access_token":     regexp.MustCompile(`ya29\.[0-9A-Za-z\\-_]+`),
        "mailchimp_api_key":             regexp.MustCompile(`[0-9a-f]{32}-us[0-9]{1,2}`),
        "mailgun_api_key":               regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),
        "google_drive_oauth":            regexp.MustCompile(`\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b`),
        "paypal_braintree_access_token": regexp.MustCompile(`access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}`),
        "picatic_api_key":               regexp.MustCompile(`sk_live_[0-9a-z]{32}`),
        "stripe_api_key":                regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`),
        "stripe_restricted_api_key":     regexp.MustCompile(`rk_live_[0-9a-zA-Z]{24}`),
        "square_access__token":          regexp.MustCompile(`sq0atp-[0-9A-Za-z\\-_]{22}`),
        "square_oauth__secret":          regexp.MustCompile(`sq0csp-[0-9A-Za-z\\-_]{43}`),
        // "twitter_access_token":          regexp.MustCompile(`[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}`),
	"heroku_api__key":               regexp.MustCompile(`(?i)[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`),
        "generic_api_key":               regexp.MustCompile(`(?i)["']?[aA][pP][iI]_?[kK][eE][yY]["']?\s*[:=]\s*["']([0-9a-zA-Z]{32,45})["']`),
        "generic_secret":                regexp.MustCompile(`(?i)["']?[sS][eE][cC][rR][eE][tT]_?[kK][eE][yY]?["']?\s*[:=]\s*["']([0-9a-zA-Z]{32,45})["']`),
        // Generic_secret_2: Matches JSON-escaped keys, e.g. \"clientSecret\":\"<value>\"
        "generic_secret_2": regexp.MustCompile(`\\\"(?:[A-Za-z]+)Secret\\\":\\\"([A-Za-z0-9_-]+)\\\"`),

        // Generic_secret_3: Matches keys with normal quotes, e.g. "clientSecret":"<value>"
        "generic_secret_3": regexp.MustCompile(`"(?:[A-Za-z]+)Secret":"([A-Za-z0-9_-]+)"`),

        // Generic_secret_4: Matches keys without a starting quote, e.g. clientSecret:"<value>"
        "generic_secret_4": regexp.MustCompile(`(?:[A-Za-z]+)Secret:"([A-Za-z0-9_-]+)"`),
        "slack_webhook":                 regexp.MustCompile(`https://hooks[.]slack[.]com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`),
        "gcp_service_account":           regexp.MustCompile(`\"type\": \"service_account\"`),
        "password_in_url":               regexp.MustCompile(`[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]`),
	"discord_webhook_url":           regexp.MustCompile(`https://discord(?:app)?\.com/api/webhooks/[0-9]{18,20}/[A-Za-z0-9_-]{64,}`),
	"discord_bot_token":             regexp.MustCompile(`[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}`),
	"okta_api_token":                regexp.MustCompile(`00[a-zA-Z0-9]{30}\.[a-zA-Z0-9\-_]{30,}\.[a-zA-Z0-9\-_]{30,}`),
	"sendgrid_api_key":              regexp.MustCompile(`SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`),
	"mapbox_access_token":           regexp.MustCompile(`pk\.[a-zA-Z0-9]{60}\.[a-zA-Z0-9]{22}`),
	"gitlab_personal_access_token":  regexp.MustCompile(`glpat-[A-Za-z0-9\-]{20}`),
	"datadog_api_key":               regexp.MustCompile(`ddapi_[a-zA-Z0-9]{32}`),
	"shopify_access_token":          regexp.MustCompile(`shpat_[A-Za-z0-9]{32}`),
        "atlassian_access_token":        regexp.MustCompile(`[a-zA-Z0-9]{20,}\.[a-zA-Z0-9_-]{6,}\.[a-zA-Z0-9_-]{25,}`),
	"crowdstrike_api_key":           regexp.MustCompile(`(?i)^[A-Za-z0-9]{32}\.[A-Za-z0-9]{16}$`),
	"quickbooks_api_key":            regexp.MustCompile(`A[0-9a-f]{32}`),
	"cisco_api_key":                 regexp.MustCompile(`cisco[A-Za-z0-9]{30}`),
	"cisco_access_token":            regexp.MustCompile(`access_token=\w+`),
	"segment_write_key":             regexp.MustCompile(`sk_[A-Za-z0-9]{32}`),
	"tiktok_access_token":           regexp.MustCompile(`tiktok_access_token=[a-zA-Z0-9_]+`),
	"slack_client_secret":           regexp.MustCompile(`xoxs-[0-9]{1,9}.[0-9A-Za-z]{1,12}.[0-9A-Za-z]{24,64}`),
    "phone_number":                  regexp.MustCompile(`^\+\d{9,14}$`),
    //"email":                         regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
	"AliCloudAccessKey":		 regexp.MustCompile(`^LTAI[A-Za-z0-9]{12,20}$`),
	"TencentCloudAccessKey":	 regexp.MustCompile(`^AKID[A-Za-z0-9]{13,20}$`),
    }

    asciiArt = `
         ________             __         
     __ / / __/ /  __ _____  / /____ ____
    / // /\ \/ _ \/ // / _ \/ __/ -_) __/
    \___/___/_//_/\_,_/_//_/\__/\__/_/  

     v0.2 SecretHunter            
    `
)

func main() {
    // Define command-line
    var (
        url, list, filePath, dirPath, output, regex, cookies, proxy string
        threads                                                      int
        quiet, help, recursive                                       bool
    )


    flag.StringVar(&url, "u", "", "Input a URL")
    flag.StringVar(&url, "url", "", "Input a URL")
    flag.StringVar(&list, "l", "", "Input a file with URLs (.txt)")
    flag.StringVar(&list, "list", "", "Input a file with URLs (.txt)")
    flag.StringVar(&filePath, "f", "", "Path to any file to scan for secrets")
    flag.StringVar(&filePath, "file", "", "Path to any file to scan for secrets")
    flag.StringVar(&dirPath, "d", "", "Path to directory to scan for secrets")
    flag.StringVar(&dirPath, "dir", "", "Path to directory to scan for secrets")
    flag.BoolVar(&recursive, "recursive", false, "Recursively scan directories")
    flag.StringVar(&output, "o", "output.txt", "Output file path (default: output.txt)")
    flag.StringVar(&output, "output", "output.txt", "Output file path (default: output.txt)")
    flag.StringVar(&regex, "r", "", "RegEx for filtering endpoints")
    flag.StringVar(&regex, "regex", "", "RegEx for filtering endpoints")
    flag.StringVar(&cookies, "c", "", "Cookies for authenticated JS files")
    flag.StringVar(&cookies, "cookies", "", "Cookies for authenticated JS files")
    flag.StringVar(&proxy, "p", "", "Set proxy (host:port)")
    flag.StringVar(&proxy, "proxy", "", "Set proxy (host:port)")
    flag.IntVar(&threads, "t", 5, "Number of concurrent threads")
    flag.IntVar(&threads, "threads", 5, "Number of concurrent threads")
    flag.BoolVar(&quiet, "q", false, "Quiet mode: suppress ASCII art output")
    flag.BoolVar(&quiet, "quiet", false, "Quiet mode: suppress ASCII art output")
    flag.BoolVar(&help, "h", false, "Display help message")
    flag.BoolVar(&help, "help", false, "Display help message")


    flag.Parse()

    if help {
        customHelp()
        return
    }



    if url == "" && list == "" && filePath == "" && dirPath == "" {
        if isInputFromStdin() {
            scanner := bufio.NewScanner(os.Stdin)
            for scanner.Scan() {
                inputURL := scanner.Text()
                
                processInputs(inputURL, list, output, regex, cookies, proxy, threads, quiet)
            }
            if err := scanner.Err(); err != nil {
                fmt.Fprintln(os.Stderr, "Error reading from stdin:", err)
            }
            return
        }
        fmt.Println("Error: Either -u, -l, -f, or -d must be provided.")
        os.Exit(1)
    }


    if !quiet {
        time.Sleep(100 * time.Millisecond)
        fmt.Println(asciiArt)
    }


    if quiet {
        disableColors()
    }

    // Clear the output file if specified
    if output != "" {
        var err error
        outFile, err := os.Create(output)
        if err != nil {
            fmt.Printf("Error creating output file: %v\n", err)
            return
        }
        outFile.Close()
    }


    if filePath != "" {
        processFile(filePath, regex, quiet, output)
    }

    if dirPath != "" {
        processDirectory(dirPath, regex, recursive, output, cookies, proxy, threads, quiet)
    }

    // Only process URL inputs if url or list is actually provided
    if url != "" || list != "" {
        processInputs(url, list, output, regex, cookies, proxy, threads, quiet)
    }
}


func customHelp() {
    fmt.Println(asciiArt)
    fmt.Println("Usage:")
    fmt.Println("  -u, --url URL                 Input a URL")
    fmt.Println("  -l, --list FILE.txt           Input a file with URLs (.txt)")
    fmt.Println("  -f, --file FILE               Path to any file type to scan for secrets")
    fmt.Println("  -d, --dir DIR                 Path to directory to scan for secrets")
    fmt.Println()
    fmt.Println("Options:")
    fmt.Println("  -t, --threads INT             Number of concurrent threads (default: 5)")
    fmt.Println("  -c, --cookies <cookies>       Cookies for authenticated files")
    fmt.Println("  -p, --proxy host:port         Set proxy (host:port), e.g., 127.0.0.1:8080 for Burp Suite")
    fmt.Println("  --recursive                   Recursively scan directories")
    fmt.Println("  -q, --quiet                   Suppress ASCII art output")
    fmt.Println("  -o, --output FILENAME.txt     Output file path (default: output.txt)")
    fmt.Println("  -r, --regex <pattern>         RegEx for filtering endpoints")
    fmt.Println("  -h, --help                    Display this help message")
}

func processStdin(output, regex, cookies, proxy string, threads int) {
    scanner := bufio.NewScanner(os.Stdin)
    for scanner.Scan() {
        line := scanner.Text()
        fmt.Println("Processing line from stdin:", line)

    }
    if err := scanner.Err(); err != nil {
        fmt.Fprintln(os.Stderr, "Error reading from stdin:", err)
    }
}


func isInputFromStdin() bool {
    fi, err := os.Stdin.Stat()
    if err != nil {
        fmt.Println("Error checking stdin:", err)
        return false
    }
    return fi.Mode()&os.ModeCharDevice == 0 // Check if it's not a character device
}

func disableColors() {
    for k := range colors {
        colors[k] = ""
    }
}


func processFile(filePath, regex string, quiet bool, output string) {
    if _, err := os.Stat(filePath); os.IsNotExist(err) {
        fmt.Printf("[%sERROR%s] File not found: %s\n", colors["RED"], colors["NC"], filePath)
    } else if err != nil {
        fmt.Printf("[%sERROR%s] Unable to access file %s: %v\n", colors["RED"], colors["NC"], filePath, err)
    } else {
        if !quiet {
            fmt.Printf("[%sFOUND%s] FILE: %s\n", colors["RED"], colors["NC"], filePath)
        }
        _, sensitiveData := searchForSensitiveData(filePath, regex, "", "", quiet)
        
        // Write any findings to the output file if it exists
        if len(sensitiveData) > 0 && output != "" {
            // Create a local output file
            outFile, err := os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
            if err != nil {
                fmt.Printf("Error opening output file: %v\n", err)
            } else {
                defer outFile.Close()
                fmt.Fprintln(outFile, "\nFILE:", filePath)
                fmt.Fprintln(outFile, strings.Repeat("-", 80))
                
                // Display summary count first
                uniqueMatches := make(map[string]map[string]bool)
                totalMatchCount := 0
                for name, matches := range sensitiveData {
                    if uniqueMatches[name] == nil {
                        uniqueMatches[name] = make(map[string]bool)
                    }
                    for _, match := range matches {
                        if !uniqueMatches[name][match] {
                            totalMatchCount++
                        }
                        uniqueMatches[name][match] = true
                    }
                }
                fmt.Fprintf(outFile, "Found %d unique sensitive data matches across %d categories\n\n", totalMatchCount, len(uniqueMatches))
                
                // Display by category
                for name, matches := range uniqueMatches {
                    fmt.Fprintf(outFile, "\n[%s] Found %d matches\n", name, len(matches))
                    for match := range matches {
                        displayMatch := match
                        if len(displayMatch) > 60 {
                            displayMatch = displayMatch[:57] + "..."
                        }
                        fmt.Fprintf(outFile, "    %s\n", displayMatch)
                    }
                }
            }
        }
    }
}

func processDirectory(dirPath, regex string, recursive bool, output, cookies, proxy string, threads int, quiet bool) {
    var wg sync.WaitGroup
    fileChannel := make(chan string)
    
    var fileWriter *os.File
    if output != "" {
        var err error
        fileWriter, err = os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err != nil {
            fmt.Printf("Error opening output file: %v\n", err)
            return
        }
        defer fileWriter.Close()
    }
    
    // Start worker goroutines
    for i := 0; i < threads; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for file := range fileChannel {
                _, sensitiveData := searchForSensitiveData(file, regex, cookies, proxy, quiet)
                
                if len(sensitiveData) > 0 {
                    if fileWriter != nil {
                        // Use mutex or file locking if needed in the future
                        fmt.Fprintln(fileWriter, "\nFILE:", file)
                        fmt.Fprintln(fileWriter, strings.Repeat("-", 80))
                        // Display summary count first
                        uniqueMatches := make(map[string]map[string]bool)
                        totalMatchCount := 0
                        for name, matches := range sensitiveData {
                            if uniqueMatches[name] == nil {
                                uniqueMatches[name] = make(map[string]bool)
                            }
                            for _, match := range matches {
                                if !uniqueMatches[name][match] {
                                    totalMatchCount++
                                }
                                uniqueMatches[name][match] = true
                            }
                        }
                        fmt.Fprintf(fileWriter, "Found %d unique sensitive data matches across %d categories\n\n", totalMatchCount, len(uniqueMatches))
                        
                        // Display by category
                        for name, matches := range uniqueMatches {
                            fmt.Fprintf(fileWriter, "\n[%s] Found %d matches\n", name, len(matches))
                            for match := range matches {
                                displayMatch := match
                                if len(displayMatch) > 60 {
                                    displayMatch = displayMatch[:57] + "..."
                                }
                                fmt.Fprintf(fileWriter, "    %s\n", displayMatch)
                            }
                        }
                    }
                }
            }
        }()
    }
    
    // Walk the directory tree
    walkFn := func(path string, info os.FileInfo, err error) error {
        if err != nil {
            fmt.Printf("[%sERROR%s] Unable to access path %s: %v\n", colors["RED"], colors["NC"], path, err)
            return nil // Continue walking
        }
        
        // Skip directories if not recursive
        if info.IsDir() {
            if path != dirPath && !recursive {
                return filepath.SkipDir
            }
            return nil
        }
        
        // Skip binary files or other file types you want to exclude
        // You can add more conditions here if needed
        fileChannel <- path
        return nil
    }
    
    if err := filepath.Walk(dirPath, walkFn); err != nil {
        fmt.Printf("[%sERROR%s] Error walking directory %s: %v\n", colors["RED"], colors["NC"], dirPath, err)
    }
    
    close(fileChannel)
    wg.Wait()
}


func processInputs(url, list, output, regex, cookie, proxy string, threads int, quiet bool) {
    var wg sync.WaitGroup
    urlChannel := make(chan string)

    var fileWriter *os.File
    if output != "" {
        var err error
        fileWriter, err = os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err != nil {
            fmt.Printf("Error opening output file: %v\n", err)
            return
        }
        defer fileWriter.Close()
    }

    for i := 0; i < threads; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for u := range urlChannel {
                _, sensitiveData := searchForSensitiveData(u, regex, cookie, proxy, quiet)

                if len(sensitiveData) > 0 {
                    if fileWriter != nil {
                        fmt.Fprintln(fileWriter, "\nURL:", u)
                        fmt.Fprintln(fileWriter, strings.Repeat("-", 80))
                        // Display summary count first
                        uniqueMatches := make(map[string]map[string]bool)
                        totalMatchCount := 0
                        for name, matches := range sensitiveData {
                            if uniqueMatches[name] == nil {
                                uniqueMatches[name] = make(map[string]bool)
                            }
                            for _, match := range matches {
                                if !uniqueMatches[name][match] {
                                    totalMatchCount++
                                }
                                uniqueMatches[name][match] = true
                            }
                        }
                        fmt.Fprintf(fileWriter, "Found %d unique sensitive data matches across %d categories\n\n", totalMatchCount, len(uniqueMatches))
                        
                        // Display by category
                        for name, matches := range uniqueMatches {
                            fmt.Fprintf(fileWriter, "\n[%s] Found %d matches\n", name, len(matches))
                            for match := range matches {
                                displayMatch := match
                                if len(displayMatch) > 60 {
                                    displayMatch = displayMatch[:57] + "..."
                                }
                                fmt.Fprintf(fileWriter, "    %s\n", displayMatch)
                            }
                        }
                    } else if !quiet {
                        fmt.Println("URL:", u)
                        for name, matches := range sensitiveData {
                            for _, match := range matches {
                                fmt.Printf("Sensitive Data [%s]: %s\n", name, match)
                            }
                        }
                    }
                }
            }
        }()
    }

    if err := enqueueURLs(url, list, urlChannel, regex, quiet, output); err != nil {
        fmt.Printf("Error in input processing: %v\n", err)
        close(urlChannel)
        return
    }

    close(urlChannel)
    wg.Wait()
}


func enqueueURLs(url, list string, urlChannel chan<- string, regex string, quiet bool, output string) error {
    if list != "" {
        return enqueueFromFile(list, urlChannel)
    } else if url != "" {
        enqueueSingleURL(url, urlChannel, regex, quiet, output)
    } else {
        enqueueFromStdin(urlChannel)
    }
    return nil
}

func enqueueFromFile(filename string, urlChannel chan<- string) error {
    file, err := os.Open(filename)
    if err != nil {
        return fmt.Errorf("Error opening file: %w", err)
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        urlChannel <- scanner.Text()
    }
    return scanner.Err()
}

func enqueueSingleURL(url string, urlChannel chan<- string, regex string, quiet bool, output string) {
    if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
        urlChannel <- url
    } else {
        processFile(url, regex, quiet, output)
    }
}

func enqueueFromStdin(urlChannel chan<- string) {
    scanner := bufio.NewScanner(os.Stdin)
    for scanner.Scan() {
        urlChannel <- scanner.Text()
    }
    if err := scanner.Err(); err != nil {
        fmt.Printf("Error reading from stdin: %v\n", err)
    }
}


func searchForSensitiveData(urlStr, regex, cookie, proxy string, quiet bool) (string, map[string][]string) {
    var client *http.Client

    if proxy != "" {
        proxyURL, err := url.Parse(proxy)
        if err != nil {
            fmt.Printf("Invalid proxy URL: %v\n", err)
            return urlStr, nil
        }
        client = &http.Client{
            Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
            Timeout: 30 * time.Second,
        }
    } else {
        client = &http.Client{Timeout: 30 * time.Second}
    }

    var sensitiveData map[string][]string

    if strings.HasPrefix(urlStr, "http://") || strings.HasPrefix(urlStr, "https://") {
        req, err := http.NewRequest("GET", urlStr, nil)
        if err != nil {
            fmt.Printf("Failed to create request for URL %s: %v\n", urlStr, err)
            return urlStr, nil
        }

        // Add User-Agent header
        req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:134.0) Gecko/20100101 Firefox/134.0")
    
        if cookie != "" {
            req.Header.Set("Cookie", cookie)
        }

        resp, err := client.Do(req)
        if err != nil {
            fmt.Printf("Failed to fetch URL %s: %v\n", urlStr, err)
            return urlStr, nil
        }
        defer resp.Body.Close()

        body, err := io.ReadAll(resp.Body)
        if err != nil {
            fmt.Printf("Error reading response body: %v\n", err)
            return urlStr, nil
        }

        sensitiveData = reportMatches(urlStr, body, regexPatterns, quiet)
    } else {
        body, err := os.ReadFile(urlStr)
        if err != nil {
            fmt.Printf("Error reading local file %s: %v\n", urlStr, err)
            return urlStr, nil
        }

        sensitiveData = reportMatches(urlStr, body, regexPatterns, quiet)
    }

    return urlStr, sensitiveData
}


func reportMatches(source string, body []byte, regexPatterns map[string]*regexp.Regexp, quiet bool) map[string][]string {
    matchesMap := make(map[string][]string)

    for name, pattern := range regexPatterns {
        if pattern.Match(body) {
            matches := pattern.FindAllString(string(body), -1)
            for _, match := range matches {
				// Exclude matches that are in the filter
				if !isFiltered(match) {
					matchesMap[name] = append(matchesMap[name], match)
				}
			}
        }
    }

    if len(matchesMap) > 0 {
        if !quiet {
            fmt.Printf("[%s FOUND %s] Sensitive data at: %s\n", colors["RED"], colors["NC"], source)
        }
        
        // Create a map to deduplicate matches by type
        uniqueMatches := make(map[string]map[string]bool)
        totalMatchCount := 0
        
        for name, matches := range matchesMap {
            if uniqueMatches[name] == nil {
                uniqueMatches[name] = make(map[string]bool)
            }
            for _, match := range matches {
                if !uniqueMatches[name][match] {
                    totalMatchCount++
                }
                uniqueMatches[name][match] = true
            }
        }
        
        // Display summary count if not in quiet mode
        if !quiet {
            fmt.Printf("Found %d unique sensitive data matches across %d categories\n", totalMatchCount, len(uniqueMatches))
        }
        
        // First display matches with counts if not in quiet mode
        if !quiet {
            for name, matches := range uniqueMatches {
                fmt.Printf("\n[%s%s%s] Found %d matches\n", colors["YELLOW"], name, colors["NC"], len(matches))
                for match := range matches {
                    // Truncate match if too long
                    displayMatch := match
                    if len(displayMatch) > 60 {
                        displayMatch = displayMatch[:57] + "..."
                    }
                    fmt.Printf("    %s\n", displayMatch)
                }
            }
        }
    }
    // Don't print anything for missing/no findings

    return matchesMap
}

// isFiltered checks if a match is part of the filter
func isFiltered(match string) bool {
	for _, exclude := range filter {
		if strings.Contains(match, exclude) {
			return true
		}
	}
	return false
}