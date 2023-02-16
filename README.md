# Reddit Scraper
A command line utility developed using Python to scrape media arbitrary subreddits.

# Usage
`python3 ./scraper.py download_dir subreddits.txt ?reddit_password`
* `download_dir` - The destination directory for the media to be saved to.
* `subreddits.txt` - A file containing a list of subreddits to scrape, one subreddit per line.
* `?reddit_password` - For automation sake, you may pass your Reddit password. If not provided, you will be prompted to enter it during run time. THIS IS AN OPTIONAL ARGUMENT, AND NOT RECOMMENDED FOR USE.

When you execute the scraper the first time, you will be prompted for your Reddit username, password, client ID, and client secret.
For later executions, you will only be prompted for your Reddit password, which is used to encrypt other authentication credentials.


# Requirements
To use this scraper, two requirements must be fulfilled: requests and pycryptodome.

You can install these requirements by using:

`python3 -m pip install -r requirements.txt`

For more information on the individual requirements and how to install them manually, see below.

### Requests
`python3 -m pip install requests`

This is required to send the network requests to query the subreddits and download the media.

### PyCryptoDome
`python3 -m pip install pycryptodome`

This is required to securely store credentials so that you only need to enter a password before the web scraping can begin.

### Other
You must create a Reddit app on their website to access your Client ID and Client Secret.

# Are My Credentials Secure?
When running the scraper for the first time, your credentials are automatically encrypted using your Reddit password and stored in a file named `creds`. The credentials (including your username, password, client ID, and client secret) are encrypted using AES-256 in CBC mode with a securely random initialzation vector. In other words, if your Reddit password is secure, then this encrypted file is secure as well.

By using the optional arguement `?reddit_password`, your Reddit password will most likely be stored in plaintext in your systems history. It is for this reason that the use of this option is not recommended.

If you are still worried about storing your credentials in an encrypted format, you may delete the `creds` file after executing the scraper. You will be prompted to enter all credentials the next execution.
