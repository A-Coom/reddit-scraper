import json
import os
from hashlib import md5, sha256
from sys import stdout, argv
from time import sleep
import requests
import requests.auth

import base64
import getpass
from Crypto import Random
from Crypto.Cipher import AES

# Constants for Reddit routing
TOKEN_ACCESS_ENDPOINT = 'https://www.reddit.com/api/v1/access_token'
OAUTH_ENDPOINT = 'https://oauth.reddit.com'

# Constants for customizing downloads
EXTS = [ 'jpg', 'jpeg', 'png', 'gif', 'mp4' ]
MAXIMUM_POSTS = 99
REPEAT = -1
SLEEP_SECONDS = 3600


"""
Clean a list of extensions to not include a leading dot.
@param exts - Original list of extensions.
@return a list of cleaned extensions.
"""
def clean_exts(exts):
    exts_clean = []
    for ext in exts:
        exts_clean.append(ext.replace('.', ''))
    return exts_clean


"""
Compute the hashes of files with specified extensions using a specified algorithm function.
@param dir - String of directory to process.
@param exts - List of extensions.
@param algo - Function for the hashing algorithm.
@param hashes - An initial list of hashes.
@return a map indexed by hash value storing the file name.
"""
def compute_file_hashes(dir, exts, algo, hashes={}):
    exts_clean = clean_exts(exts)
    for name in os.listdir(dir):
        full_name = os.path.join(dir, name)
        ext = name.split('.')[-1]
        if(os.path.isfile(full_name) and ext in exts_clean):
            with open(full_name, 'rb') as file_in:
                file_bytes = file_in.read()
                file_hash = algo(file_bytes).hexdigest()
                hashes[file_hash] = name
    return hashes


"""
Scrape a list of subreddits for all new media with specified extensions.
@param subs - List of subreddits
@param seen_urls - List of URLs that have already been seen.
@param headers_get - Headers for the GET request.
@param params_get - Parameters for the GET request.
@param exts - List of extensions to match.
@return a list of newly found URLs for the media.
"""
def scrape_subs(subs, seen_urls, headers_get, params_get, exts):
    new_urls = []
    exts_clean = clean_exts(exts)
    for sub in subs:
        response = requests.get(OAUTH_ENDPOINT + '/r/' + sub + '/new', headers=headers_get, params=params_get)
        posts = response.json()['data']['children']
        new_posts = 0
        start_length = len(new_urls)
        for post in posts:
            post_data = post['data']
            if('gallery_data' in post_data):
                post_data = post_data['gallery_data']['items']
                for slide in post_data:
                    slide_data = 'https://i.redd.it/' + slide['media_id'] + '.jpg'
                    if(slide_data not in seen_urls):
                        new_urls.append(slide_data)
                    else:
                        break
                new_posts = new_posts + 1
            else:
                if(post_data['is_video'] == True):
                    post_data = post_data['media']['reddit_video']['fallback_url'][:-16]
                else:
                    post_data = post_data['url']
                ext = post_data.split('.')[-1]
                if(ext in exts_clean):
                    if(post_data not in seen_urls):
                        new_urls.append(post_data)
                    else:
                        break
                    new_posts = new_posts + 1
        stdout.write('[scrape_subs] INFO: Got %d images from %d new posts from r/%s!\n' % ((len(new_urls) - start_length), new_posts, sub))
    return new_urls


"""
Download media from a list of URLs if they have not been seen before.
@param dir - Destination directory for the download.
@param urls - List of URLs to query.
@param hashes - Map of seen hashes, indexed by hash with value for the original media name.
@param algo - Algorithm used by the map of hashes.
@return the new map of hashes.
"""
def download_urls(dir, urls, hashes, algo):
    for url in urls:
        stdout.write('[download_urls] INFO: Media from %s:\t\t' % (url))
        ext = url.split('.')[-1]
        if('DASH_' in url):
            name = url.split('/')[-2] + '.' + ext
        else:
            name = url.split('/')[-1]
        img = requests.get(url).content
        hash = algo(img).hexdigest()
        if(hash not in hashes):
            hashes[hash] = name
            stdout.write('Downloading as %s\n' % (hash + '.' + ext))
            with open(os.path.join(dir, hash + '.' + ext), 'wb') as file_out:
                file_out.write(img)
        else:
            stdout.write('Duplicate image of %s\n' % hashes[hash])
    return hashes


"""
Encrypt a file to contain private information.
@return the username, password, client id, and client secret in a list.
"""
def encrypt_private():
    stdout.write('[encrypt_private] INFO: Credentials file not found.\n')
    username = input('[encrypt_private] Enter Reddit Username: ')
    password = getpass.getpass('[encrypt_private] Enter Reddit Password: ')
    id = input('[encrypt_private] Enter Reddit Client ID: ')
    secret = getpass.getpass('[encrypt_private] Enter Reddit Client Secret: ')
    entries = [username, password, id, secret]
    
    with open('./creds', 'w') as file_out:
        bs = AES.block_size
        key = sha256(password.encode()).digest()
        for data in entries:
            iv = Random.new().read(bs)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            data = data + (bs - len(data) % bs) * chr(bs - len(data) % bs)
            file_out.write(base64.b64encode(iv + cipher.encrypt(data.encode())).decode())
            file_out.write('\n')
    
    return entries


"""
Decrypt the file containing private data.
@return the username, password, client id, and client secret in a list.
"""
def decrypt_private(cmd_password):
    if(not os.path.isfile('./creds')):
        return encrypt_private()
    
    stdout.write('[decrypt_private] INFO: Credentials file found.\n')
    if(cmd_password is not None):
        stdout.write('[decrypt_private] INFO: Password captured from program parameters.\n')
        password = cmd_password
    else:
        password = getpass.getpass('[decrypt_private] Enter Reddit Password: ')
    key = sha256(password.encode()).digest()
    
    entries = []
    try:
        with open('./creds', 'r') as file_in:
            for line in file_in:
                encrypted = base64.b64decode(line)
                iv = encrypted[:AES.block_size]
                cipher = AES.new(key, AES.MODE_CBC, iv)
                decrypted = cipher.decrypt(encrypted[AES.block_size:]).decode()
                decrypted = decrypted[:-ord(decrypted[len(decrypted)-1])]
                entries.append(decrypted)
    except:
        stdout.write('[decrypt_private] INFO: Could not decrypt credentials file.\n')
        stdout.write('[decrypt_private] INFO: If problem persists, delete the creds file and re-enter information.\n')
        return [None, None, None, None]

    return entries


"""
Driver function to scrape a list of subreddits and download all new images.
"""
def main(download_dir, subreddits_file, cmd_password):
    # Initialize the private information.
    username, password, id, secret = decrypt_private(cmd_password)
    if(username is None):
        return
    
    # Initialize the states.
    stdout.write('[main] INFO: Computing hashes of all files with extensions %s in (%s).\n' % (EXTS, download_dir))
    loopCounter = 0;
    allUrls = []
    hashes = compute_file_hashes(download_dir, EXTS, md5)
    
    # Read in the list of subreddits.
    subreddits = []
    with open(subreddits_file) as file_in:
        for line in file_in:
            line = line.rstrip()
            if(len(line) > 0):
                subreddits.append(line)

    # Define the authentication parameters.
    stdout.write('[main] INFO: Fetching authentication from Reddit.\n')
    client_auth = requests.auth.HTTPBasicAuth(id, secret)
    post_data = { 'grant_type': 'password', 'username': username, 'password': password }
    headers = { 'User-Agent': 'Python App' }
    
    # Get the access token
    response = requests.post(TOKEN_ACCESS_ENDPOINT, data=post_data, headers=headers, auth=client_auth)
    if(response.status_code == 200):
        response_json = response.json()
        if('error' not in response_json):
            access_token = response_json['access_token']
        else:
            stdout.write('[main] INFO: Failed to fetch. Error: %s\n' % (response_json['error']))
            return
    else:
        stdout.write('[main] INFO: Could not resolve access token.\n')
        stdout.write('[main] INFO: If problem persists, delete the creds file and re-enter information.\n')
        return
        
    # Define the GET parameters and headers for subreddit requests.
    params_get = { 'limit': MAXIMUM_POSTS }
    headers_get = { 'User-Agent': 'Python App', 'Authorization': 'Bearer ' + access_token }
    
    # Perform the scraping loop
    while(loopCounter < REPEAT or REPEAT == -1):
        # Get all image URLs from posts in the subreddits until reaching a post that been seen before.
        stdout.write('[main] INFO: Scrapping (%d) subreddits for all media URLs.\n' % (len(subreddits)))
        urls = scrape_subs(subreddits, allUrls, headers_get, params_get, EXTS)
        allUrls = allUrls + urls
        
        # Iterate the URLs to download files that are not duplicates.
        before = len(hashes)
        hashes = download_urls(download_dir, urls, hashes, md5)
        stdout.write('[main] INFO: Downloaded a total of %d new images.\n' % (len(hashes) - before))
                    
        # Increment the loop counter and sleep if not the last iteration
        loopCounter = loopCounter + 1;
        if loopCounter < REPEAT or REPEAT == -1:
            stdout.write('[main] INFO: Waiting %d seconds. This is repetition #%d...\n\n' % (SLEEP_SECONDS, loopCounter))
            sleep(SLEEP_SECONDS)


"""
Entrypoint
"""
if __name__ == '__main__':
    stdout.write('\n')
    if(len(argv) < 3):
        stdout.write('USAGE: %s <download_dir> <subreddits.txt> ?reddit_password?\n' % (argv[0]))
    elif(not os.path.isfile(argv[2])):
        stdout.write('Not a file (%s)\n' % (argv[2]))
    else:
        if(len(argv) > 3):
            main(argv[1], argv[2], argv[3])
        else:
            main(argv[1], argv[2], None)
    stdout.write('\n')
