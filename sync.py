#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests, json, hashlib, time, math, os, re

class Provider:
    def __init__(self, config):
        self.config = config

    def _hash(self, value, hash = 'sha1'):
        m = None
        if hash == 'sha1':
            m = hashlib.sha1()
        elif hash == 'sha224':
            m = hashlib.sha224()
        elif hash == 'sha256':
            m = hashlib.sha256()
        elif hash == 'sha512':
            m = hashlib.sha512()
        elif hash == 'blake2b':
            m = hashlib.blake2b()
        elif hash == 'blake2s':
            m = hashlib.blake2s()

        if not m is None:
            m.update(value.encode('utf-8'))
            return m.hexdigest()
        else:
            raise Exception('hash method {} not supported'.format(hash))

    def get_files():
        raise Exception('get_files to be implemented by concrete class')

    def get_content(filename):
        raise Exception('get_content to be implemented by concrete class')

    def debug():
        print('A concrete will respond with a debug message')

class GithubGistProvider(Provider):
    """
    Provider: Github Gists
    """
    def __init__(self, config):
        super(GithubGistProvider, self).__init__(config)
        # Setup a local backoff for the API calls
        self._backoff = 1
        self._rateLimit = 60
        self._rateLimitRemaining = 60
        self._rateLimitReset = -1

    def _request_github_gists(self, user):
        url = 'https://api.github.com/users/{user}/gists'.format(user=user)
        header = self.config['headers']

        tries = 0
        while tries < 3:
            try:
                resp = requests.get(url, headers=header)
            except Exception as e:
                print(e)
                time.sleep(self._backoff)
                tries += 1
                continue;

            # Successful request, update the rate limit data
            if 'X-RateLimit-Limit' in resp.headers:
                self._rateLimit = int(resp.headers['X-RateLimit-Limit'])
            if 'X-RateLimit-Remaining' in resp.headers:
                self._rateLimitRemaining = int(
                    resp.headers['X-RateLimit-Remaining'])
            if 'X-RateLimit-Reset' in resp.headers:
                self._rateLimitReset = int(resp.headers['X-RateLimit-Reset'])
            if resp.status_code == 404:
                # User does not exist!
                return None
            if resp.status_code == 403:
                # Rate limit exceeded probably
                return None
            files = []
            for gist in resp.json():
                for filename in gist['files']:
                    files.append({
                        'name': filename,
                        'token': gist['files'][filename]['raw_url'],
                        'size':  gist['files'][filename]['size'],
                        'updated': gist['updated_at']
                    })
            return files
        # Tried 3 times and failed
        return None

    def _generate_user(self, rounds = 0):
        secret = self.config['secret']
        previous = secret
        # Setup the initial secret as just applying the hash
        while rounds >= 0:
            previous = self._hash(self.config['templates']['mixing'].format(
                secret=secret,
                previous=previous), self.config['hash'])
            rounds -= 1

        return self.config['templates']['user'].format(
            hash=previous)

    def get_files(self):
        probe, max_probes = 0, self.config['probes']
        while probe < max_probes or max_probes < 0:
            user = self._generate_user(rounds = probe)
            print('[LOG] Trying user {}'.format(user))
            file_list = self._request_github_gists(user)
            if not file_list is None:
                return file_list
            print('[LOG] Acquire failed! Waiting before next request...')
            reset_time = self._rateLimitReset - int(time.time())
            if reset_time < 0:
                reset_time = 1800
            print('[LOG] Remaining: {rem} / {total} (Resets in {time})'.format(
                rem=self._rateLimitRemaining,
                total=self._rateLimit,
                time=reset_time))
            sleep_time = math.ceil(reset_time / self._rateLimitRemaining)
            print('[LOG] Sleeping for {} s...'.format(sleep_time))
            time.sleep(sleep_time)
            probe += 1

        return []

    def get_content(self, token):
        # Just pull the token
        resp = requests.get(token)
        if resp.status_code == 200:
            return resp.content
        raise Exception('content not acquired!')

    def debug(self):
        print('ProbeId\tUser Name')
        for i in range(0, self.config['probes']):
            print('{pindex}\t{name}'.format(pindex=i,
                name=self._generate_user(rounds = i)))

def update_files(target, files, provider):
    # Create the directory if nonexistent
    if not os.path.isdir(target):
        os.mkdir(target)
    # Read the listing file
    listfile = os.path.join(target, '.list')
    old_files = {}
    if os.path.isfile(listfile):
        print('[LOG] Reading existing directory sync list...')
        with open(listfile, 'r') as f:
            for line in f:
                line = line.strip()
                if len(line) == 0:
                    continue
                try:
                    filename, token, size, updated = line.split('\t')
                    old_files[filename] = {
                        'name': filename,
                        'token': token,
                        'size': size,
                        'updated': updated
                    }
                except Exception as e:
                    pass

    # Perform the update if necessary
    with open(listfile, 'w') as f:
        for file in files:
            if (not file['name'] in old_files) or \
                (old_files[file['name']]['token'] != file['token'] and
                old_files[file['name']]['updated'] < file['updated']):
                print('[LOG] Updating {} ...'.format(file['name']))
                # Pull in the file
                try:
                    localpath = os.path.join(target,
                        re.sub(r'[/\\]', '', file['name']))
                    with open(localpath, 'wb') as g:
                        g.write(provider.get_content(file['token']))
                except Exception as e:
                    print(e)
                    # File was not correctly written, so clear do not record
                    continue
            else:
                print('[LOG] Skipping existing {}'.format(file['name']))
            # Write the record on successful download of the file
            f.write('{filename}\t{token}\t{size}\t{updated}\n'.format(
                filename=file['name'],
                token=file['token'],
                size=file['size'],
                updated=file['updated']));
        

def load_provider(provider_config):
    if provider_config['type'] == 'github-gist':
        return GithubGistProvider(provider_config)
    else:
        raise Exception('provider {} not accepted'.format(
            provider_config['type']))

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(
        description='Service to synchronize files against a cloud provider')
    parser.add_argument('config', 
        metavar='config',
        help='Specify a configuration file')
    parser.add_argument('--target', 
        metavar='target',
        help='Specify a directory to sync to. ' + 
            'If unspecified, the current directory will be used.')
    parser.add_argument('--cron', 
        action='store_true',
        help='Indicate that the script is being run as a cron job')
    parser.add_argument('--debug', 
        action='store_true',
        help='Pull debugging information from each provider')
    args = parser.parse_args()
    
    if args.config:
        with open(args.config, 'r') as f:
            try:
                config = json.load(f)
                
            except Exception as e:
                print('Load config file failed! JSON Error.')
                exit(2)
            try:
                providers = [load_provider(p) for p in config['providers']]
            except Exception as e:
                print('Initialize provider failed')
                exit(3)

            if args.debug:
                for provider in providers:
                    provider.debug()
            else:
                target_dir = args.target if args.target else '.'
                if args.cron:
                    print('Cron mode')
                else:
                    print('Updating now!')
                    for provider in providers:
                        files = provider.get_files()
                        update_files(target_dir, files, provider)
    else:
        exit(1)