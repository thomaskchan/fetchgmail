# fetchgmail
Inspired by fetchmail, this allows you to fetch your mail from Gmail using the Google Gmail API.

## Requirements
- Perl
- module Data::Dumper
- module Google::API::Client
- module Google::API::OAuth2::Client
- module MIME::Base64::URLSafe
- module Config::Simple
- module Storable
- module Crypt::CBC
- module IO::Prompter
- module Getopt::Long
- module Net::Server::Daemonize
- module File::Basename
- module File::Monitor
- module IO::Pager
- ps

## Using fetchgmail

### Create a new Google API client
- Go to https://console.developers.google.com/apis
- Create a project.  Project name: fetchgmail
- Credentials -> Create credentials -> OAuth client ID -> Other
- Dashboard -> ENABLE API -> Gmail API -> ENABLE

### Run it for the first time to generate a config file
    ./fetchgmail.pl

### Edit the config file with your clientid and clientsecret
    vi ~/.fetchmailrc

### Run it again
    ./fetchgmail.pl

## Other fetchgmail options

### Run with a non-default .fetchmailrc
    ./fetchgmail.pl -f /path/to/fetchmailrc

### Quit a running daemon
    ./fetchgmail.pl --quit

### Show status of running daemon
    ./fetchgmail.pl -s

### List all possible Gmail labels
    ./fetchgmail.pl -l

### Remove older message ids (cleanup)
    ./fetchgmail.pl -m AGE  
Remove seen msgid older than AGE.
AGE format is \[integer\]\[h|d|m|y\] (hour|day|month|year), eg 1m

### Fetch single message by ID
    ./fetchgmail.pl -i 1234567890abcdef

### Provide token passphrase on command line (unsafe option)
    ./fetchgmail.pl -p mysuperawesomepassphrase

## Configuration file options

Default configuration file is ~/.fetchgmailrc, but you may specify it as an argument.

fetchgmail will detect config file changes and apply them on the next run.  This does not include clientid nor clientsecret, which will require a full restart.

### mda /usr/bin/formail -s /usr/bin/procmail -f - -m ~/.procmailrc
- What to pipe each mail to

### clientid 1234567890ab-1234567890abcdefghijklmnopqrstuv.apps.googleusercontent.com
- API client ID

### clientsecret 1234-567890abcdefghijklm
- API client secret

### token ~/.fetchgmail/.fetchgmail.token
- Where to save google token

### passwd mysuperawesomepasshrase
- Encrypted token passphrase (It's safer to not enable this option)

### msgid ~/.fetchgmail/.fetchgmail.msgid
- Message ID cache

### pidfile ~/.fetchgmail/.fetchgmail.pid
- Path to pidfile

### logfile ~/.fetchgmail/.fetchgmail.log
- Path to logfile

### fetchall 0
- Fetch all messages whether seen or not (not enabled by default)
- fetchall 0    Do partial sync + msgid
- fetchall 1    Do full sync + msgid
- fetchall 2    Do full sync

### newer 1d
- Fetch all mail newer than date (1h 2d 3m 4y) (Default: all)

### labels INBOX
- Labels to sync from (space delimited, single quote if multiple words)
- Note: multiple (repeated) labelIds do not currently work, so will only take a single entry.  Maybe try to patch the module later.

### filters subject:hello is:unread
- Additional filters.  Use gmail search operators.  Default is none.

### daemon 0
- daemon mode:  Poll every x number of seconds.  Default is 0, which means it only runs once.

