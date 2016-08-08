#!/usr/bin/perl -w
#
# fetchgmail: A Gmail fetcher that uses the Google Gmail API.  Inspired by fetchmail.
#
# thomaschan@gmail.com
#
$| = 1;

use strict;
use Data::Dumper;
use Google::API::Client;
use Google::API::OAuth2::Client;
use MIME::Base64::URLSafe;
use Config::Simple;
# Reenable later if we patch API for multiple labelIds
#use Text::ParseWords;
use Storable qw(freeze thaw store retrieve);
use Crypt::CBC;
use IO::Prompter;
use Getopt::Long;
use Net::Server::Daemonize qw(daemonize);
use File::Basename;
use File::Monitor;

my $username = $ENV{LOGNAME} || $ENV{USER} || getpwuid($<);
my $groupname = getgrgid($<);
my $homedir = $ENV{HOME};
my $scriptname = 'fetchgmail';

sub usage {
   my $message = $_[0];
   if (defined $message && length $message) {
      $message .= "\n"
         unless $message =~ /\n$/;
   }
   my $command = $0;
   $command =~ s#^.*/##;
   print STDERR (
      $message,
      "Usage: $command [-l] [-f .fetchgmailrc] [-m AGE] [-i ID]\n" .
      "  -l      List labels only\n" .
      "  -f      Path to a .fetchgmailrc file\n" .
      "  -m AGE  Remove seen msgid older than AGE.\n" .
      "          AGE format is [integer][h|d|m|y] (hour|day|month|year), eg 1m\n" .
      "  -i ID   Fetch single message\n" .
      "  --quit  Terminate the running daemon process\n"
   );
   die("\n")
}

my $opt_labels;
my $opt_help;
my $opt_fetchgmailrc;
my $opt_msgidclean;
my $opt_messageid;
my $opt_quit;
Getopt::Long::GetOptions(
    'l' => \$opt_labels,
    'f=s' => \$opt_fetchgmailrc,
    'm=s' => \$opt_msgidclean,
    'i=s' => \$opt_messageid,
    'q|quit' => \$opt_quit,
    'h|help' => \$opt_help,
)
or usage("Invalid commmand line options.");
if ($opt_help) {
    usage("");
}

# Default variables
my $defaultconfig = $ENV{"HOME"} . "/.fetchgmailrc";
my $mdacmd = "cat";
my $clientid = "";
my $clientsecret = "";
my $tokenfile = $ENV{"HOME"} . ".fetchgmail/token.dat";
my $labelslist = "";
my $msgidfile = $ENV{"HOME"} . ".fetchgmail/.fetchgmail.msgid";
my $pidfile = $ENV{"HOME"} . ".fetchgmail/.fetchgmail.pid";
my $logfile = $ENV{"HOME"} . ".fetchgmail/.fetchgmail.log";
my $newer = "all";
my $fetchall = 0;
my $filters = "";
my $daemon = 0;
my $debug = 0;

# Read from config file
my $configfile = $opt_fetchgmailrc || $defaultconfig;
if ( -e $configfile ) {
    readconfig($configfile);
}
else {
    print "WARNING: $configfile does not exist, creating from template.\n";
    print "         Please edit and run again.\n";
    writeconfig($configfile);
    exit;
}

sub readconfig {
    my ($configfile) = @_;
    my $config = new Config::Simple($configfile);
    $mdacmd = $config->param('mda') || $mdacmd;
    $mdacmd =~ s/~/$homedir/g;
    $clientid = $config->param('clientid') || $clientid;
    $clientsecret = $config->param('clientsecret') || $clientsecret;
    $tokenfile = $config->param('token') || $tokenfile;
    $tokenfile =~ s/~/$homedir/g;
    $labelslist = $config->param('labels') || $labelslist;
    $msgidfile = $config->param('msgid') || $msgidfile;
    $msgidfile =~ s/~/$homedir/g;
    $pidfile = $config->param('pidfile') || $pidfile;
    $pidfile =~ s/~/$homedir/g;
    $logfile = $config->param('logfile') || $logfile;
    $logfile =~ s/~/$homedir/g;
    $newer = $config->param('newer') || $newer;
    $fetchall = $config->param('fetchall') || $fetchall;
    $filters = $config->param('filters') || $filters;
    $daemon = $config->param('daemon') || $daemon;
    $debug = $config->param('debug') || $debug;
}

# Monitor config file for changes
my $monitor = File::Monitor->new();
$monitor->watch($configfile);
$monitor->scan;

# Test to clean msgid
if ($opt_msgidclean) {
    if ($opt_msgidclean =~ /^([0-9]+)(h|d|m|y)$/) {
        my $number = $1;
        my $period = $2;
        my $seconds;
        if ($period eq "h") {
            $period = 'hour';
            $seconds = '3600';
        }
        elsif ($period eq "d") {
            $period = 'day';
            $seconds = '86400';
        }
        elsif ($period eq "m") {
            $period = 'month';
            # Assume 30 days
            $seconds = '2592000';
        }
        elsif ($period eq 'y') {
            $period = 'year';
            # Assume 365 days
            $seconds = '31536000';
        }
        my $s = "";
        if ($number > 1) {
            $s = "s";
        }
        my $total_seconds = $number * $seconds;
        my $cleantime = time - $total_seconds;
        print "Removing stored msgid older than $number $period$s.\n";
        msgid_clean($cleantime);
        exit;
    }
    else {
        usage("Invalid value for -m AGE\n\n");
    }
}

# Quit out
if ($opt_quit) {
    my $pid;
    if ( -e $pidfile) {
        open(FH, $pidfile);
        while (<FH>) {  
            $pid = $_;
            chomp $pid;
        }
        close (FH);
        # Not that portable, maybe change this out later
        my $pidname = `ps -hp $pid -o %c`;
        if ($pidname =~ /$scriptname/) {
            print "Killing $pid\n";
            my $kill = kill TERM => -$pid;
            $kill && unlink $pidfile;
        }
        else {
            print "PID $pid does not match name $scriptname, quitting.\n";
        }
    }
    else {
        print "$pidfile does not exist.  Quitting.\n";
    }
    exit;
}

# Initialize connection
my $client = Google::API::Client->new;
my $service = $client->build('gmail', 'v1');

# $service->{auth_doc} will provide all (overreaching) scopes
# We will instead just request the scopes we need.
#my $auth_doc = $service->{auth_doc};
my $auth_doc = {
    oauth2 => {
        scopes => {
            'https://www.googleapis.com/auth/gmail.readonly' => 1,
        }
    }
};

# Set up client secrets
my $auth_driver = Google::API::OAuth2::Client->new(
    {
        auth_uri => 'https://accounts.google.com/o/oauth2/auth',
        token_uri => 'https://accounts.google.com/o/oauth2/token',
        client_id => $clientid,
        client_secret => $clientsecret,
        redirect_uri => "urn:ietf:wg:oauth:2.0:oob",
        auth_doc => $auth_doc,
    }
);

# Set up token
my $encryptedtoken;
# Read in existing encrypted token
if ( -e $tokenfile ) {
    open (FH, $tokenfile);
    while (<FH>) {
        $encryptedtoken= $_;
    }
}
if ($encryptedtoken) {
    # Restore the previous token
    &restoretoken;
}
else {
    # Get a new token
    &gettoken;
}

my $res;

# Get single message (as requested)
if ($opt_messageid) {
    getmessage($opt_messageid);
    exit;
}

# Get msgid cache
my $msgid = {};
readmsgid($fetchall);

sub readmsgid {
    my ($fetchall) = @_;
    if ($fetchall eq "1") {
        # Do full sync + msgid
        if ( -e $msgidfile ) {
            $msgid = retrieve($msgidfile);
        }
        # Clear historyId so no partial sync
        $msgid->{latest} = "";
    }
    elsif ($fetchall eq "2") {
        # Do full sync
        # Don't pull in msgid
    }
    else {
        # Do partial sync + msgid
        if ( -e $msgidfile ) {
            $msgid = retrieve($msgidfile);
        }
    }
}

# Get labels name->id mapping
my %labels;
$res = $service->users->labels->list(
    body => {
        userId => 'me',
    }
)->execute({ auth_driver => $auth_driver });
foreach my $label (@{$res->{labels}}) {
    my $label_id = $label->{id};
    my $label_name = $label->{name};
    $labels{$label_name} = $label_id;
}

if ($opt_labels) {
    print "Current Gmail Labels\n";
    print "====================\n";
    foreach my $label (sort {lc($a) cmp lc($b)} keys %labels) {
        print "\'$label\'\n";
    }
    exit;
}

# Daemonize this program
if ($daemon) {
    daemonize($username,$groupname,$pidfile);
}

# Loop for periodic poll
while (1) {

    # Reread config if the file changed
    my @configchanges = $monitor->scan;
    if (@configchanges) {
        $debug && print "Detected config file change, rereading\n";
        $logfile && logit($logfile,"Detected config file change, rereading");
        readconfig($configfile);
        readmsgid($fetchall);
    }

    my %body;

    # Build array of labelIds
    if ($labelslist) {
        # This does nothing right now as the module doesn't support multiple labelIds parameters
        # Just use a single string for now, and maybe patch Google::API::Client later
        #
        # my @labelids;
        # my @extractedlabels =  quotewords('\s+', 0, $labelslist);
        # foreach my $label (@extractedlabels) {
        #     push @labelids, $labels{$label};
        # }
        # print Dumper @labelids;
        # print @labelids;
        # $body{body}{labelIds} = \@labelids;
        #
        $body{body}{labelIds} = $labels{$labelslist};
    }

    # Get list of messages
    my @messages; 

    # Test to see if we do a partial or full sync
    if ($msgid->{latest}) {
        eval {
            $debug && print "Performing partial sync from id $msgid->{latest}\n";
            $logfile && logit($logfile,"Performing partial sync from id $msgid->{latest}");
            @messages = &partialsync(%body);
        };
        if ($@ =~ /^404/) {
            $debug && print "Partial sync failed, performing full sync\n";
            $logfile && logit($logfile,"Partial sync failed, performing full sync");
            @messages = &fullsync(%body);
        }
    }
    else {
        $debug && print "Performing full sync\n";
        $logfile && logit($logfile,"Performing full sync");
        @messages = &fullsync(%body);
    }

    # Get the messages from the message list
    &getmessages(@messages);

    if ($daemon) {
        sleep $daemon;
    }
    else {
        exit;
    }
}

exit;

# Do partial sync based on history id
sub partialsync {
    my %body = @_;

    my @messages;

    $body{body}{userId} = 'me';

    $body{body}{startHistoryId} = $msgid->{latest};

    # Strip down number of fields to bare minimum
    $body{body}{fields} = 'history(messagesAdded(message(id))),nextPageToken',
    #print Dumper %body;
    $res = $service->users->history->list (
        %body
    )->execute({ auth_driver => $auth_driver });

    foreach my $added (@{$res->{history}}) {
        push @messages, $added->{messagesAdded}->[0]->{message};       
    }
    #debug && print scalar @messages . " messages found\n";

    # Pull next pages of message lists
    while($res->{nextPageToken}) {
        # Not sure why the userId key disappears???
        $body{body}{userId} = 'me';
        $body{body}{pageToken} = $res->{nextPageToken};
        $res = $service->users->history->list (
            %body
        )->execute({ auth_driver => $auth_driver });
        foreach my $added (@{$res->{history}}) {
            push @messages, $added->{messagesAdded}->[0]->{message};
        }
        $debug && print scalar @messages . " messages found\n";
        $logfile && logit($logfile, scalar @messages . " messages found");
    }

    return @messages;
}

# Do full sync based on messages.list
sub fullsync {
    my %body = @_;

    my @messages;

    $body{body}{userId} = 'me';

    # Add query search params
    my $q = "";
    if ($newer ne "all") {
        $q = "newer_than:$newer $q";
    }
    $body{body}{q} = "$filters $q";

    # Strip down number of fields to bare minimum
    $body{body}{fields} = 'messages(id),nextPageToken',

    # Pull list of messages
    $res = $service->users->messages->list (
        %body
    )->execute({ auth_driver => $auth_driver });
    #print Dumper($res);
    if (!$res->{messages}) {
        $debug && print "No results found.\n";
        $logfile && logit($logfile,"No results found.");
        exit;
    }
    @messages = @{$res->{messages}};
    $debug && print scalar @messages . " messages found\n";
    $logfile && logit($logfile,scalar @messages . " messages found");
   
    # Pull next pages of message lists 
    while($res->{nextPageToken}) {
        # Not sure why the userId key disappears???
        $body{body}{userId} = 'me';
        $body{body}{pageToken} = $res->{nextPageToken};
        $res = $service->users->messages->list (
            %body
        )->execute({ auth_driver => $auth_driver });
        push @messages, @{$res->{messages}};
        $debug && print scalar @messages . " messages found\n";
        $logfile && logit($logfile,scalar @messages . " messages found");
    }

    # messages.list is in reverse chronological order
    @messages = reverse @messages;

    return @messages;
}

# Get message
sub getmessages {
    my @messages = @_;
    foreach my $message (@messages) {
        #print Dumper ($message);
        my $message_id = $message->{id};
        #print $message_id . "\n";

        # Test if we have already previously gotten this id
        if ($msgid->{$message_id}) {
            $debug && print "Skipping $message_id\n";
            $logfile && logit($logfile,"Skipping $message_id");
            next;
        }
        else {
            $debug && print "Getting $message_id\n";
            $logfile && logit($logfile,"Getting $message_id");
        }

        eval {
            # Get raw message
            $res = $service->users->messages->get(
                body => {
                    id => $message_id,
                    userId => 'me',
                    format => 'raw',
                    fields => 'historyId,raw,id,labelIds',
                }
            )->execute({ auth_driver => $auth_driver });
        };
        if ($@ =~ /^404/) {
            $debug && print "Skipping $message_id, unable to get.  You may wish to run a full sync later.\n";
            $logfile && logit($logfile,"Skipping $message_id, unable to get.  You may wish to run a full sync later.");
            next;
        }
        # Gather labels
        my $labelscsv = "";
        foreach my $label (sort @{$res->{labelIds}}) {
            $labelscsv = "$labelscsv,$label";
                  
        }
        $labelscsv =~ s/^,//;

        # Test if the label we are looking for is in  the list of labelids.
        # What seems to happen if we do a partial history sync is that we get
        # the spam emails also.
        my %labelidsfound = map {$_ => 1} @{$res->{labelIds}};
        my $labelmatch = "0";
        if ($labelidsfound{$labels{$labelslist}}) {
            $labelmatch = "1";
        }

        # If label doesn't match, then don't get the mail
        if (! $labelmatch) {
            $debug && print "Skipping $message_id, labels don't match the ones we are looking for.\n";
            $logfile && logit($logfile,"Skipping $message_id, labels don't match the ones we are looking for.");
            # Log our skipped message into msgid, and update latest historyId
            $msgid->{$message_id} = time;
            $msgid->{latest} = $res->{historyId};
            store $msgid, $msgidfile;
            next;
        }
        
        # Process raw message
        my $raw = $res->{raw};
        my $decodedmail = urlsafe_b64decode($raw);

#        # Get subject for debugging
#        my @lines = split /\n/, $decodedmail;
#        foreach my $line (@lines) {
#            if ($line =~ /^Subject: (.*)$/) {
#                print "$1\n\n";
#                last;
#            }
#        }

        # Deliver to MDA
        open my $mda, "| $mdacmd" or die;
        # Add headers to mail for debugging
        my @lines = split /\n/, $decodedmail;
        my $headerfound;
        foreach my $line (@lines) {
            if ($headerfound) {
                # We already did the header stuff, just print and go on.
                print $mda "$line\n";
                next;
            }
            if ($line =~ /^Date:/) {
                # Add our headers
                print $mda "X-Google-Id: $message_id\n";
                print $mda "X-Google-HistoryId: $res->{historyId}\n";
                print $mda "x-Google-Labels: $labelscsv\n";
                print $mda "x-Google-Labels-Match: $labelmatch\n";
                print $mda "$line\n";
                $headerfound = 1;
            }
            else {
                print $mda "$line\n";
            }
        }
        #print $mda $decodedmail;
        close $mda;

        # Log that we have delivered the id
        $msgid->{$message_id} = time;
        $msgid->{latest} = $res->{historyId};
        store $msgid, $msgidfile;
    }

}

# Encrypt string
sub encrypt {
    my ($payload,$key) = @_;
    my $cipher = Crypt::CBC->new(
        -key       => $key,
        -keylength => '256',
        -cipher    => "Crypt::OpenSSL::AES"
    );
    my $encrypted = $cipher->encrypt_hex($payload);
    return $encrypted;
}

# Decrypt string
sub decrypt {
    my ($payload,$key) = @_;
    my $cipher = Crypt::CBC->new(
        -key       => $key,
        -keylength => '256',
        -cipher    => "Crypt::OpenSSL::AES"
    );
    my $decrypted = $cipher->decrypt_hex($payload);
    return $decrypted;
}

# Restore token from encrypted string
sub restoretoken {
    my $passphrase = prompt("Enter passphrase for existing token: ", -echo=>'*');
    my $decrypted = decrypt($encryptedtoken,$passphrase) || "";
    if ($decrypted =~ /access_token/) {
        my $token = thaw($decrypted);
        $auth_driver->token_obj($token);
    }
    else {
        my $x = prompt("ERROR:\tUnable to decrypt token with passphrase.\n\tHit ENTER to get a new token or Ctrl-c to exit.\n\n");
        &gettoken;
    }
}

# Get new token and encrypt it
sub gettoken {
    my $url = $auth_driver->authorize_uri;

    print "Go to the following URL to authorize use:\n\n";
    print "  " . $url . "\n\n";

    my $code = prompt("Paste the code from google: ", -echo=>'*');
    print "\n";

    my $token = $auth_driver->exchange($code);
    if (! $token) {
        print "Token exchange rejected, try again.\n";
        exit;
    }

    my $passphrase = 1;
    my $passphrase2 = 2;
    until ($passphrase eq $passphrase2) {
        print "We will now encrypt your code before caching it.\n";
        print "Leave the passphrase blank if you don't want to cache it.\n";
        print "This means that you will need to reauthorize every time.\n";
        print "\n";
        $passphrase = prompt("Enter passphrase (to encrypt your code): ", -echo=>'*');
        if ($passphrase eq "") {
            $passphrase2 = "";
        }
        else {
            $passphrase2 = prompt("Reenter passphrase: ", -echo=>'*');
        }
        print "\n";
    }
    if ($passphrase eq "") {
        print "Code was not saved.\n";
    }
    else {
        my $encrypted = encrypt(freeze($token),$passphrase);
        mkdir_p(dirname($tokenfile));
        open(FH, "> $tokenfile");
        print FH $encrypted;
        close (FH);
    }
}

# Clean msgid before given time
sub msgid_clean {
    my ($cleantime) = @_;

    my $msgid;
    if ( -e $msgidfile ) {
        $msgid = retrieve($msgidfile);
    }
  
    my $precount = keys %{$msgid};
    foreach my $id (sort keys %{$msgid}) {
        if ($id eq "latest") {
            next;
        }
        #print "$id $msgid->{$id} $cleantime\n";
        if ($msgid->{$id} < $cleantime) {
            #print "Deleting $id $msgid->{$id}\n";
            delete $msgid->{$id};
        }
    }
    my $postcount = keys %{$msgid};
    my $deleted = $precount - $postcount;
    print "Deleted $deleted/$precount ids.  $postcount ids remain.\n"; 

    store $msgid, $msgidfile;
}

# mkdir -p equivalent
sub mkdir_p {
    my ($dir) = @_;
    if ( -d $dir) {
        return;
    }
    mkdir_p(dirname($dir));
    mkdir $dir;
}

# Log to file
sub logit {
    my ($logfile,$message) = @_;
    my $date = localtime();
    mkdir_p(dirname($logfile));
    open (LOG, ">> $logfile");
    printf LOG "%s\t%s\n", $date, $message;
    close LOG;
}

# Write default config
sub writeconfig {
    my ($configfile) = @_;
    mkdir_p(dirname($configfile));
    open (CONFIG, "> $configfile");
    print CONFIG <<EOF; 
# What to pipe each mail to
# mda cat
mda /usr/bin/formail -s /usr/bin/procmail -f - -m ~/.procmailrc

# To create a new API client:
# - Go to https://console.developers.google.com/apis
# - Create a project
#   Project name: fetchgmail
# - Credentials -> Create credentials -> OAuth client ID -> Other
# - Dashboard -> ENABLE API -> Gmail API -> ENABLE

# API client ID
# This can be found at https://console.developers.google.com/apis/credentials
# clientid 1234567890ab-1234567890abcdefghijklmnopqrstuv.apps.googleusercontent.com
clientid 1234567890ab-1234567890abcdefghijklmnopqrstuv.apps.googleusercontent.com

# API client secret
# This can be found at https://console.developers.google.com/apis/credentials
#clientsecret 1234-567890abcdefghijklm
clientsecret 1234-567890abcdefghijklm

# Where to save google token
# token ~/.fetchgmail/.fetchgmail.token
token ~/.fetchgmail/.fetchgmail.token

# Message ID cache
# msgid ~/.fetchgmail/.fetchgmail.msgid
msgid ~/.fetchgmail/.fetchgmail.msgid

# Path to pidfile
# pidfile ~/.fetchgmail/.fetchgmail.pid
pidfile ~/.fetchgmail/.fetchgmail.pid

# Path to logfile
# logfile ~/.fetchgmail/.fetchgmail.log
logfile ~/.fetchgmail/.fetchgmail.log

# Fetch all messages whether seen or not (not enabled by default)
# fetchall 0    Do partial sync + msgid
# fetchall 1    Do full sync + msgid
# fetchall 2    Do full sync
fetchall 0

# Fetch all mail newer than date (1h 2d 3m 4y) (Default: all)
# newer all
newer 1d

# Labels to sync from (space delimited, single quote if multiple words)
# Note: multiple (repeated) labelIds do not currently work, so will only take a single entry
#       Maybe try to patch the module later
#labels SPAM '[Mailbox]' INBOX
labels INBOX

# Additional filters.  Use gmail search operators.  Default is none.
# filters subject:hello is:unread

# daemon mode:  Poll every x number of seconds.  Default is 0, which means it only runs once.
# daemon 0

# Print out debug messages.  Default is 0.
# debug 0
EOF
    close CONFIG;
    chmod 0600, $configfile;
}



