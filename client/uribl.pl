#!/usr/bin/perl
#
# Queries a HTML file, executable file, an URL, a host, an IP 
# or an e-mail at SPFBL.net's URIBL. http://spfbl.net/en/uribl
#
# This script will follow all URL redirections, until no more redirections. 
# The target is final URL, that will be viewed by user.
#
# Returns:
#    0 - not listed.
#    1 - listed as phishing or as SPAM resource.
#    2 - listed as rejected executable file.
#    3 - malware found at executable file.
#    4 - undefined executable file found.
#
# SPFBL is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# SPFBL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with SPFBL. If not, see <http://www.gnu.org/licenses/>.
#
# Project SPFBL - Copyright Leandro Carlos Rodrigues - leandro@spfbl.net
# https://github.com/leonamp/SPFBL
#
# Version: 3.0

use strict;
use Cwd;
use Cwd qw(abs_path);
use URI;
use URI::Encode qw(uri_decode);
use HTML::TreeBuilder;
use HTML::Entities qw(decode_entities);
use Email::Valid;
use Set::Scalar;
use WWW::Mechanize;
use WWW::Scripter;
use HTTP::Request;
use Data::Validate::URI;
use Data::Validate::IP qw(is_ip is_ipv4 is_ipv6);
use Data::Validate::Domain qw(is_domain);
use Net::IP qw(ip_expand_address ip_reverse);
use Mail::RBL;
use Net::DNS;
use ClamAV::Client;
use Digest::MD5 qw(md5_hex);
use File::Spec;
use File::Slurper qw(read_text write_text read_lines);
use JSON::Parse qw(parse_json);
use Image::ExifTool qw(:Public);
use DateTime;
use MIME::Lite;
use IO::Handle;

my $FINAL = '(/unsubscribe\.php?|(//|\.)facebook\.com/|(//|\.)instagram\.com/|(//|\.)twitter\.com/|(//|\.)linkedin\.com/|(//|\.)strava\.com/|(//|\.)youtube\.com/|(//|\.)myspace\.com/|(//|\.)support\.icewarp\.com/|(//|\.)google-analytics\.com/)'; # REGEX of all URLs that must be considered final. Do not access it!
my $IGNORE = '((//|\.)avg\.com(/|$)|\.avast\.com(/|$)|//tinyurl\.com/nospam\.php?)'; # REGEX of all URLs that must be ignored.
my $NOREDIR = '((//|\.)netflix\.com(/|$)|(//|\.)netflix\.com\.br(/|$))'; # REGEX to demilit redirecions. Do not redirect to it!
my $SHORTENERS = '^https?\:\/\/(1link\.in|1url\.com|2big\.at|2pl\.us|2tu\.us|2ya\.com|4url\.cc|6url\.com|a\.gg|a\.nf|a2a\.me|abbrr\.com|adf\.ly|adjix\.com|alturl\.com|atu\.ca|b23\.ru|bacn\.me|bc\.vc|bit\.do|bit\.ly|bitly\.com|bkite\.com|bloat\.me|budurl\.com|buk\.me|burnurl\.com|buzurl\.com|c-o\.in|chilp\.it|clck\.ru|cli\.gs|clickmeter\.com|cort\.as|cur\.lv|cutt\.us|cuturl\.com|db\.tt|decenturl\.com|dfl8\.me|digbig\.com|digg\.com|doiop\.com|dwarfurl\.com|dy\.fi|easyuri\.com|easyurl\.net|eepurl\.com|esyurl\.com|ewerl\.com|fa\.b|ff\.im|fff\.to|fhurl\.com|filoops\.info|fire\.to|firsturl\.de|flic\.kr|fly2\.ws|fon\.gs|fwd4\.me|gl\.am|go\.9nl\.com|go2\.me|go2cut\.com|goo\.gl|goshrink\.com|gowat\.ch|gri\.ms|gurl\.es|hellotxt\.com|hex\.io|hover\.com|href\.in|htxt\.it|hugeurl\.com|hurl\.it|hurl\.me|hurl\.ws|icanhaz\.com|idek\.net|inreply\.to|is\.gd|iscool\.net|iterasi\.net|ity\.im|j\.mp|jijr\.com|jmp2\.net|just\.as|kissa\.be|kl\.am|klck\.me|korta\.nu|krunchd\.com|liip\.to|liltext\.com|lin\.cr|link\.zip\.net|linkbee\.com|linkbun\.ch|liurl\.cn|ln-s\.net|ln-s\.ru|lnk\.gd|lnk\.in|lnkd\.in|loopt\.us|lru\.jp|lt\.tl|lurl\.no|metamark\.net|migre\.me|minilien\.com|miniurl\.com|minurl\.fr|moourl\.com|myurl\.in|ne1\.net|njx\.me|nn\.nf|notlong\.com|nsfw\.in|o-x\.fr|om\.ly|ow\.ly|pd\.am|pic\.gd|ping\.fm|piurl\.com|pnt\.me|po\.st|poprl\.com|post\.ly|posted\.at|prettylinkpro\.com|profile\.to|q\.gs|qicute\.com|qlnk\.net|qr\.ae|qr\.net|quip-art\.com|rb6\.me|redirx\.com|ri\.ms|rickroll\.it|riz\.gd|rsmonkey\.com|ru\.ly|rubyurl\.com|s7y\.us|safe\.mn|scrnch\.me|sharein\.com|sharetabs\.com|shorl\.com|short\.ie|short\.to|shortlinks\.co\.uk|shortna\.me|shorturl\.com|shoturl\.us|shrinkify\.com|shrinkster\.com|shrt\.st|shrten\.com|shrunkin\.com|shw\.me|simurl\.com|sn\.im|snipr\.com|snipurl\.com|snurl\.com|sp2\.ro|spedr\.com|sqrl\.it|starturl\.com|sturly\.com|su\.pr|t\.co|tcrn\.ch|thrdl\.es|tighturl\.com|tiny\.cc|tiny\.pl|tiny123\.com|tinyarro\.ws|tinyarrows\.com|tinytw\.it|tinyuri\.ca|tinyurl\.com|tinyvid\.io|tnij\.org|to\.ly|togoto\.us|tr\.im|tr\.my|traceurl\.com|turo\.us|tweetburner\.com|tweez\.me|twirl\.at|twit\.ac|twitterpan\.com|twitthis\.com|twiturl\.de|twurl\.cc|twurl\.nl|u\.bb|u\.mavrev\.com|u\.nu|u\.to|u6e\.de|ub0\.cc|updating\.me|ur1\.ca|url\.co\.uk|url\.ie|url4\.eu|urlao\.com|urlbrief\.com|urlcover\.com|urlcut\.com|urlenco\.de|urlhawk\.com|urlkiss\.com|urlot\.com|urlpire\.com|urlx\.ie|urlx\.org|urlzen\.com|v\.gd|virl\.com|vl\.am|vzturl\.com|w3t\.org|wapurl\.co\.uk|wipi\.es|wp\.me|x\.co|x\.se|xaddr\.com|xeeurl\.com|xr\.com|xrl\.in|xrl\.us|xurl\.jp|xzb\.cc|yep\.it|yfrog\.com|yourls\.org|yweb\.com|zi\.ma|zi\.pe|zipmyurl\.com|zz\.gd|back\.ly|ouo\.io)\/'; # List of all know shorteners.

my $USERAGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0';
my $VALIDATOR = Data::Validate::URI->new();
my $CLAMAV = ClamAV::Client->new(socket_name => '/var/run/clamav/clamd.ctl'); # Set the ClamaAV socket.
my $GSBKEY = ''; # Google SafeBrowsing API key.
my $AGRESSIVE = 1; # Will visit all URL contents if 1 or only shorteners if 0.

sub startsWith {
    return substr($_[0], 0, length($_[1])) eq $_[1];
}

# Search HTTP redirection at META tag.
sub redirectionHTML {
    eval {
        my ($tree) = @_;
        for my $meta ($tree->look_down(_tag => 'meta')) {
            my $equiv = lc($meta->attr('http-equiv'));
            if ($equiv eq 'refresh') {
                my $content = $meta->attr('content');
                if ($content =~ m/(https?\:\/\/[A-Za-z0-9\-\._~!\$&\(\)\*+,;=:\/?@]+)/g) {
                    if ($VALIDATOR->is_uri($1)) {
                        if ($1 !~ m/$NOREDIR/g) {
                            return $1;
                        }
                    }
                }
            }
        }
    };
}

# Search JavaScript redirection.
sub redirectionJavascript {
    eval {
        my ($tree, $uri) = @_;
        my $head = $tree->look_down(_tag => q{head});
        for my $script ($head->look_down(_tag => 'script')) {
            my $type = $script->attr('type');
            if ($type eq 'text/javascript') {
                my @content = $script->content_list();
                my $content = @content[0];
                while($content =~ m/\bwindow\.location\.href *= *('|") *(https?\:\/\/[^\s]+[\/\w]) *('|")/gi) {
                    my $newuri = uri_decode($2);
                    if ($VALIDATOR->is_uri($newuri)) {
                        if ($newuri !~ m/$NOREDIR/g) {
                            return $newuri;
                        }
                    }
                }
                if ($content =~ m/\bwindow\.location\.href *= */) {
                    if ($content =~ m/('|") *(https?\:\/\/([a-z0-9\._-]+|\[[a-f0-9\:]+\])(:[0-9]{1,6})?[a-z0-9\-\._~!\$&\(\)\*+,;\=:\/?@#%]*) *('|")/i) {
                        my $newuri = uri_decode($2);
                        if ($newuri !~ m/$NOREDIR/g) {
                            return $newuri;
                        }
                    }
                }
            }
        }
        my $body = $tree->look_down(_tag => q{body});
        for my $script ($tree->look_down(_tag => 'script')) {
            my $type = $script->attr('type');
            if ($type eq 'text/javascript') {
                my @content = $script->content_list();
                my $content = @content[0];
                while($content =~ m/\bdocument\.location *= *('|") *([a-z0-9\-\._~!\$&\(\)\*+,;\=:\/?@]+) *('|")/gi) {
                    my $newuri = repath($uri, uri_decode($2));
                    if ($VALIDATOR->is_uri($newuri)) {
                        if ($newuri !~ m/$NOREDIR/g) {
                            return $newuri;
                        }
                    }
                }
                if ($content =~ m/\bdocument\.location *= */) {
                    if ($content =~ m/('|") *(https?\:\/\/([a-z0-9\._-]+|\[[a-f0-9\:]+\])(:[0-9]{1,6})?[a-z0-9\-\._~!\$&\(\)\*+,;\=:\/?@#%]*) *('|")/i) {
                        my $newuri = uri_decode($2);
                        if ($newuri !~ m/$NOREDIR/g) {
                            return $newuri;
                        }
                    }
                }
            }
        }
        # Looking for a special JavaScript redireciton using iframe.
        for my $iframe ($tree->look_down(_tag => 'iframe')) {
            my $onload = $iframe->attr('onload');
            if ($onload =~ m/^top.location=/) {
                $onload =~ s/\\\//\//g;
                while($onload =~ m/\btop\.location *= *' *(https?\:\/\/[^\s]+[\/\w]) *'/g) {
                    if ($VALIDATOR->is_uri($1)) {
                        if ($1 !~ m/$NOREDIR/g) {
                            return $1;
                        }
                    }
                }
            }
        }
        # Looking for a special redirection at body tag that is invoked by JavaScript.
        for my $meta ($tree->look_down(_tag => 'body')) {
            my $redirect = lc($meta->attr('data-redirect'));
            if ($redirect eq 'true') {
                my $location = decode_entities($meta->attr('data-url'));
                if ($location =~ m/(https?\:\/\/[A-Za-z0-9\-\._~!\$&\(\)\*+,;=:\/?@]+)/g) {
                    if ($VALIDATOR->is_uri($1)) {
                        if ($1 !~ m/$NOREDIR/g) {
                            return $1;
                        }
                    }
                }
            }
        }
        return;
    };
}

# Search URL flagged as suspicious by bit.ly within your shortening.
sub redirectionBitly {
    eval {
        my ($tree) = @_;
        for my $link ($tree->look_down(_tag => 'a')) {
            my $id = $link->attr('id');
            if ($id eq 'clickthrough') {
                my $clickthrough = $link->attr('href');
                if ($VALIDATOR->is_uri($clickthrough)) {
                    return $clickthrough;
                }
            }
        }
        return;
    };
}

# Search for any redirection.
sub redirection {
    my ($tree, $uri) = @_;
    my $redir;
    if ($redir = redirectionHTML($tree)) {
        return $redir;
    } elsif ($redir = redirectionJavascript($tree, $uri)) {
        return $redir;
    } elsif (($uri =~ m/https?\:\/\/bit\.ly\//i) && ($redir = redirectionBitly($tree))) {
        return $redir;
    } else {
        return;
    }
}

# Scan file at ClamAV.
sub clamavScan {
    my ($filename) = @_;
    my ($path, $result);
    if (-e $filename) {
        eval {
            ($path, $result) = $CLAMAV->scan_path($filename);
        };
    }
    return $result;
}

# Try to LOG at Exim or STDOUT for exception.
sub logWrite {
    my ($text) = @_;
    eval {
        Exim::log_write($text);
    };
#    if ($@) {
#        print("$text\n");
#    }
}

# Calculate MD5 hex sum of a file.
sub md5sum {
    my ($filename) = @_;
    if (-e $filename) {
        my $digest = Digest::MD5->new;
        open(FILE, "$filename");
        binmode(FILE); 
        $digest->addfile(*FILE);
        close FILE;open
        return $digest->hexdigest();
    }
    return;
}

# Process an executable file.
sub processExecutable {
    my ($filename, $extension, $addressset) = @_;
    logWrite("EXEC $filename");
    # Generate executable signature.
    my $length = -s $filename;
    my $signature = md5sum($filename);
    my $name = "$signature.$length.$extension";
    $addressset->insert($name);
    # Store cache.
    my $folder = "/var/spfbl";
    if (-d $folder) {
        system("cp '$filename' '$folder/$name'");
    }
    # ClamAV scan.
    my $result = clamavScan($filename);
    if ($result) {
        $addressset->insert("MALWARE=$result");
        logWrite("MLWR $result");
    }
    return $name;
}

# Recursive routine to check a file or a folder.
sub checkFile {
    my ($dir, $filename, $content_type, $uriset, $addressset) = @_;
    my $executable;
    if (-l $filename) {
        logWrite("LINK inode/symlink $filename");
    } elsif (-d $filename) {
        logWrite("FILE inode/directory $filename");
        if (substr($filename, -1) ne "/") {
            $filename =~ s/ /\\ /g;
            $filename = "$filename/";
        }
        my @children = glob("$filename*");
        foreach my $child (@children) {
            my $result = checkFile($filename, $child, '', $uriset, $addressset);
            if ($result) {
                $executable = $result;
            }
        }
    } elsif (-e $filename) {
        if ($filename =~ m/\.lnk$/i) {
            $executable = processExecutable($filename, 'lnk', $addressset);
            # Check if the LNK file is calling msiexec.exe to install by URL. 
            my $info = ImageInfo($filename);
            my $target = $info->{TargetFileDOSName};
            if ($target eq 'msiexec.exe') {
                my $arguments = $info->{CommandLineArguments};
                if ($arguments =~ m/\/i +(https?\:\/\/[A-Za-z0-9\-\._~!\$&\(\)\*+,;=:\/?@]+)\b/i) {
                    $uriset->insert(uri_decode($1));
                }
            }
#        } elsif ($filename =~ m/\.ace$/i) {
#            # TODO: decompress ACE files with unace.
        } elsif ($filename =~ m/\.cab$/i) {
            # TODO: decompress CAB files with cabextract.
            logWrite("FILE application/vnd.ms-cab-compressed $filename");
        } elsif ($filename =~ m/\.(com|vbs|vbe|bat|cmd|pif|scr|prf|exe|shs|arj|hta|jar|ace|js|msi|sh)$/i) {
            my $extension = lc($1);
            $executable = processExecutable($filename, $extension, $addressset);
        } else {
            my $type = `file --brief --mime-type "$filename"`;
            $type =~ s/\n//g;
            if ($content_type ne '') {
                if ($type eq 'text/plain') {
                    $type = $content_type;
                } elsif ($type eq 'application/octet-stream') {
                    $type = $content_type;
                }
            }
            if ($type eq 'application/gzip') {
                # MIME exceptions for Gzip compression.
                if ($filename !~ m/\.wmz$/i) {
                    # Compressed Windows Metafile
                    $type = 'application/x-msmetafile';
                } elsif ($filename !~ m/\.emz$/i) {
                    # Compressed Windows Enhanced Metafile
                    $type = 'application/x-msmetafile';
                }
            }
            if ($type eq 'application/x-dosexec') {
                $executable = processExecutable($filename, 'exe', $addressset);
            } elsif ($type eq 'text/x-msdos-batch') {
                $executable = processExecutable($filename, 'cmd', $addressset);
            } elsif ($type eq 'application/x-elf') {
                $executable = processExecutable($filename, 'elf', $addressset);
            } elsif ($type eq 'application/x-sh') {
                $executable = processExecutable($filename, 'sh', $addressset);
            } elsif ($type eq 'application/jar') {
                $executable = processExecutable($filename, 'jar', $addressset);
            } elsif ($type eq 'application/x-msdownload') {
                $executable = processExecutable($filename, 'exe', $addressset);
            } elsif ($type eq 'application/x-ms-installer') {
                $executable = processExecutable($filename, 'msi', $addressset);
            } elsif ($type eq 'application/zip') {
                logWrite("FILE $type $filename");
                my $directory = "$filename.d";
                if (system("unzip -qq -P password '$filename' -d '$directory'") < 3) {
                    my $result = checkFile($directory, $directory, "inode/directory", $uriset, $addressset);
                    if ($result) {
                        $executable = $result;
                    }
                } else {
                    # Encrypted file. Find any executable by filename list.
                    my $list = `unzip -Z -1 '$filename'`;
                    my @lines = split /\n/, $list;
                    foreach my $line (@lines) {
                        if ($line =~ m/\.(com|vbs|vbe|bat|cmd|pif|scr|prf|lnk|exe|shs|arj|hta|jar|ace|js|msi|sh)$/i) {
                            $executable = processExecutable($filename, 'zip', $addressset);
                            last;
                        }
                    }
                }
                system("rm -R '$directory'");
            } elsif ($type eq 'application/gzip') {
                logWrite("FILE $type $filename");
                my $directory = "$filename.d";
                system("mkdir '$directory'");
                system("cp '$filename' '$directory'");
                system("gunzip --quiet --recursive '$directory'");
                my $result = checkFile($directory, $directory, 'inode/directory', $uriset, $addressset);
                if ($result) {
                    $executable = $result;
                }
                system("rm -R '$directory'");
            } elsif ($type eq 'application/x-tar') {
                logWrite("FILE $type $filename");
                my $directory = "$filename.d";
                system("mkdir '$directory'");
                system("tar --extract --file '$filename' --directory '$directory'");
                my $result = checkFile($directory, $directory, 'inode/directory', $uriset, $addressset);
                if ($result) {
                    $executable = $result;
                }
                system("rm -R '$directory'");
            } elsif ($type eq 'application/x-7z-compressed') {
                logWrite("FILE $type $filename");
                my $directory = "$filename.d";
                if (system("7z x -bd -ppassword '$filename' '-o$directory' > /dev/null") < 2) {
                    my $result = checkFile($directory, $directory, 'inode/directory', $uriset, $addressset);
                    if ($result) {
                        $executable = $result;
                    }
                } else {
                    # Encrypted file. Find any executable by filename list.
                    my $list = `7z l -bd '$filename'`;
                    my @lines = split /\n/, $list;
                    foreach my $line (@lines) {
                        if ($line =~ m/^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} .+\.(com|vbs|vbe|bat|cmd|pif|scr|prf|lnk|exe|shs|arj|hta|jar|ace|js|msi|sh)$/i) {
                            $executable = processExecutable($filename, '7z', $addressset);
                            last;
                        }
                    }
                }
                system("rm -R '$directory'");
            } elsif ($type eq 'application/x-rar') {
                logWrite("FILE $type $filename");
                my $directory = "$filename.d";
                system("mkdir '$directory'");
                if (system("unrar x -ppassword -inul '$filename' '$directory'") < 2) {
                    my $result = checkFile($directory, $directory, "inode/directory", $uriset, $addressset);
                    if ($result) {
                        $executable = $result;
                    }
                } else {
                    # Encrypted file. Find any executable by filename list.
                    my $list = `unrar l '$filename'`;
                    my @lines = split /\n/, $list;
                    foreach my $line (@lines) {
                        if ($line =~ m/..[rwx-]{9} +[0-9]+  [0-9]{2}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}  .+\.(com|vbs|vbe|bat|cmd|pif|scr|prf|lnk|exe|shs|arj|hta|jar|ace|js|msi|sh)/i) {
                            $executable = processExecutable($filename, 'rar', $addressset);
                            last;
                        }
                    }
                }
                system("rm -R '$directory'");
            } elsif ($type eq 'application/x-ace-compressed') {
                 # TODO: decompress ACE files with unace.
            } elsif ($type eq 'application/vnd.ms-cab-compressed') {
                 # TODO: decompress CAB files with cabextract.
            }
        }
    }
    return $executable;
}

sub signature {
    eval {
        my ($key) = @_;
        if ($key =~ m/^(https?)\:\/\/([a-z0-9\._-]+|\[[a-f0-9\:]+\])(:([0-9]{1,6}))?(\/|\?|#|$)/i) {
            $key = uri_decode($key);
            my $protocol = lc($1);
            my $host = lc($2);
            my $port = $4;
            if (!$port) {
                if ($protocol eq 'http') {
                    $port = '80';
                } else {
                    $port = '443';
                }
            }
            if (is_ipv4($host)) {
                $host = ip_reverse($host);
                $host = substr($host, 0, -14);
            } elsif ($host =~ /\[([a-f0-9\:]+)\]/ && is_ipv6($1)) {
                $host = ip_reverse($1);
                $host = substr($host, 0, -10);
            }
            my $signature = md5_hex($key);
            return "$signature.$host.$port.$protocol";
        } elsif ($key =~ m/^[0-9a-f]{32}(\.[a-z0-9_-]+)+\.[0-9]+\.https?$/) {
            return $key;
        } elsif ($key =~ m/^[0-9a-f]{32}\.[0-9]+\.(com|vbs|vbe|bat|cmd|pif|scr|prf|lnk|exe|shs|arj|hta|jar|ace|js|msi|sh)$/) {
            return $key;
        } elsif ($key =~ m/^MALWARE=/) {
            return $key;
        }
        return;
    };
}

sub loadCache {
    eval {
        my ($folder, $key, $expiration) = @_;
        if (-d $folder) {
            my $name = signature($key);
            if ($name) {
                my $file = "$folder/$name";
                if (-e $file) {
                    if (!$expiration || -M $file < $expiration) {
                        return read_text($file);
                    }
                }
            }
        }
        return;
    };
}

sub loadLastCache {
    eval {
        my ($folder, $key) = @_;
        my $count = 0;
        my $cache;
        do {
            $cache = loadCache($folder, $key);
            if ($cache eq '200') {
                return $key;
            } elsif ($cache eq '404') {
                return $key;
            } elsif ($cache eq '500') {
                return $key;
            } else {
                $key = $cache;
            }
            $count++;
        } while ($count < 32 && $key =~ m/^(https?\:\/\/)/i);
        return $key;
    };
}

sub linesCache {
    eval {
        my ($folder, $key) = @_;
        if (-d $folder) {
            my $name = signature($key);
            if ($name) {
                my $file = "$folder/$name";
                if (-e $file) {
                    if (-M $file < 1) {
                        return read_lines($file);
                    }
                }
            }
        }
        return;
    };
}

sub storeCache {
    eval {
        my ($folder, $key, $value) = @_;
        if (-d $folder && $value) {
            my $name = signature($key);
            if ($name) {
                my $file = "$folder/$name";
                write_text($file, $value);
                chmod 0664, $file;
            }
        }
    };
}

sub appendCache {
    eval {
        my ($folder, $key, $value) = @_;
        if (-d $folder && $value) {
            my $name = signature($key);
            if ($name) {
                my $file = "$folder/$name";
                open(my $fh, '>>', $file);
                say $fh "$value";
                close $fh;
                chmod 0664, $file;
            }
        }
    };
}

sub repath {
    my ($uri, $location) = @_;
    if ($location =~ m/^mailto:([^?]*)/) {
        return $location;
    } elsif ($location =~ m/^https?\:\/\/([a-z0-9\._-]+|\[[a-f0-9\:]+\])(:[0-9]{1,6})?(\/|\?|#|$)/i) {
        return $location;
    } elsif ($location =~ m/^\/\/([a-z0-9\._-]+|\[[a-f0-9\:]+\])(:[0-9]{1,6})?(\/|\?|#|$)/i) {
        if ($uri =~ m/^(https?)\:\/\/([a-z0-9\._-]+|\[[a-f0-9\:]+\])/gi) {
            return "$1:$location";
        } else {
            return "http:$location";
        }
    } elsif ($uri =~ m/^((https?)\:\/\/([a-z0-9\._-]+|\[[a-f0-9\:]+\])(:[0-9]{1,6})?)\//i) {
        my $root = $1;
        if ($location =~ m/^\.\.\//i) {
            my $index = rindex($uri, "/");
            $uri = substr($uri, 0, $index);
            $location = substr($location, 1);
            return repath($uri, $location);
        } elsif ($location =~ m/^\.\//i) {
            my $index = rindex($uri, "/");
            $uri = substr($uri, 0, $index + 1);
            $location = substr($location, 2);
            return repath($uri, $location);
        } elsif ($location =~ m/^\//i) {
            return "$root$location";
        } else {
            my $index = rindex($uri, "/");
            $uri = substr($uri, 0, $index + 1);
            return "$uri$location";
        }
    } else {
        return $uri;
    }
}

# Process all URIs to respective addresses.
sub processURI {
    my ($uriset, $addressset, $dir, $getall, $suspect) = @_;
    if ($uriset) {
        my $start = DateTime->now();
        my $ua = WWW::Mechanize->new(keep_alive => 0, timeout => 5, autocheck => 0);
#        my $ua = WWW::Scripter->new(keep_alive => 0, timeout => 5, autocheck => 0, show_progress => 0);
#        $ua->use_plugin('JavaScript');
        $ua->agent($USERAGENT);
        $ua->requests_redirectable(['HEAD']);
        my $redircount = 0;
        my $visitedset = new Set::Scalar->new;
        my $errorset = new Set::Scalar->new;
        my $successset = new Set::Scalar->new;
        while ($uriset) {
            my $uri = @$uriset[0];
            $uriset->delete($uri);
            if (!$visitedset->contains($uri)) {
                $visitedset->insert($uri);
                if ($uri !~ m/$FINAL/gi) {
                    my $cache = loadCache('/var/spfbl', $uri, 1);
                    if ($cache eq '200') {
                    	# Do nothing.
                    } elsif ($cache eq '404') {
                        $errorset->insert($uri);
                    	next;
                    } elsif ($cache eq '500') {
                    	# Do nothing.
                    } elsif ($VALIDATOR->is_uri($cache)) {
                    	$uriset->insert(uri_decode($cache));
                    	next;
                    } elsif (Email::Valid->address($cache)) {
                    	$addressset->insert($cache);
                    	next;
                    } elsif ($cache =~ m/^MALWARE=/) {
                        $addressset->insert($cache);
                        next;
                    } elsif ($cache =~ m/^[0-9a-f]{32}\.[0-9]+\.(com|vbs|vbe|bat|cmd|pif|scr|prf|lnk|exe|shs|arj|hta|jar|ace|js|msi|sh)$/) {
                        $addressset->insert($cache);
                        my $filename = "/var/spfbl/$cache";
                        if (-e $filename) {
                            # ClamAV scan.
                            my $result = clamavScan($filename);
                            if ($result) {
                                $addressset->insert("MALWARE=$result");
                                logWrite("MLWR $result");
                            }
                        }
                    } elsif (($getall || $uri =~ m/$SHORTENERS/i) && (DateTime->now - $start)->in_units('seconds') < 30) {
                        my $response = $ua->get($uri);
                        eval {
                            my $location = $ua->uri();
                            if ($uri ne $location) {
                                storeCache('/var/spfbl', $uri, $location);
                                $uri = $location;
                                $visitedset->insert($uri);
                            }
                        };
                        if ($response->code == 200) {
                            my $filename = $response->filename;
                            my $type = $response->header('Content-Type');
                            (my $mime) = $type =~ m/^[a-z]+\/[a-z0-9+.-]+\b/g;
                            
                            if ($mime eq 'text/html') {
                                my $tree = HTML::TreeBuilder->new_from_content($response->decoded_content);
                                my $redir = redirection($tree, $uri);
                                if ($redir =~ m/^https?\:\/\//i) {
                                    if ($redircount++ < 32) {
                                        $uriset->insert(uri_decode($redir));
                                        storeCache('/var/spfbl', $uri, $redir);
                                        next;
                                    }
                                } elsif ($redir =~ m/^MALWARE=/) {
                                    $addressset->insert($redir);
                                    storeCache('/var/spfbl', $uri, $redir);
                                    next;
                                } else {
                                    storeCache('/var/spfbl', $uri, '200');
                                }
                            } elsif ($filename =~ m/\.(com|vbs|vbe|bat|cmd|pif|scr|prf|lnk|exe|shs|arj|hta|jar|ace|msi|sh|zip|gz|tar|rar|7z)$/i) {
                                my $extension = lc($1);
                                my $headers = $response->headers;
                                my $length = $headers->content_length;
                                if ($length < 1048576) {
                                    logWrite("WGET $mime $uri");
                                    eval {
                                        my $folder = $dir."download";
                                        system("mkdir '$folder'");
                                        $filename = "$folder/$filename";
                                        my $name;
                                        if (-e $filename) {
                                            $name = checkFile($folder, $filename, $mime, $uriset, $addressset);
                                        } else {
                                            open FILE, ">", $filename;
                                            binmode FILE;
                                            print FILE $response->decoded_content;
                                            close FILE;
                                            $name = checkFile($folder, $filename, $mime, $uriset, $addressset);
                                            unlink($filename);
                                        }
                                        system("rm -R '$folder'");
                                        storeCache('/var/spfbl', $uri, $name);
                                    };
                                } else {
                                    storeCache('/var/spfbl', $uri, '200');
                                }
                            }
                        } elsif ($response->code == 404) {
                            $errorset->insert($uri);
                            storeCache('/var/spfbl', $uri, '404');
                            next;
                        } elsif ($response->code == 500) {
                            storeCache('/var/spfbl', $uri, '500');
                        } elsif ($response->code == 301 || $response->code == 302) {
                            # This is a redirection URL.
                            my $location = $response->header('Location');
                            $location = repath($uri, $location);
                            if ($location !~ m/$NOREDIR/gi) {
                                if ($location =~ m/^mailto:([^?]*)/) {
                                    my $email = $1;
                                    if ($email =~ m/<(.+)>/) {
                                        $email = $1;
                                    }
                                    $email = lc($email);
                                    if (Email::Valid->address($email)) {
                                        $addressset->insert($email);
                                        storeCache('/var/spfbl', $uri, $email);
                                        next;
                                    } else {
                                        storeCache('/var/spfbl', $uri, '200');
                                    }
                                } elsif ($location =~ m/^https?\:\/\/([a-z0-9\._-]+|\[[a-f0-9\:]+\])(:[0-9]{1,6})?(\/|\?|#|$)/gi) {
                                    if ($redircount++ < 32) {
                                        $uriset->insert(uri_decode($location));
                                        storeCache('/var/spfbl', $uri, $location);
                                        next;
                                    }
                                } else {
                                    storeCache('/var/spfbl', $uri, '200');
                                }
                            } else {
                                storeCache('/var/spfbl', $uri, '200');
                            }
                        }
                    }
                }
                $successset->insert($uri);
            }
        }
        my $processset;
        if ($successset) {
            $processset = $successset;
        } else {
            $processset = $errorset;
        }
        for my $uri ($processset->elements) {
            if ($uri !~ m/$IGNORE/g) {
                if ($uri =~ m/^https?\:\/\/([a-z0-9\._-]+|\[[a-f0-9\:]+\])(:[0-9]{1,6})?(\/|\?|#|$)/i) {
                    my $host = lc($1);
                    if (is_ipv4($host)) {
                        $addressset->insert($host);
                    } elsif ($host =~ /\[([a-f0-9\:]+)\]/ && is_ipv6($1)) {
                        $addressset->insert(lc(ip_expand_address($1, 6)));
                    } elsif (is_domain($host)) {
                        $addressset->insert($host);
                    }
                }
            }
        }
        if ($suspect && $GSBKEY && $visitedset) {
            eval {
                my $entrieset = new Set::Scalar->new;
                for my $uri ($visitedset->elements) {
                    if ($VALIDATOR->is_uri($uri) && $uri !~ m/$SHORTENERS/i) {
                        if ($uri =~ m/^https?\:\/\/(([a-z0-9\_-]+\.)+[a-z0-9\_-]+|\[[a-f0-9\:]+\])(:[0-9]{1,6})?(\/|\?|#|$)/i) {
                            my @threats = linesCache('/var/spfbl/gsb', $uri);
                            if (@threats > 0 && $threats[0] eq '200') {
                                for (my $i=1; $i < @threats; $i++) {
                                    my $threat = $threats[$i];
                                    $addressset->insert("MALWARE=Google.SafeBrowsing.$threat");
                                }
                            } else {
                                $entrieset->insert($uri);
                                storeCache('/var/spfbl/gsb', $uri, "200\n");
                            }
                        }
                    }
                }
                if ($entrieset) {
                    my $request = '{';
                    $request = join("\n", $request, '  "client": {');
                    $request = join("\n", $request, '    "clientId":      "SPFBL",');
                    $request = join("\n", $request, '    "clientVersion": "2.9.0"');
                    $request = join("\n", $request, '  },');
                    $request = join("\n", $request, '  "threatInfo": {');
                    $request = join("\n", $request, '    "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],');
                    $request = join("\n", $request, '    "platformTypes":    ["LINUX", "ANDROID", "OSX", "IOS", "WINDOWS"],');
                    $request = join("\n", $request, '    "threatEntryTypes": ["URL"],');
                    $request = join("\n", $request, '    "threatEntries": [');
                    for my $uri ($entrieset->elements) {
                        $request = join("\n", $request, "      {\"url\": \"$uri\"},");
                    }
                    $request = join("\n", $request, '    ]');
                    $request = join("\n", $request, '  }');
                    $request = join("\n", $request, '}');
                    my $url = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=$GSBKEY";
                    my $response = $ua->post($url, 'Content-Type' => 'application/json', Content => $request);
                    if ($response->code == 200) {
                        foreach my $match (@{parse_json($response->decoded_content)->{'matches'}}) {
                            my $threat = $match->{'threatType'};
                            $addressset->insert("MALWARE=Google.SafeBrowsing.$threat");
                            my $url = $match->{'threat'}->{'url'};
                            appendCache('/var/spfbl/gsb', $url, $threat);
                        }
                    } else {
                        my $code = $response->code;
                        my $content = $response->decoded_content;
                        logWrite("ERROR $code $visitedset");
                        for my $uri ($entrieset->elements) {
                            storeCache('/var/spfbl/gsb', $uri, "$code\n");
                        }
                    }
                }
            };
        }
    }
}

# Exim function to get HREF address list.
sub getListHREF {
    my ($filename, $content_type, $getall, $suspect) = @_;
    if (-e $filename) {
        $filename = abs_path($filename);
        my ($volume,$dir,$file) = File::Spec->splitpath($filename);
        my $uriset = new Set::Scalar->new;
        my $addressset = new Set::Scalar->new;
        my $tree;
        if ($content_type eq 'text/html') {
            $tree = HTML::TreeBuilder->new_from_file($filename);
        } elsif ($content_type eq 'text/plain') {
            $tree = HTML::TreeBuilder->new_from_file($filename);
        } elsif ($content_type eq 'application/pdf') {
            system("pdftohtml -i -noframes '$filename' '$filename.html'");
            if (-e "$filename.html") {
                $tree = HTML::TreeBuilder->new_from_file("$filename.html");
                system("rm '$filename.html'");
            }
        } else {
            checkFile($dir, $filename, $content_type, $uriset, $addressset);
        }
        if ($tree) {
            my $redir = redirection($tree);
            if ($redir =~ m/^https?\:\/\//i) {
                $uriset->insert(uri_decode($redir));
            } elsif ($redir =~ m/^MALWARE=/) {
                $addressset->insert($redir);
            } else {
                for my $element ($tree->look_down(_tag => 'a', href => qr/./)) {
                    my $uri = $element->attr('href');
                    if ($uri =~ m/^mailto:([^?]*)/) {
                        my $email = $1;
                        if ($email =~ m/<(.+)>/) {
                            $email = $1;
                        }
                        if (Email::Valid->address($email)) {
                            $addressset->insert(lc($email));
                        }
                    }
                    elsif ($uri =~ m/^https?\:\/\//i && $VALIDATOR->is_uri($uri)) {
                        $uriset->insert(uri_decode($uri));
                    }
                }
                for my $element ($tree->look_down(_tag => 'area', href => qr/./)) {
                    my $uri = $element->attr('href');
                    if ($uri =~ m/^mailto:([^?]*)/) {
                        my $email = $1;
                        if ($email =~ m/<(.+)>/) {
                            $email = $1;
                        }
                        if (Email::Valid->address($email)) {
                            $addressset->insert(lc($email));
                        }
                    }
                    elsif ($uri =~ m/^https?\:\/\//i && $VALIDATOR->is_uri($uri)) {
                        $uriset->insert(uri_decode($uri));
                    }
                }
            }
            my $text = $tree->look_down(_tag => q{body})->as_HTML();
            $text = decode_entities($text);
            while ($text =~ /\b([0-9a-z_+-][0-9a-z._+-]*@([a-z0-9]|[a-z0-9][a-z0-9_-]{0,61}[a-z0-9])(\.([a-z0-9]|[a-z0-9][a-z0-9_-]{0,61}[a-z0-9]))*\.(com|org|net|int|edu|gov|mil|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bl|bm|bn|bo|bq|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cw|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mf|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|za|zm|zw))\b/gi) {
                my $email = $1;
                if (Email::Valid->address($email)) {
                    $addressset->insert(lc($email));
                }
            }
            while ($text =~ /\b(https?\:\/\/([a-z0-9\._-]+|\[[a-f0-9\:]+\])(:[0-9]{1,6})?[a-z0-9\-\._~!\$&\(\)\*+,;\=:\/?@#]*)\b/gi) {
                my $url = $1;
                if ($VALIDATOR->is_uri($url)) {
                    $uriset->insert(uri_decode($url));
                }
            }
            while ($text =~ /\b(www\.[a-z0-9\._-]+\.(com|org|net|int|edu|gov|mil|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bl|bm|bn|bo|bq|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cw|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mf|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|za|zm|zw)(\/[a-z0-9\-\._~!\$&\(\)\*+,;=:\/?@#]*)?)\b/gi) {
	        my $url = "http://$1";
	        if ($VALIDATOR->is_uri($url)) {
	            $uriset->insert(uri_decode($url));
	        }
            }
            while ($text =~ /\b([a-z0-9\._-]+\.(com|org|net|int|edu|gov|mil|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bl|bm|bn|bo|bq|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cw|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mf|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|za|zm|zw)(\/[a-z0-9\-\._~!\$&\(\)\*+,;=:\/?@#]*))\b/gi) {
	        my $url = "http://$1";
	        if ($VALIDATOR->is_uri($url)) {
	            $uriset->insert(uri_decode($url));
	        }
            }
            for my $uri ($uriset->elements) {
                if ($uri =~ m/$SHORTENERS/i) {
                    my $signature = signature($uri);
                    $addressset->insert($signature);
                }
            }
            if ($getall eq '1' || $getall eq 'true' || $getall eq 'yes') {
                $getall = 1;
            } else {
                $getall = 0;
            }
            if ($suspect eq '1' || $suspect eq 'true' || $suspect eq 'yes') {
                $suspect = 1;
            } else {
                $suspect = 0;
            }
            processURI($uriset, $addressset, $dir, $getall, $suspect);
        }
        my $list = '';
        for my $address ($addressset->elements) {
            if ($list eq '') {
                $list = "$address";
            } else {
                $list = "$list $address";
            }
        }
        if ($list ne '') {
            logWrite("HREF $list");
        }
        return $list;
    } else {
        return '';
    }
}

my $n = $#ARGV + 1;
if ($n == 1){
    main();
}

# Main code for command line.
sub main() {
    my $arg = $ARGV[0];
    if ($arg eq 'porcupine') {
        my $dir = '/var/spfbl/porcupine';
        if (-d $dir) {
            my $uribl = new Mail::RBL('uribl.spfbl.net');
            opendir(DIR, '/var/spfbl');
            while (my $file = readdir(DIR)) {
                if ($file =~ m/^[0-9a-f]{32}((\.[a-z0-9_-]+)+)\.[0-9]+\.https?$/) {
                    my $host1 = substr($1, 1);
                    if ("http://$host1/" =~ m/$SHORTENERS/i) {
                        if (!$uribl->check_rhsbl($file)) {
                            my $cache = loadLastCache('/var/spfbl', $file);
                            if ($cache =~ m/^[0-9a-f]{32}\.[0-9]+\.(com|vbs|vbe|bat|cmd|pif|scr|prf|lnk|exe|shs|arj|hta|jar|ace|js|msi|sh)$/) {
                                my $result = clamavScan("/var/spfbl/$cache");
                                if ($result) {
                                    print("$file\n");
                                } elsif ($uribl->check_rhsbl($cache)) {
                                    print("$file\n");
                                }
                            } elsif ($cache =~ m/^[0-9a-f]{32}((\.[a-z0-9_-]+)+)\.[0-9]+\.https?$/) {
                                my $host2 = substr($1, 1);
                                if ("http://$host2/" =~ m/$SHORTENERS/i) {
                                    print("$file\n");
                                }
                            } elsif ($cache =~ m/^https?\:\/\/([a-z0-9\._-]+|\[[a-f0-9\:]+\])(:[0-9]{1,6})?(\/|\?|#|$)/gi) {
                                my $host2 = substr($1, 1);
                                if (is_domain($host2) && $uribl->check_rhsbl($host2)) {
                                    print("$file\n");
                                }
                            }
                        }
                    }
                } elsif ($file =~ m/^[0-9a-f]{32}\.[0-9]+\.(com|vbs|vbe|bat|cmd|pif|scr|prf|lnk|exe|shs|arj|hta|jar|ace|msi|sh)$/) {
                    my $path = "/var/spfbl/$file";
                    my $result = clamavScan($path);
                    my $listed = $uribl->check_rhsbl($file);
                    if ($result && !$listed) {
                        print("$file\n");
                    } elsif (!$result && $listed) {
                        my $cache = "/var/spfbl/porcupine/$file.zip";
                        next if -e $cache;
                        if (system("zip -qq --junk-paths -P infected '$cache' '$path'") == 0) {
                            my $msg = MIME::Lite->new(
                                From    => 'admin@spfbl.net',
                                To      => 'abuse@base64.com.br',
                                Subject => 'Malware submission',
                                Type    => 'multipart/mixed',
                            );
                            $msg->attach(
                                Type     => 'TEXT',
                                Data     => "New malware inside compressed with 'infected' as password.",
                            );
                            $msg->attach(
                                Type     => 'application/zip',
                                Path     => "$cache",
                                Filename => "$file",
                            );
                            $msg->send;
                            print("$file\n");
                        }
                    }
                }
            }
            closedir(DIR);
        }
        return 0;
    } else {
        
        my ($volume,$dir,$file) = File::Spec->splitpath(abs_path("./temp"));
        my $uriset = new Set::Scalar->new;
        my $addressset = new Set::Scalar->new;

        if (-e $arg) {
            # The argument is a file.
            my $filename = $arg;
            $filename = abs_path($filename);
            ($volume,$dir,$file) = File::Spec->splitpath($filename);
            my $type = `file --brief --mime-type "$filename"`;
            $type =~ s/\n//g;
            my $tree;
            if ($filename =~ m/\.(com|vbs|vbe|bat|cmd|pif|scr|prf|lnk|exe|shs|arj|hta|jar|ace|js|msi|sh|zip|gz|tar|rar|7z)$/i) {
                checkFile($dir, $filename, $type, $uriset, $addressset);
            } elsif ($type eq 'text/html') {
                $tree = HTML::TreeBuilder->new_from_file($filename);
            } elsif ($type eq 'text/plain') {
                $tree = HTML::TreeBuilder->new_from_file($filename);
            } elsif ($type eq 'application/pdf') {
                if (-e "$filename.html") {
                    $tree = HTML::TreeBuilder->new_from_file("$filename.html");
                } else {
                    system("pdftohtml -i -noframes '$filename' '$filename.html'");
                    if (-e "$filename.html") {
                        $tree = HTML::TreeBuilder->new_from_file("$filename.html");
                        system("rm '$filename.html'");
                    }
                }
            } else {
                checkFile($dir, $filename, $type, $uriset, $addressset);
            }
            if ($tree) {
                my $redir = redirection($tree);
                if ($redir =~ m/^https?\:\/\//i) {
                    $uriset->insert(uri_decode($redir));
                } elsif ($redir =~ m/^MALWARE=/) {
                    $addressset->insert($redir);
                } else {
                    for my $element ($tree->look_down(_tag => 'a', href => qr/./)) {
                        my $uri = $element->attr('href');
                        if ($uri =~ m/^mailto:([^?]*)/) {
                            my $email = $1;
                            if ($email =~ m/<(.+)>/) {
                                $email = $1;
                            }
                            if (Email::Valid->address($email)) {
                                $addressset->insert(lc($email));
                            }
                        } elsif ($uri =~ m/^https?\:\/\//i && $VALIDATOR->is_uri($uri)) {
                            $uriset->insert(uri_decode($uri));
                        }
                    }
                    for my $element ($tree->look_down(_tag => 'area', href => qr/./)) {
                        my $uri = $element->attr('href');
                        if ($uri =~ m/^mailto:([^?]*)/) {
                            my $email = $1;
                            if ($email =~ m/<(.+)>/) {
                                $email = $1;
                            }
                            if (Email::Valid->address($email)) {
                                $addressset->insert(lc($email));
                            }
                        } elsif ($uri =~ m/^https?\:\/\//i && $VALIDATOR->is_uri($uri)) {
                            $uriset->insert(uri_decode($uri));
                        }
                    }
                }
                my $text = $tree->look_down(_tag => q{body})->as_HTML();
                $text = decode_entities($text);
                while ($text =~ /\b([0-9a-z_+-][0-9a-z._+-]*@([a-z0-9]|[a-z0-9][a-z0-9_-]{0,61}[a-z0-9])(\.([a-z0-9]|[a-z0-9][a-z0-9_-]{0,61}[a-z0-9]))*\.(com|org|net|int|edu|gov|mil|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bl|bm|bn|bo|bq|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cw|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mf|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|za|zm|zw))\b/gi) {
                    my $email = $1;
                    if (Email::Valid->address($email)) {
                        $addressset->insert(lc($email));
                    }
                }
                while ($text =~ /\b(https?\:\/\/([a-z0-9\._-]+|\[[a-f0-9\:]+\])(:[0-9]{1,6})?[a-z0-9\-\._~!\$&\(\)\*+,;\=:\/?@#]*)\b/gi) {
                    my $url = $1;
                    if ($VALIDATOR->is_uri($url)) {
                        $uriset->insert(uri_decode($url));
                    }
                }
                while ($text =~ /\b(www\.[a-z0-9\._-]+\.(com|org|net|int|edu|gov|mil|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bl|bm|bn|bo|bq|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cw|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mf|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|za|zm|zw)(\/[a-z0-9\-\._~!\$&\(\)\*+,;=:\/?@#]*)?)\b/gi) {
                    my $url = "http://$1";
                    if ($VALIDATOR->is_uri($url)) {
                        $uriset->insert(uri_decode($url));
                    }
                }
                while ($text =~ /\b([a-z0-9\._-]+\.(com|org|net|int|edu|gov|mil|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bl|bm|bn|bo|bq|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cw|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mf|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|za|zm|zw)(\/[a-z0-9\-\._~!\$&\(\)\*+,;=:\/?@#]*))\b/gi) {
                    my $url = "http://$1";
                    if ($VALIDATOR->is_uri($url)) {
                        $uriset->insert(uri_decode($url));
                    }
                }
            }
        } elsif ($VALIDATOR->is_uri($arg)) {
            # The argument is an URI.
            $uriset->insert(uri_decode($arg));
            my $signature = signature($arg);
            print("$signature $arg\n");
        } elsif (is_domain($arg)) {
            # The argument is a hostname.
            $addressset->insert(lc($arg));
        } elsif (is_ipv4($arg)) {
            # The argument is an IPv4.
            $addressset->insert($arg);
        } elsif (is_ipv6($arg)) {
            # The argument is an IPv6.
            $addressset->insert(lc(ip_expand_address($arg, 6)));
        } elsif (Email::Valid->address($arg)) {
            # The argument is an e-mail.
            $addressset->insert(lc($arg));
        } else {
            print("Invalid query.\n");
            exit 0;
        }
        
        my $list = new Mail::RBL('uribl.spfbl.net');
        
        for my $uri ($uriset->elements) {
            my $signature = signature($uri);
            if ($list->check_rhsbl($signature)) {
                print("The URL signature $signature is listed in 'uribl.spfbl.net'.\n");
                exit 1;
            }
        }
        
        processURI($uriset, $addressset, $dir, $AGRESSIVE, 1);
        
        for my $address ($addressset->elements) {
            if ($address =~ m/^MALWARE=(.*)$/) {
                $addressset->delete($address);
                my $malware = $1;
                print("$malware malware was found in file.\n");
                exit 3;
            }
        }
    
        my $executable = "";
    
        for my $address ($addressset->elements) {
            if ($address =~ m/^[0-9a-f]{32}\.[0-9]+\.(com|vbs|vbe|bat|cmd|pif|scr|prf|lnk|exe|shs|arj|hta|jar|ace|js|msi|sh)$/) {
                eval {
                    $addressset->delete($address);
                    $executable = $address;
                    if ($list->check_rhsbl($address)) {
                        print("The executable with signature $address is listed in 'uribl.spfbl.net'.\n");
                        exit 2;
                    }
                };
            }
        }
        
    
        for my $address ($addressset->elements) {
            if (is_ip($address)) {
                eval {
                    if ($list->check($address)) {
                        print("$address is listed in 'uribl.spfbl.net'.\n");
                        exit 1;
                    }
                };
            } else {
                eval {
                    if ($list->check_rhsbl($address)) {
                        print("$address is listed in 'uribl.spfbl.net'.\n");
                        exit 1;
                    }
                };
            }
        }
    
        my $resolver = new Net::DNS::Resolver();
    
        for my $address ($addressset->elements) {
            if (is_domain($address)) {
                eval {
                    my $query = $resolver->query($address, 'A');
                    if ($query) {
                        foreach my $rr ($query->answer) {
                            my $ip = $rr->address;
                            if (is_ip($ip)) {
                                eval {
                                    if ($list->check($ip)) {
                                        print("$ip is listed in 'uribl.spfbl.net'.\n");
                                        exit 1;
                                    }
                                };
                            }
                        }
                    }
                };
                eval {
                    my $query = $resolver->query($address, 'AAAA');
                    if ($query) {
                        foreach my $rr ($query->answer) {
                            my $ip = $rr->address;
                            if (is_ip($ip)) {
                                eval {
                                    if ($list->check($ip)) {
                                        print("$ip is listed in 'uribl.spfbl.net'.\n");
                                        exit 1;
                                    }
                                };
                            }
                        }
                    }
                };
            }
        }
        if ($executable) {
            print("The undefined executable with signature $executable was found.\n");
            exit 4;
        } elsif ($addressset) {
            print("$addressset is not listed in 'uribl.spfbl.net'.\n");
            exit 0;
        } else {
            print("Not listed in 'uribl.spfbl.net'.\n");
            exit 0;
        }
    }
}
