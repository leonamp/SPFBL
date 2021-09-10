#!/usr/bin/perl
#
# An advanced SPF query, like spfquery command, but with two more result codes.
# This script queries the public lists of SPFBL.net, so be careful about query limits.
#
# Usage:
#    spfbl.pl '<ip>' '<helo>' '<sender>' [debug|header <data>]
#
# Parameters:
#    1 - IP address
#    2 - hostname from HELO
#    3 - envelope sender
#    4 - debug mode (optional)
#
# Returns:
#    0 - pass: accept the message because the sender is permitted.
#    1 - fail: reject the message because the sender is not permitted.
#    2 - softfail: accept the message, but flag it as suspect.
#    3 - neutral: accept the message because of neutral result.
#    4 - permerror: reject the message because it is a pemanent error.
#    5 - temperror: defer the message because it is a temporary error.
#    6 - none: accept the message because the sender don't have a SPF record.
#    7 - accept: accept the message because it's a special situation.
#    8 - junk: move the message to junk because it's probably spam.
#    9 - reject: reject the message because it's a special situation.
#    10 - defer: defer the message because it's a special situation.
#
# The output must be included as Received-SPF header. Example:
#
#    Received-SPF: pass (matrix.spfbl.net: domain of postmaster@spfbl.net
#                  designates 54.233.253.229 as permitted sender)
#                  identity=mailfrom; client-ip=54.233.253.229;
#                  envelope-from=postmaster@spfbl.net;
#
# These libraries must be installed before use it:
#
#    sudo cpan -i -f Config::Std Net::IP Net::DNS Mail::SPF URI::Encode
#    sudo cpan -i -f LWP::UserAgent HTTP::Request HTTP::Cookies
#
# For cPanel configuration, run this installation script:
#
#    Install:
#
#       sudo cpan -i -f Config::Std Net::IP Net::DNS Mail::SPF URI::Encode
#       sudo cpan -i -f LWP::UserAgent HTTP::Request HTTP::Cookies JSON::XS
#       cd /usr/local/bin/
#       wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/spfbl.pl
#       sudo chmod +x spfbl.pl
#       cd /usr/local/cpanel/etc/exim/acls/ACL_MAIL_BLOCK
#       wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/custom_end_mail_spfbl
#       service exim restart
#
#    Uninstall:
#
#       rm /usr/local/cpanel/etc/exim/acls/ACL_MAIL_BLOCK/custom_end_mail_spfbl
#       service exim restart
#
#
# For Exim configuration, add this in the acl_check_mail ACL section and restart it:
#
#      warn
#        logwrite = ${run{/usr/local/bin/spfbl.pl '$sender_host_address' \
#                          '$sender_helo_name' '$sender_address'}}
#      deny
#        message = 5.7.1 [SPF] $sender_host_address is not allowed to send mail from \
#                  ${if def:sender_address_domain {$sender_address_domain}{$sender_helo_name}}. \
#                  Please see http://www.openspf.org/Why?scope=${if def:sender_address_domain \
#                  {mfrom}{helo}};identity=${if def:sender_address_domain \
#                  {$sender_address}{$sender_helo_name}};ip=$sender_host_address
#        condition = ${if eq {$runrc}{1}{true}{false}}
#      deny
#        message = 5.7.0 Permanent DNS error while checking SPF record.
#        condition = ${if eq {$runrc}{4}{true}{false}}
#      defer
#        message = 4.5.1 Temporary DNS error while checking SPF record. Try again later.
#        condition = ${if eq {$runrc}{5}{true}{false}}
#      warn
#        condition = ${if eq {$runrc}{8}{true}{false}}
#        add_header = X-Spam-Flag: YES
#      deny
#        message = 5.7.1 Your sender cannot send messages to this recipient.
#        condition = ${if eq {$runrc}{9}{true}{false}}
#      defer
#        message = 4.7.1 Your sender is greylisted.
#        condition = ${if eq {$runrc}{10}{true}{false}}
#      warn
#        add_header = Received-SPF: $value
#
#
# For Postfix configuration, follow this procedure and restart it:
#
#     Add this line in master.cf file:
#
#         policy-spfbl  unix  -       n       n       -       -       spawn user=nobody argv=/usr/local/bin/spfbl.pl
#
#     Add this line in section "smtpd_recipient_restrictions" in main.cf file:
#
#         check_policy_service = unix:private/policy-spfbl
#
#     Keep this line comented at file main.cf:
#
#         # soft_bounce=yes
#
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
# Version: 1.7

use Config::Std;
use Net::IP qw(ip_expand_address ip_reverse);
use Net::DNS;
use Mail::SPF;
use URI::Encode;
use LWP::UserAgent;
use HTTP::Request;
use HTTP::Cookies;
use JSON::XS 'decode_json';

my %config;
my $licence;

my $ip;
my $helo;
my $sender;
my $output;
my $query;

if ($#ARGV == -1) {
    my $params = {};
    while ( my $line = <STDIN> ) {
        chomp $line;
        if ($line =~ /=/) {
            my ($key, $value) = split /=/, $line, 2;
            $params->{$key} = $value;
            next;
        } else {
            last;
        }
    }
    if ($params->{sasl_method} ne '') {
        # Authenticated user.
        STDOUT->print("action=DUNNO\n\n");
        STDOUT->flush();
        exit 0;
    }
    $ip = $params->{client_address};
    $helo = $params->{helo_name};
    $sender = $params->{sender};
    $output = 'postfix';
} elsif ($ARGV[3] eq 'debug') {
    $ip = $ARGV[0];
    $helo = $ARGV[1];
    $sender = $ARGV[2];
    $output = 'debug';
} elsif ($ARGV[3] eq 'header') {
    $ip = $ARGV[0];
    $helo = $ARGV[1];
    $sender = $ARGV[2];
    $output = 'header';
    eval {
        read_config '/etc/spfbl.conf' => %config;
        $licence = $config{''}{'licence'};
    };
    if ($licence) {
        my $encoder = URI::Encode->new({encode_reserved => 1});
        my $ip2 = $encoder->encode($ip);
        my $helo2 = $encoder->encode($helo);
        my $sender2 = $encoder->encode($sender);
        $query = "$licence?ip=$ip2&helo=$helo2&sender=$sender2";
        for (my $i = 4; $i < @ARGV; $i++) {
            my $parameter = $ARGV[$i];
            if ($parameter =~ m/^([^=]+)=(.*)$/g) {
                my $key = $1;
                my $value = $encoder->encode($2);
                $query = "$query&$key=$value";
            }
        }
    }
} else {
    $ip = $ARGV[0];
    $helo = $ARGV[1];
    $sender = $ARGV[2];
    $output = 'header';
}

my $resolver = Net::DNS::Resolver->new(
    nameservers => [ '8.8.8.8', '208.67.222.222' ]
);

my $reverse = ip_reverse($ip);
my $hostname = $helo;
my $fqdn;
my $email;
my $domain;
my $result;

# Fix IPv4 ip_reverse function result.
if ($reverse =~ m/^(([0-9]{1,3}\.){1})in-addr\.arpa\.$/i) {
   $reverse = "0.0.0.$reverse";
} elsif ($reverse =~ m/^(([0-9]{1,3}\.){2})in-addr\.arpa\.$/i) {
   $reverse = "0.0.$reverse";
} elsif ($reverse =~ m/^(([0-9]{1,3}\.){3})in-addr\.arpa\.$/i) {
   $reverse = "0.$reverse";
}

if (!$reverse) {
    print("permerror ($ip: invalid IP)");
    exit 4;
} elsif ($reverse =~ m/^(([0-9a-f]\.){32})ip6\.arpa\.$/i) {
    my $expanded = ip_expand_address($ip, 6);
    eval {
        my $packetAAAA = $resolver->query($helo, 'AAAA');
        if ($packetAAAA) {
            foreach my $rrAAAA ($packetAAAA->answer) {
                if ($expanded eq ip_expand_address($rrAAAA->rdstring, 6)) {
                    $fqdn = $helo;
                    break;
                }
            }
        }
    };
    if (!$fqdn) {
        eval {
            my $packetPTR = $resolver->query($reverse, 'PTR');
            if ($packetPTR) {
                foreach my $rrPTR ($packetPTR->answer) {
                    $hostname = $rrPTR->rdstring;
                    $packetAAAA = $resolver->query($hostname, 'AAAA');
                    if ($packetAAAA) {
                        foreach my $rrAAAA ($packetAAAA->answer) {
                            if ($expanded eq ip_expand_address($rrAAAA->rdstring, 6)) {
                                $fqdn = $hostname;
                                break;
                            }
                        }
                    }
                }
            }
         };
    }
    $reverse = $1;
} elsif ($reverse =~ m/^(([0-9]{1,3}\.){4})in-addr\.arpa\.$/i) {
    my $expanded = ip_expand_address($ip, 4);
    eval {
        my $packetA = $resolver->query($helo, 'A');
        if ($packetA) {
            foreach my $rrA ($packetA->answer) {
                if ($expanded eq ip_expand_address($rrA->rdstring, 4)) {
                    $fqdn = $helo;
                    break;
                }
            }
        }
    };
    if (!$fqdn) {
        eval {
            my $packetPTR = $resolver->query($reverse, 'PTR');
            if ($packetPTR) {
                foreach my $rrPTR ($packetPTR->answer) {
                    my $hostname = $rrPTR->rdstring;
                    $packetA = $resolver->query($hostname, 'A');
                    if ($packetA) {
                        foreach my $rrA ($packetA->answer) {
                            if ($expanded eq ip_expand_address($rrA->rdstring, 6)) {
                                $fqdn = $hostname;
                                break;
                            }
                        }
                    }
                }
            }
        };
    }
    $reverse = $1;
} else {
    print("permerror ($reverse: undefined reverse version)");
    exit 4;
}

if ($fqdn =~ m/^((([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]+)\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9]))\.?$/i) {
    $fqdn = lc($1);
}

my $freemail = 0;
my $invalid = 0;
my $bounce = 0;

if (!$sender) {
    $bounce = 1;
} elsif ($sender =~ m/^([a-zA-Z0-9._-]+)((\+|=)[a-zA-Z0-9._\+=-]+)?@((([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]+)\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9]))$/i) {
    $sender = "$1\@$4";
    $domain = lc($4);
    $freemail = freemail($domain);
    if ($freemail) {
        $email = lc($1) . '\\@' . $domain;
    } else {
        $email = '\\@' . $domain;
    }
} else {
    $invalid = 1;
}

my $qualifier;
my $explanation;
if ($sender) {
    eval {
        my $spf = Mail::SPF::Server->new();
        my $request = Mail::SPF::Request->new(
            versions        => [1, 2],
            scope           => 'mfrom',
            identity        => "$sender",
            ip_address      => "$ip",
            helo_identity   => "$helo"
        );
        my $process = $spf->process($request);
        $qualifier = $process->code;
        $result = $process->code;
        $explanation = $process->local_explanation;
    } or do {
        $qualifier = 'temperror';
        $result = 'temperror';
        $explanation = "$domain: could not process SPF query";
    };
    if ($result eq 'none' || $result eq 'temperror') {
        eval {
            $resolver->query($domain, 'TXT');
            if ($resolver->errorstring() eq 'NXDOMAIN') {
                $result = 'nxdomain';
            }
        };
    }
} else {
    $qualifier = 'none';
    $result = 'none';
    $explanation = 'bounce message';
}

my $information;
if ($query) {
    $query = "$query&result=$result&fqdn=$fqdn";
    my $ua = LWP::UserAgent->new(
        ssl_opts => { verify_hostname => 1 }
    );
    $ua->timeout(5);
    $ua->cookie_jar(
        HTTP::Cookies->new(
            file => "/var/spfbl/cookie.jar",
            autosave => 1
        )
    );
    my $header = HTTP::Request->new(GET => $query);
    my $request = HTTP::Request->new('GET', $query, $header);
    my $response = $ua->request($request);
    if ($response->is_success){
        my $content = decode_json($response->content);
        $result = $content->{'result'};
        $information = $content->{'information'};
    } elsif ($response->code eq 429) {
        # Expired licence.
        removeLicence();
        $query = '';
    } elsif ($response->code eq 500 && $response->as_string =~ m/Connection refused/){
        # Query limit reached.
        $query = '';
    } elsif ($response->code eq 500 && $response->as_string =~ m/Connection timed out/){
        # Restarting server.
        $result = 'temperror';
        $information = 'connection timeout';
    } elsif ($response->code eq 500 && $response->as_string =~ m/Can't connect to/){
        # Server busy.
        $result = 'temperror';
        $information = 'connection fail';
    } elsif ($response->code eq 500 && $response->as_string =~ m/read timeout/){
        # Server busy.
        $result = 'temperror';
        $information = 'response timeout';
    } else {
        $result = 'temperror';
        $information = $response->code . ' ' . $response->as_string;
    }
}

if (!$query) {
    my $focused = $freemail && $result eq 'pass';
    my $good = 0;
    my $essential = 0;
    my $transactional = 0;
    my $bulk = 0;
    my $trusted = 0;

    if (!$focused) {
        eval {
            my $packet = $resolver->query($reverse . 'dnswl.spfbl.net', 'A');
            if ($packet) {
                foreach my $rr ($packet->answer) {
                    my $code = $rr->rdstring;
                        if ($code eq '127.0.0.2') {
                        $good = 1;
                    } elsif ($code eq '127.0.0.3') {
                        $essential = 1;
                    } elsif ($code eq '127.0.0.4') {
                        $transactional = 1;
                    } elsif ($code eq '127.0.0.5') {
                        $bulk = 1;
                    } elsif ($code eq '127.0.0.6') {
                        $trusted = 1;
                    }
                }
            }
        };
        if ($fqdn) {
            eval {
                $packet = $resolver->query($fqdn . '.dnswl.spfbl.net', 'A');
                if ($packet) {
                    foreach my $rr ($packet->answer) {
                        my $code = $rr->rdstring;
                        if ($code eq '127.0.0.2') {
                            $good = 1;
                         } elsif ($code eq '127.0.0.3') {
                            $essential = 1;
                        } elsif ($code eq '127.0.0.4') {
                            $transactional = 1;
                        } elsif ($code eq '127.0.0.5') {
                            $bulk = 1;
                        } elsif ($code eq '127.0.0.6') {
                            $trusted = 1;
                        }
                    }
                }
            };
        }
    }
    if (!$good && $result eq 'pass') {
        eval {
            $packet = $resolver->query($email . '.dnswl.spfbl.net', 'A');
            if ($packet) {
                foreach my $rr ($packet->answer) {
                    my $code = $rr->rdstring;
                    if ($code eq '127.0.0.2') {
                        $good = 1;
                    }
                }
            }
        };
    }

    my $bad = 0;
    my $suspicious = 0;
    my $notserver = 0;
    my $residential = 0;
    my $generic = 0;

    if (!$good) {
        if (!$focused) {
            eval {
                my $packet = $resolver->query($reverse . 'dnsbl.spfbl.net', 'A');
                if ($packet) {
                    foreach my $rr ($packet->answer) {
                        my $code = $rr->rdstring;
                        if ($code eq '127.0.0.2') {
                            $bad++;
                        } elsif ($code eq '127.0.0.3') {
                            $suspicious++;
                        } elsif ($code eq '127.0.0.4') {
                            $notserver++;
                        }
                   }
                }
            };
            eval {
                if ($fqdn) {
                    $packet = $resolver->query($fqdn . '.dnsbl.spfbl.net', 'A');
                } else {
                    $packet = $resolver->query($hostname . '.dnsbl.spfbl.net', 'A');
                }
                if ($packet) {
                    foreach my $rr ($packet->answer) {
                        my $code = $rr->rdstring;
                        if ($code eq '127.0.0.2') {
                            $bad++;
                        } elsif ($code eq '127.0.0.3') {
                            $suspicious++;
                        } elsif ($code eq '127.0.0.4') {
                            $residential = 1;
                        }
                    }
                }
            };
        }
        eval {
            $packet = $resolver->query($email . '.dnsbl.spfbl.net', 'A');
            if ($packet) {
                foreach my $rr ($packet->answer) {
                    my $code = $rr->rdstring;
                    if ($code eq '127.0.0.2') {
                        $bad++;
                    } elsif ($code eq '127.0.0.3') {
                        $suspicious++;
                    } elsif ($code eq '127.0.0.4') {
                        $generic = 1;
                    }
                }
            }
        };
    }

    my $score = '';
    if ($bad) {
        eval {
            $packet = $resolver->query($email . '.score.spfbl.net', 'A');
            if ($packet) {
                foreach my $rr ($packet->answer) {
                    my $code = $rr->rdstring;
                    if ($code =~ m/^127\.0\.1\.([0-9]{1,3})$/i) {
                        $score = $1;
                    }
                }
            }
        };
        if ($score eq '') {
            if ($fqdn) {
                eval {
                    $packet = $resolver->query($fqdn . '.score.spfbl.net', 'A');
                    if ($packet) {
                        foreach my $rr ($packet->answer) {
                            my $code = $rr->rdstring;
                            if ($code =~ m/^127\.0\.1\.([0-9]{1,3})$/i) {
                                $score = $1;
                            }
                        }
                    }
                };
            }
            if ($score eq '') {
                eval {
                    my $packet = $resolver->query($reverse . 'score.spfbl.net', 'A');
                    if ($packet) {
                        foreach my $rr ($packet->answer) {
                            my $code = $rr->rdstring;
                            if ($code =~ m/^127\.0\.1\.([0-9]{1,3})$/i) {
                                $score = $1;
                            }
                        }
                    }
                };
            }
        }
    }

    if ($bounce && $bulk) {
        $result = 'accept';
        $information = 'bounce from bulk provider';
    } elsif ($good) {
        $result = 'accept';
        $information = 'good reputation';
    } elsif ($result eq 'nxdomain') {
        $result = 'reject';
        $information = 'non-existent domain';
    } elsif ($residential) {
        $result = 'reject';
        $information = 'residential IP';
    } elsif (!$fqdn && $result ne 'pass') {
        $result = 'reject';
        $information = 'invalid FQDN';
    } elsif ($invalid) {
        $result = 'reject';
        $information = 'invalid sender';
    } elsif ($score ne '' && $bad ge $score) {
        $result = 'reject';
        $information = 'very bad reputation';
    } elsif ($bad && $generic) {
        $result = 'reject';
        $information = 'bad generic server';
    } elsif ($bad) {
        $result = 'junk';
        $information = 'bad reputation';
    } elsif ($essential && $result ne 'pass') {
        $result = 'accept';
        $information = 'essential organization';
    } elsif ($transactional && $result ne 'pass') {
        $result = 'accept';
        $information = 'transactional email server';
    } elsif ($bulk && $result eq 'fail') {
        $result = 'softfail';
        $information = 'bulk email provider';
    } elsif ($bulk && $result eq 'permerror') {
        $result = 'accept';
        $information = 'bulk email provider';
    } elsif ($suspicious && $result eq 'softfail') {
        $result = 'junk';
        $information = 'suspicious origin';
    } elsif ($suspicious && $result eq 'permerror') {
        $result = 'junk';
        $information = 'suspicious origin';
    } elsif ($notserver && $generic) {
        $result = 'junk';
        $information = 'generic sender';
    } elsif ($notserver && $result eq 'softfail') {
        $result = 'junk';
        $information = 'non email server';
    } elsif ($notserver && $result eq 'permerror') {
        $result = 'junk';
        $information = 'non email server';
    } elsif ($generic && $result eq 'permerror') {
        $result = 'junk';
        $information = 'generic sender';
    } elsif ($trusted) {
        $result = 'accept';
        $information = 'trusted abuse team';
    } elsif ($bounce) {
        $information = 'bounce message';
    } elsif ($result eq 'none') {
        $information = 'no valid SPF registry';
    } elsif ($result eq 'permerror' && $explanation =~ m/ Redundant applicable /) {
        $result = 'accept';
        $information = 'redundant SPF registry';
    } elsif ($result eq 'permerror' && $explanation =~ m/ Maximum DNS-interactive terms limit /) {
        $result = 'accept';
        $information = 'maximum DNS look-ups exceeded';
    } elsif ($result eq 'permerror' && $explanation =~ m/ Maximum void DNS look-ups limit /) {
        $result = 'accept';
        $information = 'maximum void DNS look-ups exceeded';
    } elsif ($result eq 'permerror' && $explanation =~ m/ Junk encountered in /) {
        $result = 'accept';
        $information = 'SPF syntax error';
    } elsif ($result eq 'permerror' && $explanation =~ m/ Unknown mechanism /) {
        $result = 'accept';
        $information = 'SPF syntax error';
    } elsif ($result eq 'permerror' && $explanation =~ m/ Missing required /) {
        $result = 'accept';
        $information = 'SPF syntax error';
    } elsif ($result eq 'permerror' && $explanation =~ m/ has no applicable sender policy/) {
        $result = 'accept';
        $information = 'no applicable sender policy for include';
    } elsif ($result eq 'permerror') {
        $information = 'could not process SPF query';
    } elsif ($result eq 'temperror' && $explanation =~ m/ 'SERVFAIL' /) {
        $information = 'DNS service failed';
    } elsif ($result eq 'temperror') {
        $information = 'could not process SPF query';
    } elsif ($result eq 'pass') {
        $information = "designates $ip as permitted sender";
    } else {
        $information = "does not designate $ip as permitted sender";
    }
}

if ($output eq 'header') {
    if ($qualifier eq $result) {
        print("$qualifier \($information\) identity=mailfrom; client-ip=$ip; helo=$helo; envelope-from=$sender\;");
    } else {
        print("$qualifier \($result: $information\) identity=mailfrom; client-ip=$ip; helo=$helo; envelope-from=$sender\;");
    }
} elsif ($output eq 'postfix') {
    if ($result eq 'fail') {
        STDOUT->print("action=550 5.7.1 $information.\n\n");
    } elsif ($result eq 'permerror') {
        STDOUT->print("action=550 5.7.1 $information.\n\n");
    } elsif ($result eq 'temperror') {
        STDOUT->print("action=451 4.4.3 $information.\n\n");
    } elsif ($result eq 'junk') {
        STDOUT->print("action=PREPEND X-Spam-Flag: YES;\n\n");
    } elsif ($result eq 'reject') {
        STDOUT->print("action=550 5.7.1 $information.\n\n");
    } elsif ($result eq 'defer') {
        STDOUT->print("action=action=451 4.7.1 You sender is greylisted.\n\n");
    } else {
        STDOUT->print("action=PREPEND Received-SPF: $qualifier \($information\) identity=mailfrom; client-ip=$ip; helo=$helo; envelope-from=$sender\;\n\n");
    }
    STDOUT->flush();
    exit 0;
} else {
    print("IP: $ip\n");
    print("HELO: $helo\n");
    print("SENDER: $sender\n");
    print("\n");
    print("FQDN: $fqdn\n");
    print("HOSTNAME: $hostname\n");
    print("REVERSE: $reverse\n");
    print("EMAIL: $email\n");
    print("\n");
    print("FREEMAIL: $freemail\n");
    print("FOCUSED: $focused\n");
    print("GOOD: $good\n");
    print("ESSENTIAL: $essential\n");
    print("TRANSACTIONAL: $transactional\n");
    print("BULK: $bulk\n");
    print("\n");
    print("BAD: $bad\n");
    print("SUSPICIOUS: $suspicious\n");
    print("NOTSERVER: $notserver\n");
    print("RESIDENTIAL: $residential\n");
    print("GENERIC: $generic\n");
    print("SCORE: $score\n");
    print("\n");
    print("EXPLANATION: $explanation\n");
    if ($qualifier eq $result) {
        print("RESULT: $qualifier \($information\) identity=mailfrom; client-ip=$ip; helo=$helo; envelope-from=$sender\;\n");
    } else {
        print("RESULT: $qualifier \($result: $information\) identity=mailfrom; client-ip=$ip; helo=$helo; envelope-from=$sender\;\n");
    }
    print("\n");
}

if ($result eq 'pass') {
    exit 0;
} elsif ($result eq 'fail') {
    exit 1;
} elsif ($result eq 'softfail') {
    exit 2;
} elsif ($result eq 'neutral') {
    exit 3;
} elsif ($result eq 'permerror') {
    exit 4;
} elsif ($result eq 'temperror') {
    exit 5;
} elsif ($result eq 'none') {
    exit 6;
} elsif ($result eq 'accept') {
    exit 7;
} elsif ($result eq 'junk') {
    exit 8;
} elsif ($result eq 'reject') {
    exit 9;
} elsif ($result eq 'defer') {
    exit 10;
} else {
    exit 4;
}

sub freemail {
    my @freemail = ('gmail.com', 'hotmail.com', 'terra.com.br', 'yahoo.com.br', 'outlook.com', 'juno.com', 'uol.com.br', 'superwave.com.br', 'ig.com.br', 'yahoo.com', 'gpturbo.com.br', 'icloud.com', 'googlegroups.com', 'bol.com.br', 'googlemail.com', '163.com', 'desbrava.com.br', 'outlook.com.br', 'globo.com', 'sky.com', 'live.com', 'hotmail.com.br', 'shared.mandic.net.br', 'net11.com.br', 'bnet.com.br', 'portalnet.com.br', 'tolrs.com.br', 'ps5.com.br', 'tl.com.br', 'zoho.com', '126.com', 'test.com', 'email.com', 'msn.com', 'gmail.com.br', 'pannet.com.br', 'excite.it', 'me.com', 'netuno.com.br', 'aol.com', 'oi.net.br', 'globomail.com', 'plugarnet.com.br', 'chacuo.net', 'qq.com', 'mail.com', 'mail.ru', 'speedy.com.ar', 'walla.co.il', 'discovery.com', 'onda.com.br', 'ttml.co.in', 'hanmail.net', 'wanadoo.es', 'sercomtel.com.br', 'orange.fr', 'yandex.com', 'aliyun.com', 'ymail.com', 'ibest.com.br', 'pando.com', 'yahoo.dk', 'mhnet.com.br', 'sinos.net', 'veloxmail.com.br', 'eresmas.com', 'dgnet.com.br', 'att.net', 'alice.it', 'brturbo.com.br', 'rambler.ru', 't-online.de', 'bk.ru', 'aol.fr', 'com4.com.br', 'gmx.de', 'yahoo.co.jp', 'vip.163.com', 'yahoo.it', 'bt.com', 'foxmail.com', 'daum.net', 'terra.com', 'sbcglobal.net', 'mdbrasil.com.br', 'netvigator.com', 'yahoogrupos.com.br', '188.com', 'consultant.com', 'hotmail.it', 'outlook.fr', 'breathe.com', 'comcast.net', 'litoral.com.br', 'tiscali.it', 'veloturbo.com.br', 'americanet.com.br', 'yandex.ru', 'yahoo.co.uk', 'citromail.hu', 'live.co.uk', 'hotmail.co.uk', 'verizon.net', 'wnet.com.br', 'ya.com', 'web.de', 'mailcan.com', 'freemail.hu', 'cox.net', 'tca.com.br', 'libero.it', 'ntlworld.com', 'yahoo.com.ar', 'mundivox.com', 'netsite.com.br', 'lpnet.com.br', 'protonmail.com', 'wanadoo.fr', 'virgin.net', 'redesul.com.br', 'zipmail.com.br', 'rediffmail.com', 'adinet.com.uy', 'bellsouth.net', 'powerline.com.br', 'yahoo.com.hk', 'certelnet.com.br', 'desktop.com.br', 'mixmail.com', 'netbig.com.br', 'sina.com', 'spoofmail.de', 'abv.bg', 'mail.bg', 'orange.net', 'sapo.pt', 'blueyonder.co.uk', 'gmx.net', 'throwam.com', 'ya.ru', 'gmx.com', 'hughes.net', 'pzo.com.br', 'gruposinos.com.br', 'hitmail.com', 'hotmail.fr', 'oi.com.br', 'usa.com', 'yahoo.es', 'live.it', 'zohomail.com', 'dglnet.com.br', 'excite.co', 'wln.com.br', 'yahoo.de', 'yahoo.fr', 'engineer.com', 'usa.net', 'vetorial.net', 'inbox.ru', 'montevideo.com.uy', 'katamail.com', 'mail2freedom.com', 'wp.pl', 'financier.com', 'o2.pl', 'onet.pl', 'rocketmail.com', 'yaho.com', 'vip.sina.com', 'earthlink.net', 'freenet.de', 'netscape.net', 'outlook.de', 'excite.com', 'outlook.pt', 'virgilio.it', 'whale-mail.com', 'gmx.at', 'hotmail.de', 'huhmail.com', 'onda.net.br', 'versatel.nl', 'btinternet.com', 'canoemail.com', 'netzero.net', 'telenet.be', 'bigmir.net', 'gmx.co.uk', 'matrix.com.br', 'outlook.es', 'webjump.com', 'accountant.com', 'btconnect.com', 'micropic.com.br', 'sfr.fr', 'tin.it', 'xtra.co.nz', 'cc.lv', 'europe.com', 'list.ru', 'mac.com', 'mail2uk.com', 'net.hr', 'pacer.com', 'post.com', 'vodafone.com', 'yahoo.ca', 'yahoo.com.tw', 'yeah.net', 'hotmail.ca', 'infovia.com.ar', 'instruction.com', 'mailbox.co.za', 'mksnet.com.br', 'moose-mail.com', 'my.com', 'outlook.com.au', 'outlook.com.tr', 'tim.it', 'windowslive.com', 'yahoo.com.au', 'alibaba.com', 'chemist.com', 'fstelecom.com.br', 'inbox.lv', 'live.cn', 'live.fr', 'mail2abc.com', 'mail2europe.com', 'outlook.it', 'seanet.com', 'seznam.cz', 'singnet.com.sg', 'superig.com.br', 'ukr.net', 'wickmail.net', 'writeme.com', 'yahoo.co.nz', 'counsellor.com', 'free.fr', 'hetnet.nl', 'iveloz.net.br', 'live.ca', 'live.de', 'mail2ny.com', 'pobox.com', 'smtp.ru', 'techie.com', 'alumni.com', 'ananzi.co.za', 'arabia.com', 'arnet.com.ar', 'azet.sk', 'dcemail.com', 'floripa.com.br', 'hedgeai.com', 'housemail.com', 'irelandmail.com', 'korea.com', 'libre.net', 'mail-easy.fr', 'mail2artist.com', 'mail2cool.com', 'mail2earth.com', 'mail2engineer.com', 'mail2footballfan.com', 'mail2free.com', 'mail2hell.com', 'mail2honey.com', 'mgconecta.com.br', 'mt2015.com', 'op.pl', 'outlook.com.vn', 'outlook.my', 'pobox.sk', 'ro.ru', 'rogers.com', 'safrica.com', 'telstra.com.au', 'tlen.pl', 'virginmedia.com', 'webmail.co.za', 'yahoo.co.in', 'yahoo.com.co', 'yahoo.gr', 'aim.com', 'aol.de', 'aport.ru', 'aruba.it', 'as-if.com', 'dr.com', 'email.com.br', 'englandmail.com', 'interfree.it', 'interia.pl', 'km.ru', 'kyokodate.com', 'laposte.net', 'live.be', 'live.nl', 'london.com', 'mail.ee', 'mail2agent.com', 'mail2angela.com', 'mail2art.com', 'mail2australia.com', 'mail2beyond.com', 'mail2catlover.com', 'mail2dave.com', 'mail2irene.com', 'mail2leo.com', 'mail2mom.com', 'mail2power.com', 'mail2son.com', 'mail2stlouis.com', 'mail2swimmer.com', 'mail2teacher.com', 'mail2woman.com', 'mailinator.com', 'myself.com', 'naver.com', 'netlimit.com', 'neuf.fr', 'nifty.com', 'nus.edu.sg', 'optusnet.com.au', 'osite.com.br', 'poczta.fm', 'poczta.onet.pl', 'reality-concept.club', 'terra.es', 'tom.com', 'uswestmail.net', 'yahoo.co', 'yahoo.com.cn', '150mail.com', '2trom.com', 'ameritech.net', 'arcor.de', 'asia.com', 'australiamail.com', 'bartender.net', 'bonbon.net', 'c2.hu', 'caramail.com', 'casino.com', 'centrum.sk', 'chechnya.conf.work', 'chello.nl', 'cyber-innovation.club', 'dnsmadeeasy.com', 'e-mail.cz', 'email.it', 'eml.pp.ua', 'executivemail.co.za', 'fastservice.com', 'gazeta.pl', 'hotmail.com.ar', 'hotmail.es', 'index.ua', 'iqemail.com', 'jippii.fi', 'live.com.mx', 'live.dk', 'mail2007.com', 'mail2allen.com', 'mail2amber.com', 'mail2anesthesiologist.com', 'mail2arabia.com', 'mail2bank.com', 'mail2beauty.com', 'mail2bill.com', 'mail2bob.com', 'mail2bryan.com', 'mail2cancer.com', 'mail2care.com', 'mail2chocolate.com', 'mail2consultant.com', 'mail2cowgirl.com', 'mail2cutey.com', 'mail2dad.com', 'mail2dancer.com', 'mail2darren.com', 'mail2dude.com', 'mail2fashion.com', 'mail2florida.com', 'mail2grandma.com', 'mail2grant.com', 'mail2harry.com', 'mail2jail.com', 'mail2jazz.com', 'mail2john.com', 'mail2leone.com', 'mail2lloyd.com', 'mail2mars.com', 'mail2matt.com', 'mail2nick.com', 'mail2paris.com', 'mail2philippines.com', 'mail2pickup.com', 'mail2pop.com', 'mail2qatar.com', 'mail2rage.com', 'mail2rebecca.com', 'mail2roy.com', 'mail2runner.com', 'mail2scientist.com', 'mail2seth.com', 'mail2sexy.com', 'mail2smile.com', 'mail2song.com', 'mail2strong.com', 'mail2tango.com', 'mail2tycoon.com', 'mail2webtop.com', 'mailed.ro', 'mailproxsy.com', 'mynet.com', 'neo.rr.com', 'netcmail.com', 'opoczta.pl', 'optonline.net', 'outlook.cl', 'outlook.in', 'parrot.com', 'pop.com.br', 'prodigy.net', 'r7.com', 'rambler.ua', 'roadrunner.com', 'shitmail.org', 'sify.com', 'soldier.hu', 'techemail.com', 'telefonica.net', 'thai.com', 'w3.to', 'wavetec.com.br', 'wooow.it', 'workmail.com', 'yahoo.com.my', 'yahoo.no', 'yahoo.se', '21cn.com', 'address.com', 'aon.at', 'bigboss.cz', 'bigpond.net.au', 'c3.hu', 'centrum.cz', 'china.com', 'compuserve.com', 'contractor.net', 'cox.com', 'cyberleports.com', 'dbmail.com', 'eircom.net', 'fastmail.co.uk', 'fastmail.net', 'fibertel.com.ar', 'freesurf.fr', 'gencmail.com', 'hello.to', 'homemail.co.za', 'homemail.com', 'interlap.com.ar', 'internode.on.net', 'ixp.net', 'jazzandjava.com', 'jubii.dk', 'latinmail.com', 'live.cl', 'live.com.au', 'live.com.pt', 'live.ie', 'live.se', 'lycos.com', 'mail.com.tr', 'mail.de', 'mail.yahoo.co.jp', 'me.by', 'myway.com', 'narod.ru', 'onenet.com.ar', 'orthodontist.net', 'pacbell.net', 'peoplepc.com', 'post.cz', 'priest.com', 'radicalz.com', 'representative.com', 'rhyta.com', 'rline.com.br', 'runbox.com', 'saigonnet.vn', 'seguros.com.br', 'skynet.be', 'sonnenkinder.org', 'starmedia.com', 'start.no', 'swbell.net', 'telegraf.by', 'tempymail.com', 'vodamail.co.za', 'voila.fr', 'walla.com', 'wazabi.club', 'workmail.co.za', 'xs4all.nl', 'y7mail.com', 'yahoo.com.mx', 'yahoo.com.vn', 'yahoo.in', 'yandex.ua', 'zednet.co.uk', 'zworg.com');
    foreach $domain (@freemail) {
        if (@_[0] eq $domain) {
            return 1;
        }
    }
    return 0;
}

sub removeLicence() {
    if (%config) {
        eval {
            $config{''}{'licence'} = '';
            write_config %config;
        };
    }
}
