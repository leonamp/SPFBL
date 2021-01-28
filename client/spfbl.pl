#!/usr/bin/perl
#
# An advanced SPF query, like spfquery command, but with two more result codes.
# This script queries the public lists of SPFBL.net, so be careful about query limits.
#
# Usage:
#    spfbl.pl '<ip>' '<helo>' '<sender>' [0|1]
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
#    sudo cpan -i -f Net::IP Net::DNS Mail::SPF
#
# For cPanel configuration, run this installation script:
#
#    Install:
#
#       sudo cpan -i -f Net::IP Net::DNS Mail::SPF
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
#        message = 5.7.1 You cannot send messages to this system.
#        condition = ${if eq {$runrc}{9}{true}{false}}
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
#         check_policy_service unix:private/policy-spfbl
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
# Version: 1.6

use Net::IP qw(ip_expand_address ip_reverse);
use Net::DNS;
use Mail::SPF;

my $ip;
my $helo;
my $sender;
my $output;

if ($#ARGV == -1) {
    my $params = {};
    while ( my $line = <STDIN> ) {
        chomp $line;
        if ( $line =~ /=/ ) {
            my ( $key, $value ) = split /=/, $line, 2;
            $params->{ $key } = $value;
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
} elsif ($ARGV[3]) {
    $ip = $ARGV[0];
    $helo = $ARGV[1];
    $sender = $ARGV[2];
    $output = 'debug';
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
        my $qualifier = $spf->process($request);
        $result = $qualifier->code;
        $explanation = $qualifier->local_explanation;
    } or do {
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
    $result = 'none';
    $explanation = 'bounce message';
}

my $focused = $freemail && $result eq 'pass';
my $good = 0;
my $essential = 0;
my $transactional = 0;
my $bulk = 0;

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

my $information;
if ($bounce && $bulk) {
    $result = 'accept';
    $information = "$hostname: bounce from bulk provider";
} elsif ($good) {
    $result = 'accept';
    $information = "$hostname: good reputation";
} elsif ($result eq 'nxdomain') {
    $result = 'reject';
    $information = "$domain: non-existent domain";
} elsif ($residential) {
    $result = 'reject';
    $information = "$hostname: residential IP";
} elsif (!$fqdn && $result ne 'pass') {
    $result = 'reject';
    $information = "$helo: invalid FQDN";
} elsif ($invalid) {
    $result = 'reject';
    $information = "$sender: invalid sender";
} elsif ($score ne '' && $bad ge $score) {
    $result = 'reject';
    $information = "$hostname: very bad reputation";
} elsif ($bad && $generic) {
    $result = 'reject';
    $information = "$hostname: bad generic server";
} elsif ($bad) {
    $result = 'junk';
    $information = "$hostname: bad reputation";
} elsif ($essential && $result ne 'pass') {
    $result = 'accept';
    $information = "$hostname: essential organization";
} elsif ($transactional && $result ne 'pass') {
    $result = 'accept';
    $information = "$hostname: transactional email server";
} elsif ($bulk && $result eq 'fail') {
    $result = 'softfail';
    $information = "$hostname: bulk email provider";
} elsif ($bulk && $result eq 'permerror') {
    $result = 'accept';
    $information = "$hostname: bulk email provider";
} elsif ($suspicious && $result eq 'softfail') {
    $result = 'junk';
    $information = "$hostname: suspicious origin";
} elsif ($suspicious && $result eq 'permerror') {
    $result = 'junk';
    $information = "$hostname: suspicious origin";
} elsif ($notserver && $generic) {
    $result = 'junk';
    $information = "$hostname: generic sender";
} elsif ($notserver && $result eq 'softfail') {
    $result = 'junk';
    $information = "$hostname: non email server";
} elsif ($notserver && $result eq 'permerror') {
    $result = 'junk';
    $information = "$hostname: non email server";
} elsif ($generic && $result eq 'permerror') {
    $result = 'junk';
    $information = "$hostname: generic sender";
} elsif ($result eq 'permerror' && $explanation =~ m/ Redundant applicable /) {
    $result = 'accept';
    $information = "$hostname: redundant SPF registry";
} elsif ($result eq 'permerror' && $explanation =~ m/ Maximum DNS-interactive terms limit /) {
    $result = 'accept';
    $information = "$domain: maximum DNS look-ups exceeded";
} elsif ($result eq 'permerror' && $explanation =~ m/ Maximum void DNS look-ups limit /) {
    $result = 'accept';
    $information = "$domain: maximum void DNS look-ups exceeded";
} elsif ($result eq 'permerror' && $explanation =~ m/ Junk encountered in /) {
    $result = 'accept';
    $information = "$domain: SPF syntax error";
} elsif ($result eq 'permerror' && $explanation =~ m/ Unknown mechanism /) {
    $result = 'accept';
    $information = "$domain: SPF syntax error";
} elsif ($result eq 'permerror' && $explanation =~ m/ Missing required /) {
    $result = 'accept';
    $information = "$domain: SPF syntax error";
} elsif ($result eq 'permerror' && $explanation =~ m/ has no applicable sender policy$/) {
    $result = 'accept';
    $information = "$domain: no applicable sender policy for include";
} elsif ($result eq 'permerror') {
    $information = "$domain: could not process SPF query";
} elsif ($result eq 'temperror' && $explanation =~ m/ 'SERVFAIL' /) {
    $information = "$domain: DNS service failed";
} elsif ($result eq 'temperror') {
    $information = "$domain: could not process SPF query";
} elsif ($bounce) {
    $information = "$hostname: bounce message";
} elsif ($result eq 'none') {
    $information = "$domain: no valid SPF registry";
} elsif ($result eq 'pass') {
    $information = "$domain: designates $ip as permitted sender";
} else {
    $information = "$domain: does not designate $ip as permitted sender";
}

if ($output eq 'header') {
    print("$result \($information\) identity=mailfrom; client-ip=$ip; helo=$helo; envelope-from=$sender\;"); 
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
    } else {
        STDOUT->print("action=PREPEND Received-SPF: $result \($information\) identity=mailfrom; client-ip=$ip; helo=$helo; envelope-from=$sender\;\n\n");
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
    print("RESULT: $result \($information\) identity=mailfrom; client-ip=$ip; helo=$helo; envelope-from=$sender\;\n");
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
} else {
    exit 4;
}

sub freemail {
    if (@_[0] eq 'gmail.com') {
        return 1;
    } elsif (@_[0] eq 'hotmail.com') {
        return 1;
    } elsif (@_[0] eq 'terra.com.br') {
        return 1;
    } elsif (@_[0] eq 'yahoo.com.br') {
        return 1;
    } elsif (@_[0] eq 'outlook.com') {
        return 1;
    } elsif (@_[0] eq 'juno.com') {
        return 1;
    } elsif (@_[0] eq 'uol.com.br') {
        return 1;
    } elsif (@_[0] eq 'superwave.com.br') {
        return 1;
    } elsif (@_[0] eq 'ig.com.br') {
        return 1;
    } elsif (@_[0] eq 'yahoo.com') {
        return 1;
    } elsif (@_[0] eq 'gpturbo.com.br') {
        return 1;
    } elsif (@_[0] eq 'icloud.com') {
        return 1;
    } elsif (@_[0] eq 'googlegroups.com') {
        return 1;
    } elsif (@_[0] eq 'bol.com.br') {
        return 1;
    } elsif (@_[0] eq 'googlemail.com') {
        return 1;
    } elsif (@_[0] eq '163.com') {
        return 1;
    } elsif (@_[0] eq 'desbrava.com.br') {
        return 1;
    } elsif (@_[0] eq 'outlook.com.br') {
        return 1;
    } elsif (@_[0] eq 'globo.com') {
        return 1;
    } elsif (@_[0] eq 'sky.com') {
        return 1;
    } elsif (@_[0] eq 'live.com') {
        return 1;
    } elsif (@_[0] eq 'hotmail.com.br') {
        return 1;
    } elsif (@_[0] eq 'shared.mandic.net.br') {
        return 1;
    } elsif (@_[0] eq 'net11.com.br') {
        return 1;
    } elsif (@_[0] eq 'bnet.com.br') {
        return 1;
    } elsif (@_[0] eq 'portalnet.com.br') {
        return 1;
    } elsif (@_[0] eq 'tolrs.com.br') {
        return 1;
    } elsif (@_[0] eq 'ps5.com.br') {
        return 1;
    } elsif (@_[0] eq 'tl.com.br') {
        return 1;
    } elsif (@_[0] eq 'zoho.com') {
        return 1;
    } elsif (@_[0] eq '126.com') {
        return 1;
    } elsif (@_[0] eq 'test.com') {
        return 1;
    } elsif (@_[0] eq 'email.com') {
        return 1;
    } elsif (@_[0] eq 'msn.com') {
        return 1;
    } elsif (@_[0] eq 'gmail.com.br') {
        return 1;
    } elsif (@_[0] eq 'pannet.com.br') {
        return 1;
    } elsif (@_[0] eq 'excite.it') {
        return 1;
    } elsif (@_[0] eq 'me.com') {
        return 1;
    } elsif (@_[0] eq 'netuno.com.br') {
        return 1;
    } elsif (@_[0] eq 'aol.com') {
        return 1;
    } elsif (@_[0] eq 'oi.net.br') {
        return 1;
    } elsif (@_[0] eq 'globomail.com') {
        return 1;
    } elsif (@_[0] eq 'plugarnet.com.br') {
        return 1;
    } elsif (@_[0] eq 'chacuo.net') {
        return 1;
    } elsif (@_[0] eq 'qq.com') {
        return 1;
    } elsif (@_[0] eq 'mail.com') {
        return 1;
    } elsif (@_[0] eq 'mail.ru') {
        return 1;
    } elsif (@_[0] eq 'speedy.com.ar') {
        return 1;
    } elsif (@_[0] eq 'walla.co.il') {
        return 1;
    } elsif (@_[0] eq 'discovery.com') {
        return 1;
    } elsif (@_[0] eq 'onda.com.br') {
        return 1;
    } elsif (@_[0] eq 'ttml.co.in') {
        return 1;
    } elsif (@_[0] eq 'hanmail.net') {
        return 1;
    } elsif (@_[0] eq 'wanadoo.es') {
        return 1;
    } elsif (@_[0] eq 'sercomtel.com.br') {
        return 1;
    } elsif (@_[0] eq 'orange.fr') {
        return 1;
    } elsif (@_[0] eq 'yandex.com') {
        return 1;
    } elsif (@_[0] eq 'aliyun.com') {
        return 1;
    } elsif (@_[0] eq 'ymail.com') {
        return 1;
    } elsif (@_[0] eq 'ibest.com.br') {
        return 1;
    } elsif (@_[0] eq 'pando.com') {
        return 1;
    } elsif (@_[0] eq 'yahoo.dk') {
        return 1;
    } elsif (@_[0] eq 'mhnet.com.br') {
        return 1;
    } elsif (@_[0] eq 'sinos.net') {
        return 1;
    } elsif (@_[0] eq 'veloxmail.com.br') {
        return 1;
    } elsif (@_[0] eq 'eresmas.com') {
        return 1;
    } elsif (@_[0] eq 'dgnet.com.br') {
        return 1;
    } elsif (@_[0] eq 'att.net') {
        return 1;
    } elsif (@_[0] eq 'alice.it') {
        return 1;
    } elsif (@_[0] eq 'brturbo.com.br') {
        return 1;
    } elsif (@_[0] eq 'rambler.ru') {
        return 1;
    } elsif (@_[0] eq 't-online.de') {
        return 1;
    } elsif (@_[0] eq 'bk.ru') {
        return 1;
    } elsif (@_[0] eq 'aol.fr') {
        return 1;
    } elsif (@_[0] eq 'com4.com.br') {
        return 1;
    } elsif (@_[0] eq 'gmx.de') {
        return 1;
    } elsif (@_[0] eq 'yahoo.co.jp') {
        return 1;
    } elsif (@_[0] eq 'vip.163.com') {
        return 1;
    } elsif (@_[0] eq 'yahoo.it') {
        return 1;
    } elsif (@_[0] eq 'bt.com') {
        return 1;
    } elsif (@_[0] eq 'foxmail.com') {
        return 1;
    } elsif (@_[0] eq 'daum.net') {
        return 1;
    } elsif (@_[0] eq 'terra.com') {
        return 1;
    } elsif (@_[0] eq 'sbcglobal.net') {
        return 1;
    } elsif (@_[0] eq 'mdbrasil.com.br') {
        return 1;
    } elsif (@_[0] eq 'netvigator.com') {
        return 1;
    } elsif (@_[0] eq 'yahoogrupos.com.br') {
        return 1;
    } elsif (@_[0] eq '188.com') {
        return 1;
    } elsif (@_[0] eq 'consultant.com') {
        return 1;
    } elsif (@_[0] eq 'hotmail.it') {
        return 1;
    } elsif (@_[0] eq 'outlook.fr') {
        return 1;
    } elsif (@_[0] eq 'breathe.com') {
        return 1;
    } elsif (@_[0] eq 'comcast.net') {
        return 1;
    } elsif (@_[0] eq 'litoral.com.br') {
        return 1;
    } elsif (@_[0] eq 'tiscali.it') {
        return 1;
    } elsif (@_[0] eq 'veloturbo.com.br') {
        return 1;
    } elsif (@_[0] eq 'americanet.com.br') {
        return 1;
    } elsif (@_[0] eq 'yandex.ru') {
        return 1;
    } elsif (@_[0] eq 'yahoo.co.uk') {
        return 1;
    } elsif (@_[0] eq 'citromail.hu') {
        return 1;
    } elsif (@_[0] eq 'live.co.uk') {
        return 1;
    } elsif (@_[0] eq 'hotmail.co.uk') {
        return 1;
    } elsif (@_[0] eq 'verizon.net') {
        return 1;
    } elsif (@_[0] eq 'wnet.com.br') {
        return 1;
    } elsif (@_[0] eq 'ya.com') {
        return 1;
    } elsif (@_[0] eq 'web.de') {
        return 1;
    } elsif (@_[0] eq 'mailcan.com') {
        return 1;
    } elsif (@_[0] eq 'freemail.hu') {
        return 1;
    } elsif (@_[0] eq 'cox.net') {
        return 1;
    } elsif (@_[0] eq 'tca.com.br') {
        return 1;
    } elsif (@_[0] eq 'libero.it') {
        return 1;
    } elsif (@_[0] eq 'ntlworld.com') {
        return 1;
    } elsif (@_[0] eq 'yahoo.com.ar') {
        return 1;
    } elsif (@_[0] eq 'mundivox.com') {
        return 1;
    } elsif (@_[0] eq 'netsite.com.br') {
        return 1;
    } elsif (@_[0] eq 'lpnet.com.br') {
        return 1;
    } elsif (@_[0] eq 'protonmail.com') {
        return 1;
    } elsif (@_[0] eq 'wanadoo.fr') {
        return 1;
    } elsif (@_[0] eq 'virgin.net') {
        return 1;
    } elsif (@_[0] eq 'redesul.com.br') {
        return 1;
    } elsif (@_[0] eq 'zipmail.com.br') {
        return 1;
    } elsif (@_[0] eq 'rediffmail.com') {
        return 1;
    } elsif (@_[0] eq 'adinet.com.uy') {
        return 1;
    } elsif (@_[0] eq 'bellsouth.net') {
        return 1;
    } elsif (@_[0] eq 'powerline.com.br') {
        return 1;
    } elsif (@_[0] eq 'yahoo.com.hk') {
        return 1;
    } elsif (@_[0] eq 'certelnet.com.br') {
        return 1;
    } elsif (@_[0] eq 'desktop.com.br') {
        return 1;
    } elsif (@_[0] eq 'mixmail.com') {
        return 1;
    } elsif (@_[0] eq 'netbig.com.br') {
        return 1;
    } elsif (@_[0] eq 'sina.com') {
        return 1;
    } elsif (@_[0] eq 'spoofmail.de') {
        return 1;
    } elsif (@_[0] eq 'abv.bg') {
        return 1;
    } elsif (@_[0] eq 'mail.bg') {
        return 1;
    } elsif (@_[0] eq 'orange.net') {
        return 1;
    } elsif (@_[0] eq 'sapo.pt') {
        return 1;
    } elsif (@_[0] eq 'blueyonder.co.uk') {
        return 1;
    } elsif (@_[0] eq 'gmx.net') {
        return 1;
    } elsif (@_[0] eq 'throwam.com') {
        return 1;
    } elsif (@_[0] eq 'ya.ru') {
        return 1;
    } elsif (@_[0] eq 'gmx.com') {
        return 1;
    } elsif (@_[0] eq 'hughes.net') {
        return 1;
    } elsif (@_[0] eq 'pzo.com.br') {
        return 1;
    } elsif (@_[0] eq 'gruposinos.com.br') {
        return 1;
    } elsif (@_[0] eq 'hitmail.com') {
        return 1;
    } elsif (@_[0] eq 'hotmail.fr') {
        return 1;
    } elsif (@_[0] eq 'oi.com.br') {
        return 1;
    } elsif (@_[0] eq 'usa.com') {
        return 1;
    } elsif (@_[0] eq 'yahoo.es') {
        return 1;
    } elsif (@_[0] eq 'live.it') {
        return 1;
    } elsif (@_[0] eq 'zohomail.com') {
        return 1;
    } elsif (@_[0] eq 'dglnet.com.br') {
        return 1;
    } elsif (@_[0] eq 'excite.co') {
        return 1;
    } elsif (@_[0] eq 'wln.com.br') {
        return 1;
    } elsif (@_[0] eq 'yahoo.de') {
        return 1;
    } elsif (@_[0] eq 'yahoo.fr') {
        return 1;
    } elsif (@_[0] eq 'engineer.com') {
        return 1;
    } elsif (@_[0] eq 'usa.net') {
        return 1;
    } elsif (@_[0] eq 'vetorial.net') {
        return 1;
    } elsif (@_[0] eq 'inbox.ru') {
        return 1;
    } elsif (@_[0] eq 'montevideo.com.uy') {
        return 1;
    } elsif (@_[0] eq 'katamail.com') {
        return 1;
    } elsif (@_[0] eq 'mail2freedom.com') {
        return 1;
    } elsif (@_[0] eq 'wp.pl') {
        return 1;
    } elsif (@_[0] eq 'financier.com') {
        return 1;
    } elsif (@_[0] eq 'o2.pl') {
        return 1;
    } elsif (@_[0] eq 'onet.pl') {
        return 1;
    } elsif (@_[0] eq 'rocketmail.com') {
        return 1;
    } elsif (@_[0] eq 'yaho.com') {
        return 1;
    } elsif (@_[0] eq 'vip.sina.com') {
        return 1;
    } elsif (@_[0] eq 'earthlink.net') {
        return 1;
    } elsif (@_[0] eq 'freenet.de') {
        return 1;
    } elsif (@_[0] eq 'netscape.net') {
        return 1;
    } elsif (@_[0] eq 'outlook.de') {
        return 1;
    } elsif (@_[0] eq 'excite.com') {
        return 1;
    } elsif (@_[0] eq 'outlook.pt') {
        return 1;
    } elsif (@_[0] eq 'virgilio.it') {
        return 1;
    } elsif (@_[0] eq 'whale-mail.com') {
        return 1;
    } elsif (@_[0] eq 'gmx.at') {
        return 1;
    } elsif (@_[0] eq 'hotmail.de') {
        return 1;
    } elsif (@_[0] eq 'huhmail.com') {
        return 1;
    } elsif (@_[0] eq 'onda.net.br') {
        return 1;
    } elsif (@_[0] eq 'versatel.nl') {
        return 1;
    } elsif (@_[0] eq 'btinternet.com') {
        return 1;
    } elsif (@_[0] eq 'canoemail.com') {
        return 1;
    } elsif (@_[0] eq 'netzero.net') {
        return 1;
    } elsif (@_[0] eq 'telenet.be') {
        return 1;
    } elsif (@_[0] eq 'bigmir.net') {
        return 1;
    } elsif (@_[0] eq 'gmx.co.uk') {
        return 1;
    } elsif (@_[0] eq 'matrix.com.br') {
        return 1;
    } elsif (@_[0] eq 'outlook.es') {
        return 1;
    } elsif (@_[0] eq 'webjump.com') {
        return 1;
    } elsif (@_[0] eq 'accountant.com') {
        return 1;
    } elsif (@_[0] eq 'btconnect.com') {
        return 1;
    } elsif (@_[0] eq 'micropic.com.br') {
        return 1;
    } elsif (@_[0] eq 'sfr.fr') {
        return 1;
    } elsif (@_[0] eq 'tin.it') {
        return 1;
    } elsif (@_[0] eq 'xtra.co.nz') {
        return 1;
    } elsif (@_[0] eq 'cc.lv') {
        return 1;
    } elsif (@_[0] eq 'europe.com') {
        return 1;
    } elsif (@_[0] eq 'list.ru') {
        return 1;
    } elsif (@_[0] eq 'mac.com') {
        return 1;
    } elsif (@_[0] eq 'mail2uk.com') {
        return 1;
    } elsif (@_[0] eq 'net.hr') {
        return 1;
    } elsif (@_[0] eq 'pacer.com') {
        return 1;
    } elsif (@_[0] eq 'post.com') {
        return 1;
    } elsif (@_[0] eq 'vodafone.com') {
        return 1;
    } elsif (@_[0] eq 'yahoo.ca') {
        return 1;
    } elsif (@_[0] eq 'yahoo.com.tw') {
        return 1;
    } elsif (@_[0] eq 'yeah.net') {
        return 1;
    } elsif (@_[0] eq 'hotmail.ca') {
        return 1;
    } elsif (@_[0] eq 'infovia.com.ar') {
        return 1;
    } elsif (@_[0] eq 'instruction.com') {
        return 1;
    } elsif (@_[0] eq 'mailbox.co.za') {
        return 1;
    } elsif (@_[0] eq 'mksnet.com.br') {
        return 1;
    } elsif (@_[0] eq 'moose-mail.com') {
        return 1;
    } elsif (@_[0] eq 'my.com') {
        return 1;
    } elsif (@_[0] eq 'outlook.com.au') {
        return 1;
    } elsif (@_[0] eq 'outlook.com.tr') {
        return 1;
    } elsif (@_[0] eq 'tim.it') {
        return 1;
    } elsif (@_[0] eq 'windowslive.com') {
        return 1;
    } elsif (@_[0] eq 'yahoo.com.au') {
        return 1;
    } elsif (@_[0] eq 'alibaba.com') {
        return 1;
    } elsif (@_[0] eq 'chemist.com') {
        return 1;
    } elsif (@_[0] eq 'fstelecom.com.br') {
        return 1;
    } elsif (@_[0] eq 'inbox.lv') {
        return 1;
    } elsif (@_[0] eq 'live.cn') {
        return 1;
    } elsif (@_[0] eq 'live.fr') {
        return 1;
    } elsif (@_[0] eq 'mail2abc.com') {
        return 1;
    } elsif (@_[0] eq 'mail2europe.com') {
        return 1;
    } elsif (@_[0] eq 'outlook.it') {
        return 1;
    } elsif (@_[0] eq 'seanet.com') {
        return 1;
    } elsif (@_[0] eq 'seznam.cz') {
        return 1;
    } elsif (@_[0] eq 'singnet.com.sg') {
        return 1;
    } elsif (@_[0] eq 'superig.com.br') {
        return 1;
    } elsif (@_[0] eq 'ukr.net') {
        return 1;
    } elsif (@_[0] eq 'wickmail.net') {
        return 1;
    } elsif (@_[0] eq 'writeme.com') {
        return 1;
    } elsif (@_[0] eq 'yahoo.co.nz') {
        return 1;
    } elsif (@_[0] eq 'counsellor.com') {
        return 1;
    } elsif (@_[0] eq 'free.fr') {
        return 1;
    } elsif (@_[0] eq 'hetnet.nl') {
        return 1;
    } elsif (@_[0] eq 'iveloz.net.br') {
        return 1;
    } elsif (@_[0] eq 'live.ca') {
        return 1;
    } elsif (@_[0] eq 'live.de') {
        return 1;
    } elsif (@_[0] eq 'mail2ny.com') {
        return 1;
    } elsif (@_[0] eq 'pobox.com') {
        return 1;
    } elsif (@_[0] eq 'smtp.ru') {
        return 1;
    } elsif (@_[0] eq 'techie.com') {
        return 1;
    } elsif (@_[0] eq 'alumni.com') {
        return 1;
    } elsif (@_[0] eq 'ananzi.co.za') {
        return 1;
    } elsif (@_[0] eq 'arabia.com') {
        return 1;
    } elsif (@_[0] eq 'arnet.com.ar') {
        return 1;
    } elsif (@_[0] eq 'azet.sk') {
        return 1;
    } elsif (@_[0] eq 'dcemail.com') {
        return 1;
    } elsif (@_[0] eq 'floripa.com.br') {
        return 1;
    } elsif (@_[0] eq 'hedgeai.com') {
        return 1;
    } elsif (@_[0] eq 'housemail.com') {
        return 1;
    } elsif (@_[0] eq 'irelandmail.com') {
        return 1;
    } elsif (@_[0] eq 'korea.com') {
        return 1;
    } elsif (@_[0] eq 'libre.net') {
        return 1;
    } elsif (@_[0] eq 'mail-easy.fr') {
        return 1;
    } elsif (@_[0] eq 'mail2artist.com') {
        return 1;
    } elsif (@_[0] eq 'mail2cool.com') {
        return 1;
    } elsif (@_[0] eq 'mail2earth.com') {
        return 1;
    } elsif (@_[0] eq 'mail2engineer.com') {
        return 1;
    } elsif (@_[0] eq 'mail2footballfan.com') {
        return 1;
    } elsif (@_[0] eq 'mail2free.com') {
        return 1;
    } elsif (@_[0] eq 'mail2hell.com') {
        return 1;
    } elsif (@_[0] eq 'mail2honey.com') {
        return 1;
    } elsif (@_[0] eq 'mgconecta.com.br') {
        return 1;
    } elsif (@_[0] eq 'mt2015.com') {
        return 1;
    } elsif (@_[0] eq 'op.pl') {
        return 1;
    } elsif (@_[0] eq 'outlook.com.vn') {
        return 1;
    } elsif (@_[0] eq 'outlook.my') {
        return 1;
    } elsif (@_[0] eq 'pobox.sk') {
        return 1;
    } elsif (@_[0] eq 'ro.ru') {
        return 1;
    } elsif (@_[0] eq 'rogers.com') {
        return 1;
    } elsif (@_[0] eq 'safrica.com') {
        return 1;
    } elsif (@_[0] eq 'telstra.com.au') {
        return 1;
    } elsif (@_[0] eq 'tlen.pl') {
        return 1;
    } elsif (@_[0] eq 'virginmedia.com') {
        return 1;
    } elsif (@_[0] eq 'webmail.co.za') {
        return 1;
    } elsif (@_[0] eq 'yahoo.co.in') {
        return 1;
    } elsif (@_[0] eq 'yahoo.com.co') {
        return 1;
    } elsif (@_[0] eq 'yahoo.gr') {
        return 1;
    } elsif (@_[0] eq 'aim.com') {
        return 1;
    } elsif (@_[0] eq 'aol.de') {
        return 1;
    } elsif (@_[0] eq 'aport.ru') {
        return 1;
    } elsif (@_[0] eq 'aruba.it') {
        return 1;
    } elsif (@_[0] eq 'as-if.com') {
        return 1;
    } elsif (@_[0] eq 'dr.com') {
        return 1;
    } elsif (@_[0] eq 'email.com.br') {
        return 1;
    } elsif (@_[0] eq 'englandmail.com') {
        return 1;
    } elsif (@_[0] eq 'interfree.it') {
        return 1;
    } elsif (@_[0] eq 'interia.pl') {
        return 1;
    } elsif (@_[0] eq 'km.ru') {
        return 1;
    } elsif (@_[0] eq 'kyokodate.com') {
        return 1;
    } elsif (@_[0] eq 'laposte.net') {
        return 1;
    } elsif (@_[0] eq 'live.be') {
        return 1;
    } elsif (@_[0] eq 'live.nl') {
        return 1;
    } elsif (@_[0] eq 'london.com') {
        return 1;
    } elsif (@_[0] eq 'mail.ee') {
        return 1;
    } elsif (@_[0] eq 'mail2agent.com') {
        return 1;
    } elsif (@_[0] eq 'mail2angela.com') {
        return 1;
    } elsif (@_[0] eq 'mail2art.com') {
        return 1;
    } elsif (@_[0] eq 'mail2australia.com') {
        return 1;
    } elsif (@_[0] eq 'mail2beyond.com') {
        return 1;
    } elsif (@_[0] eq 'mail2catlover.com') {
        return 1;
    } elsif (@_[0] eq 'mail2dave.com') {
        return 1;
    } elsif (@_[0] eq 'mail2irene.com') {
        return 1;
    } elsif (@_[0] eq 'mail2leo.com') {
        return 1;
    } elsif (@_[0] eq 'mail2mom.com') {
        return 1;
    } elsif (@_[0] eq 'mail2power.com') {
        return 1;
    } elsif (@_[0] eq 'mail2son.com') {
        return 1;
    } elsif (@_[0] eq 'mail2stlouis.com') {
        return 1;
    } elsif (@_[0] eq 'mail2swimmer.com') {
        return 1;
    } elsif (@_[0] eq 'mail2teacher.com') {
        return 1;
    } elsif (@_[0] eq 'mail2woman.com') {
        return 1;
    } elsif (@_[0] eq 'mailinator.com') {
        return 1;
    } elsif (@_[0] eq 'myself.com') {
        return 1;
    } elsif (@_[0] eq 'naver.com') {
        return 1;
    } elsif (@_[0] eq 'netlimit.com') {
        return 1;
    } elsif (@_[0] eq 'neuf.fr') {
        return 1;
    } elsif (@_[0] eq 'nifty.com') {
        return 1;
    } elsif (@_[0] eq 'nus.edu.sg') {
        return 1;
    } elsif (@_[0] eq 'optusnet.com.au') {
        return 1;
    } elsif (@_[0] eq 'osite.com.br') {
        return 1;
    } elsif (@_[0] eq 'poczta.fm') {
        return 1;
    } elsif (@_[0] eq 'poczta.onet.pl') {
        return 1;
    } elsif (@_[0] eq 'reality-concept.club') {
        return 1;
    } elsif (@_[0] eq 'terra.es') {
        return 1;
    } elsif (@_[0] eq 'tom.com') {
        return 1;
    } elsif (@_[0] eq 'uswestmail.net') {
        return 1;
    } elsif (@_[0] eq 'yahoo.co') {
        return 1;
    } elsif (@_[0] eq 'yahoo.com.cn') {
        return 1;
    } elsif (@_[0] eq '150mail.com') {
        return 1;
    } elsif (@_[0] eq '2trom.com') {
        return 1;
    } elsif (@_[0] eq 'ameritech.net') {
        return 1;
    } elsif (@_[0] eq 'arcor.de') {
        return 1;
    } elsif (@_[0] eq 'asia.com') {
        return 1;
    } elsif (@_[0] eq 'australiamail.com') {
        return 1;
    } elsif (@_[0] eq 'bartender.net') {
        return 1;
    } elsif (@_[0] eq 'bonbon.net') {
        return 1;
    } elsif (@_[0] eq 'c2.hu') {
        return 1;
    } elsif (@_[0] eq 'caramail.com') {
        return 1;
    } elsif (@_[0] eq 'casino.com') {
        return 1;
    } elsif (@_[0] eq 'centrum.sk') {
        return 1;
    } elsif (@_[0] eq 'chechnya.conf.work') {
        return 1;
    } elsif (@_[0] eq 'chello.nl') {
        return 1;
    } elsif (@_[0] eq 'cyber-innovation.club') {
        return 1;
    } elsif (@_[0] eq 'dnsmadeeasy.com') {
        return 1;
    } elsif (@_[0] eq 'e-mail.cz') {
        return 1;
    } elsif (@_[0] eq 'email.it') {
        return 1;
    } elsif (@_[0] eq 'eml.pp.ua') {
        return 1;
    } elsif (@_[0] eq 'executivemail.co.za') {
        return 1;
    } elsif (@_[0] eq 'fastservice.com') {
        return 1;
    } elsif (@_[0] eq 'gazeta.pl') {
        return 1;
    } elsif (@_[0] eq 'hotmail.com.ar') {
        return 1;
    } elsif (@_[0] eq 'hotmail.es') {
        return 1;
    } elsif (@_[0] eq 'index.ua') {
        return 1;
    } elsif (@_[0] eq 'iqemail.com') {
        return 1;
    } elsif (@_[0] eq 'jippii.fi') {
        return 1;
    } elsif (@_[0] eq 'live.com.mx') {
        return 1;
    } elsif (@_[0] eq 'live.dk') {
        return 1;
    } elsif (@_[0] eq 'mail2007.com') {
        return 1;
    } elsif (@_[0] eq 'mail2allen.com') {
        return 1;
    } elsif (@_[0] eq 'mail2amber.com') {
        return 1;
    } elsif (@_[0] eq 'mail2anesthesiologist.com') {
        return 1;
    } elsif (@_[0] eq 'mail2arabia.com') {
        return 1;
    } elsif (@_[0] eq 'mail2bank.com') {
        return 1;
    } elsif (@_[0] eq 'mail2beauty.com') {
        return 1;
    } elsif (@_[0] eq 'mail2bill.com') {
        return 1;
    } elsif (@_[0] eq 'mail2bob.com') {
        return 1;
    } elsif (@_[0] eq 'mail2bryan.com') {
        return 1;
    } elsif (@_[0] eq 'mail2cancer.com') {
        return 1;
    } elsif (@_[0] eq 'mail2care.com') {
        return 1;
    } elsif (@_[0] eq 'mail2chocolate.com') {
        return 1;
    } elsif (@_[0] eq 'mail2consultant.com') {
        return 1;
    } elsif (@_[0] eq 'mail2cowgirl.com') {
        return 1;
    } elsif (@_[0] eq 'mail2cutey.com') {
        return 1;
    } elsif (@_[0] eq 'mail2dad.com') {
        return 1;
    } elsif (@_[0] eq 'mail2dancer.com') {
        return 1;
    } elsif (@_[0] eq 'mail2darren.com') {
        return 1;
    } elsif (@_[0] eq 'mail2dude.com') {
        return 1;
    } elsif (@_[0] eq 'mail2fashion.com') {
        return 1;
    } elsif (@_[0] eq 'mail2florida.com') {
        return 1;
    } elsif (@_[0] eq 'mail2grandma.com') {
        return 1;
    } elsif (@_[0] eq 'mail2grant.com') {
        return 1;
    } elsif (@_[0] eq 'mail2harry.com') {
        return 1;
    } elsif (@_[0] eq 'mail2jail.com') {
        return 1;
    } elsif (@_[0] eq 'mail2jazz.com') {
        return 1;
    } elsif (@_[0] eq 'mail2john.com') {
        return 1;
    } elsif (@_[0] eq 'mail2leone.com') {
        return 1;
    } elsif (@_[0] eq 'mail2lloyd.com') {
        return 1;
    } elsif (@_[0] eq 'mail2mars.com') {
        return 1;
    } elsif (@_[0] eq 'mail2matt.com') {
        return 1;
    } elsif (@_[0] eq 'mail2nick.com') {
        return 1;
    } elsif (@_[0] eq 'mail2paris.com') {
        return 1;
    } elsif (@_[0] eq 'mail2philippines.com') {
        return 1;
    } elsif (@_[0] eq 'mail2pickup.com') {
        return 1;
    } elsif (@_[0] eq 'mail2pop.com') {
        return 1;
    } elsif (@_[0] eq 'mail2qatar.com') {
        return 1;
    } elsif (@_[0] eq 'mail2rage.com') {
        return 1;
    } elsif (@_[0] eq 'mail2rebecca.com') {
        return 1;
    } elsif (@_[0] eq 'mail2roy.com') {
        return 1;
    } elsif (@_[0] eq 'mail2runner.com') {
        return 1;
    } elsif (@_[0] eq 'mail2scientist.com') {
        return 1;
    } elsif (@_[0] eq 'mail2seth.com') {
        return 1;
    } elsif (@_[0] eq 'mail2sexy.com') {
        return 1;
    } elsif (@_[0] eq 'mail2smile.com') {
        return 1;
    } elsif (@_[0] eq 'mail2song.com') {
        return 1;
    } elsif (@_[0] eq 'mail2strong.com') {
        return 1;
    } elsif (@_[0] eq 'mail2tango.com') {
        return 1;
    } elsif (@_[0] eq 'mail2tycoon.com') {
        return 1;
    } elsif (@_[0] eq 'mail2webtop.com') {
        return 1;
    } elsif (@_[0] eq 'mailed.ro') {
        return 1;
    } elsif (@_[0] eq 'mailproxsy.com') {
        return 1;
    } elsif (@_[0] eq 'mynet.com') {
        return 1;
    } elsif (@_[0] eq 'neo.rr.com') {
        return 1;
    } elsif (@_[0] eq 'netcmail.com') {
        return 1;
    } elsif (@_[0] eq 'opoczta.pl') {
        return 1;
    } elsif (@_[0] eq 'optonline.net') {
        return 1;
    } elsif (@_[0] eq 'outlook.cl') {
        return 1;
    } elsif (@_[0] eq 'outlook.in') {
        return 1;
    } elsif (@_[0] eq 'parrot.com') {
        return 1;
    } elsif (@_[0] eq 'pop.com.br') {
        return 1;
    } elsif (@_[0] eq 'prodigy.net') {
        return 1;
    } elsif (@_[0] eq 'r7.com') {
        return 1;
    } elsif (@_[0] eq 'rambler.ua') {
        return 1;
    } elsif (@_[0] eq 'roadrunner.com') {
        return 1;
    } elsif (@_[0] eq 'shitmail.org') {
        return 1;
    } elsif (@_[0] eq 'sify.com') {
        return 1;
    } elsif (@_[0] eq 'soldier.hu') {
        return 1;
    } elsif (@_[0] eq 'techemail.com') {
        return 1;
    } elsif (@_[0] eq 'telefonica.net') {
        return 1;
    } elsif (@_[0] eq 'thai.com') {
        return 1;
    } elsif (@_[0] eq 'w3.to') {
        return 1;
    } elsif (@_[0] eq 'wavetec.com.br') {
        return 1;
    } elsif (@_[0] eq 'wooow.it') {
        return 1;
    } elsif (@_[0] eq 'workmail.com') {
        return 1;
    } elsif (@_[0] eq 'yahoo.com.my') {
        return 1;
    } elsif (@_[0] eq 'yahoo.no') {
        return 1;
    } elsif (@_[0] eq 'yahoo.se') {
        return 1;
    } elsif (@_[0] eq '21cn.com') {
        return 1;
    } elsif (@_[0] eq 'address.com') {
        return 1;
    } elsif (@_[0] eq 'aon.at') {
        return 1;
    } elsif (@_[0] eq 'bigboss.cz') {
        return 1;
    } elsif (@_[0] eq 'bigpond.net.au') {
        return 1;
    } elsif (@_[0] eq 'c3.hu') {
        return 1;
    } elsif (@_[0] eq 'centrum.cz') {
        return 1;
    } elsif (@_[0] eq 'china.com') {
        return 1;
    } elsif (@_[0] eq 'compuserve.com') {
        return 1;
    } elsif (@_[0] eq 'contractor.net') {
        return 1;
    } elsif (@_[0] eq 'cox.com') {
        return 1;
    } elsif (@_[0] eq 'cyberleports.com') {
        return 1;
    } elsif (@_[0] eq 'dbmail.com') {
        return 1;
    } elsif (@_[0] eq 'eircom.net') {
        return 1;
    } elsif (@_[0] eq 'fastmail.co.uk') {
        return 1;
    } elsif (@_[0] eq 'fastmail.net') {
        return 1;
    } elsif (@_[0] eq 'fibertel.com.ar') {
        return 1;
    } elsif (@_[0] eq 'freesurf.fr') {
        return 1;
    } elsif (@_[0] eq 'gencmail.com') {
        return 1;
    } elsif (@_[0] eq 'hello.to') {
        return 1;
    } elsif (@_[0] eq 'homemail.co.za') {
        return 1;
    } elsif (@_[0] eq 'homemail.com') {
        return 1;
    } elsif (@_[0] eq 'interlap.com.ar') {
        return 1;
    } elsif (@_[0] eq 'internode.on.net') {
        return 1;
    } elsif (@_[0] eq 'ixp.net') {
        return 1;
    } elsif (@_[0] eq 'jazzandjava.com') {
        return 1;
    } elsif (@_[0] eq 'jubii.dk') {
        return 1;
    } elsif (@_[0] eq 'latinmail.com') {
        return 1;
    } elsif (@_[0] eq 'live.cl') {
        return 1;
    } elsif (@_[0] eq 'live.com.au') {
        return 1;
    } elsif (@_[0] eq 'live.com.pt') {
        return 1;
    } elsif (@_[0] eq 'live.ie') {
        return 1;
    } elsif (@_[0] eq 'live.se') {
        return 1;
    } elsif (@_[0] eq 'lycos.com') {
        return 1;
    } elsif (@_[0] eq 'mail.com.tr') {
        return 1;
    } elsif (@_[0] eq 'mail.de') {
        return 1;
    } elsif (@_[0] eq 'mail.yahoo.co.jp') {
        return 1;
    } elsif (@_[0] eq 'me.by') {
        return 1;
    } elsif (@_[0] eq 'myway.com') {
        return 1;
    } elsif (@_[0] eq 'narod.ru') {
        return 1;
    } elsif (@_[0] eq 'onenet.com.ar') {
        return 1;
    } elsif (@_[0] eq 'orthodontist.net') {
        return 1;
    } elsif (@_[0] eq 'pacbell.net') {
        return 1;
    } elsif (@_[0] eq 'peoplepc.com') {
        return 1;
    } elsif (@_[0] eq 'post.cz') {
        return 1;
    } elsif (@_[0] eq 'priest.com') {
        return 1;
    } elsif (@_[0] eq 'radicalz.com') {
        return 1;
    } elsif (@_[0] eq 'representative.com') {
        return 1;
    } elsif (@_[0] eq 'rhyta.com') {
        return 1;
    } elsif (@_[0] eq 'rline.com.br') {
        return 1;
    } elsif (@_[0] eq 'runbox.com') {
        return 1;
    } elsif (@_[0] eq 'saigonnet.vn') {
        return 1;
    } elsif (@_[0] eq 'seguros.com.br') {
        return 1;
    } elsif (@_[0] eq 'skynet.be') {
        return 1;
    } elsif (@_[0] eq 'sonnenkinder.org') {
        return 1;
    } elsif (@_[0] eq 'starmedia.com') {
        return 1;
    } elsif (@_[0] eq 'start.no') {
        return 1;
    } elsif (@_[0] eq 'swbell.net') {
        return 1;
    } elsif (@_[0] eq 'telegraf.by') {
        return 1;
    } elsif (@_[0] eq 'tempymail.com') {
        return 1;
    } elsif (@_[0] eq 'vodamail.co.za') {
        return 1;
    } elsif (@_[0] eq 'voila.fr') {
        return 1;
    } elsif (@_[0] eq 'walla.com') {
        return 1;
    } elsif (@_[0] eq 'wazabi.club') {
        return 1;
    } elsif (@_[0] eq 'workmail.co.za') {
        return 1;
    } elsif (@_[0] eq 'xs4all.nl') {
        return 1;
    } elsif (@_[0] eq 'y7mail.com') {
        return 1;
    } elsif (@_[0] eq 'yahoo.com.mx') {
        return 1;
    } elsif (@_[0] eq 'yahoo.com.vn') {
        return 1;
    } elsif (@_[0] eq 'yahoo.in') {
        return 1;
    } elsif (@_[0] eq 'yandex.ua') {
        return 1;
    } elsif (@_[0] eq 'zednet.co.uk') {
        return 1;
    } elsif (@_[0] eq 'zworg.com') {
        return 1;
    } else {
        return 0;
    }
}
