#!/usr/bin/perl
#
# Query URIBL from a HTML file, a URL, a host, a IP or an e-mail at SPFBL.net.
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

use strict;
use URI;
use HTML::TreeBuilder;
use Email::Valid;
use Set::Scalar;
use LWP::UserAgent;
use HTTP::Request;
use Data::Validate::URI;
use Data::Validate::IP qw(is_ip is_ipv4 is_ipv6);
use Data::Validate::Domain qw(is_domain);
use Net::IP qw(ip_expand_address);
use Mail::RBL;
use URI::Escape;

my $hrefset = new Set::Scalar->new;

my $validator = Data::Validate::URI->new();
    
my $arg = $ARGV[0];

if ($validator->is_uri($arg)) {

    $hrefset->insert($arg);

} elsif (is_domain($arg)) {

    $hrefset->insert(lc($arg));

} elsif (is_ipv4($arg)) {

    $hrefset->insert($arg);

} elsif (is_ipv6($arg)) {

    $hrefset->insert(lc(ip_expand_address($arg, 6)));

} elsif (Email::Valid->address($arg)) {

    $hrefset->insert(lc($arg));

} elsif (-e $arg) {
    
    my $tree = HTML::TreeBuilder->new;
    $tree->parse_file($arg);
    
    for my $element ($tree->look_down(_tag => "a", href => qr/./)) {
    
        my $href = $element->attr("href");
    
        if($href =~ m/^https?:\/\//) {
            $hrefset->insert($href);
        } elsif ($href =~ m/^mailto:([^?]*)/) {
            my $email = $1;
            if ($email =~ m/<(.+)>/) {
                $email = $1;
            }
            if (Email::Valid->address($email)) {
                $hrefset->insert(lc($email));
            }
        }
    }

    if (!$hrefset) {

        print("No href tags in file.\n");
        exit 0;

    }
    
} else {

    print("Invalid query.\n");
    exit 0;
    
}

    my $queryset = new Set::Scalar->new;
    
    my $ua = LWP::UserAgent->new(keep_alive => 0, timeout => 3);
    $ua->requests_redirectable(['HEAD']);
    
    for my $href ($hrefset->elements) {
    
        if ($href =~ m/^https?:\/\//) {
    
            my $response = $ua->get($href);
            my $count = 0;
    
            while ($count++ < 8 && ($response->code == 301 || $response->code == 302)) {
            
                my $location = $response->header('Location');
                
                if ($location =~ m/^https?:\/\//) {
                    $href = $location;
                    $response = $ua->get($href);
                } elsif ($location =~ m/^mailto:([^?]*)/) {
                    my $email = $1;
                    if ($email =~ m/<(.+)>/) {
                        $email = $1;
                    }
                    if (Email::Valid->address($email)) {
                        $href = $email;
                    }
                    last;
                } else {
                    last;
                }
            }
    
            if ($validator->is_uri($href)) {
            
                if ($response->code == 200) {
                
                    eval {
                        my $tree = HTML::TreeBuilder->new_from_url($href);
                    
                        for my $iframe ($tree->look_down(_tag => "iframe")) {
                            my $onload = $iframe->attr("onload");
                            if ($onload =~ m/^top.location=/) {
                                $onload =~ s/\\\//\//g;
                                while($onload =~ m/\btop\.location *= *' *(https?\:\/\/[^\s]+[\/\w]) *'/g) {
                                    if ($validator->is_uri($1)) {
                                        $href = $1;
                                        last;
                                    }
                                }
                            }
                        }
                    };
                }
                
                my $url = URI->new($href);
                $href = $url->host;
                
                if (is_ipv6($href)) {
                    $href = ip_expand_address($href, 6);
                }
            } elsif ($href =~ m/https?\:\/\/([^\/]+)/g) {
                $href = $1;
            }
        }
        
        $queryset->insert(lc($href));
    
    }

my $list = new Mail::RBL('uribl.spfbl.net');

for my $query ($queryset->elements) {
    if (is_ip($query)) {
        if ($list->check($query)) {
            print ("$query is listed in 'uribl.spfbl.net'.\n");
            exit 1;
        }
    } else {
        if ($list->check_rhsbl($query)) {
            print ("$query is listed in 'uribl.spfbl.net'.\n");
            exit 1;
        }
    }
}

if ($queryset) {
    print ("$queryset is not listed in 'uribl.spfbl.net'.\n");
} else {
    print ("No href tags in query.\n");
}

exit 0;
