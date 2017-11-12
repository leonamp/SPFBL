# Extract URL domain list in Exim.
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
# Projeto SPFBL - Copyright Leandro Carlos Rodrigues - leandro@spfbl.net
# https://github.com/leonamp/SPFBL

use strict;
use URI;
use HTML::TreeBuilder;
use Email::Valid;
use Set::Scalar;
use LWP::UserAgent;
use HTTP::Request;
use Data::Validate::URI;

sub geturldomainlist {

    my $mime_filename = Exim::expand_string('$acl_c_mime_decoded_filename');

    my $hrefset = new Set::Scalar->new;

    my $tree = HTML::TreeBuilder->new;
    $tree->parse_file($mime_filename);

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
    
    my $list = "";
    
    if ($hrefset) {

        my $validator = Data::Validate::URI->new();
        
        my $ua = LWP::UserAgent->new(keep_alive => 0, timeout => 3);
        $ua->requests_redirectable(['HEAD']);

        for my $href ($hrefset->elements) {

            if ($href =~ m/^https?:\/\//) {

                my $response = $ua->get($href);

                while ($response->code == 301 || $response->code == 302) {
                
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
                    my $url = URI->new($href);
                    $href = $url->host;
                }
            }

            $href = lc($href);

            if ($href ne "") {
                if ($list eq "") {
                    $list = "$href";
                } elsif (index($list, $href) == -1) {
                    $list = "$list $href";
                }
            }
        }
    }

    return $list;
}
