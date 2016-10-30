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

sub geturldomainlist {

    my $mime_filename = Exim::expand_string('$mime_decoded_filename');

    my $tree = HTML::TreeBuilder->new;
    $tree->parse_file($mime_filename);

    my $list = "";

    for my $element ($tree->look_down(_tag => "a", href => qr/./)) {
        my $href = lc($element->attr("href"));
        
        if($href =~ m/^https?:\/\//) {
            my $url = URI->new($href);
            $href = $url->host;
        } elsif ($href =~ m/^mailto:([^?]*)/) {
            my $email = $1;
            if ($email =~ m/<(.+)>/) {
                $email = $1;
            }
            if (Email::Valid->address($email)) {
                $href = $email;
            } else {
                $href = "";
            }
        } else {
            $href = "";
        }

        if ($href ne "") {
            if ($list eq "") {
                $list = "$href";
            } elsif (index($list, $href) == -1) {
                $list = "$list $href";
            }
        }
    }

    return $list;
}

