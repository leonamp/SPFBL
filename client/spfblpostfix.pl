#!/usr/bin/env perl

# Este é um script que processa o SPFBL dentro do Postfix.
#
# Atenção! Para utilizar este serviço, solicite a liberação das consultas
# no servidor matrix.spfbl.net através do endereço leandro@spfbl.net
# ou altere o matrix.spfbl.net deste script para seu servidor SPFBL próprio.
#
# Se a mensagem não estiver listada, o cabeçalho Received-SPFBL
# será adicionado com o resultado do SPFBL.
#
# Para implementar este script no Postfix,
# salve este arquivo em: /etc/postfix/
#
# Adicione em: /etc/postfix/master.cf
#
# policy-spfbl  unix  -       n       n       -       -       spawn
#	user=nobody argv=/usr/bin/perl /etc/postfix/spfblpostfix.pl
#
# Altere ou adicione em: /etc/postfix/main.cf
#
# smtpd_recipient_restrictions =
#	permit_mynetworks,
#	permit_sasl_authenticated,
#	permit_tls_clientcerts,
#	reject_unknown_client_hostname,
#	reject_unknown_reverse_client_hostname,
#	reject_non_fqdn_sender,
#	reject_non_fqdn_recipient,
#	reject_unknown_sender_domain,
#	reject_unknown_recipient_domain,
#	reject_invalid_hostname,
#	reject_non_fqdn_hostname,
#	reject_unauth_pipelining,
#	reject_unauth_destination,
#	check_policy_service unix:private/policy-spfbl,
#	permit
#
# Última alteração: 26/11/2016 16:45

use strict;
use warnings;

use IO::Socket::INET;

# auto-flush on socket
$| = 1;

# configs
my $CONFIG = {
    socket => {
        PeerHost => 'matrix.spfbl.net', # change to your hostname
        PeerPort => 9877,
        Proto    => 'tcp',
        Timeout  => 10,
    }
};

my $params = {};

# Captura os atributos do Postfix passados pelo STDIN.
# Associa os parâmetros SPFBL através dos atributos do Postfix.
while ( my $line = <STDIN> ) {
    chomp $line;

    if ( $line =~ /=/ ) {
        my ( $key, $value ) = split /=/, $line, 2;
        $params->{ $key } = $value;
        next;
    }

    # connecting
    my $socket = IO::Socket::INET->new( %{ $CONFIG->{socket} } )
       or die "action=WARN SPFBL NO CONNECTION\n\n";

    # build and send query
    my $query = "SPF '$params->{client_address}' '$params->{sender}' '$params->{helo_name}' '$params->{recipient}'\n";
    $socket->send($query);

    shutdown $socket, 1;

    my $result = 'TIMEOUT';
    $socket->recv( $result, 4096 );
    $socket->close();
    $result =~ s/\s+$//;

    STDOUT->autoflush(1);

    # parse the result
    if ( $result =~ /^LISTED / ) {
        STDOUT->print(
            "action=451 4.7.2 SPFBL $result\n\n"
        );
    }
    elsif ( $result =~ /^LISTED/ ) {
        STDOUT->print(
            "action=451 4.7.2 SPFBL you are temporarily blocked on this server. See http://spfbl.net/en/feedback\n\n"
        );
    }
    elsif ( $result =~ /^FLAG/ ) {
        STDOUT->print(
            "action=PREPEND X-Spam-Flag: YES\n\n"
        );
    }
    elsif ( $result =~ /^HOLD/ ) {
        STDOUT->print(
            "action=HOLD\n\n"
        );
    }
    elsif ( $result =~ /^NXDOMAIN/ ) {
        STDOUT->print(
            "action=554 5.7.1 SPFBL sender has non-existent internet domain. See http://spfbl.net/en/feedback\n\n"
        );
    }
    elsif ( $result =~ /^BLOCKED / ) {
        STDOUT->print(
            "action=554 5.7.1 SPFBL $result\n\n"
        );
    }
    elsif ( $result =~ /^BLOCKED/ ) {
        STDOUT->print(
            "action=554 5.7.1 SPFBL you are permanently blocked in this server. See http://spfbl.net/en/feedback\n\n"
        );
    }
    elsif ( $result =~ /^INVALID/ ) {
        STDOUT->print(
            "action=554 5.7.1 SPFBL hostname and sender are both invalids. See http://spfbl.net/en/feedback\n\n"
        );
    }
    elsif ( $result =~ /^INVALID / ) {
        STDOUT->print(
            "action=WARN SPFBL $result\n\n"
        );
    }
    elsif ( $result =~ /^LAN/ ) {
        STDOUT->print(
            "action=DUNNO\n\n"
        );
    }
    elsif ( $result =~ /^GREYLIST/ ) {
        STDOUT->print(
            "action=451 4.7.1 SPFBL you are greylisted on this server. See http://spfbl.net/en/feedback\n\n"
        );
    }
    elsif ( $result =~ /^SPAMTRAP/ ) {
        STDOUT->print(
            "action=DISCARD SPFBL discarded by spamtrap.\n\n"
        );
    }
    elsif ( $result =~ /^ERROR: INVALID SENDER/ ) {
        STDOUT->print(
            "action=554 5.7.1 SPFBL $params->{sender} is not a valid e-mail address. See http://spfbl.net/en/feedback\n\n"
        );
    }
    elsif ( $result =~ /^TIMEOUT/ ) {
        STDOUT->print(
            "action=DEFER [SPF] A transient error occurred when checking SPF record. Try again later.\n\n"
        );
    }
    elsif ( $result =~ /^ERROR: QUERY/ ) {
        STDOUT->print(
            "action=WARN SPFBL INVALID QUERY\n\n"
        );
    }
    elsif ( $result =~ /^ERROR: / ) {
        STDOUT->print(
             "action=WARN SPFBL $result\n\n"
        );
    }
    elsif ( $result =~ /^NONE / ) {
        STDOUT->print(
             "action=PREPEND Received-SPFBL: $result\n\n"
        );
    }
    elsif ( $result =~ /^PASS / ) {
        STDOUT->print(
             "action=PREPEND Received-SPFBL: $result\n\n"
        );
    }
    elsif ( $result =~ /^WHITE / ) {
        STDOUT->print(
             "action=PREPEND Received-SPFBL: $result\n\n"
        );
    }
    elsif ( $result =~ /^FAIL / ) {
        # retornou FAIL com ticket.
        STDOUT->print(
             "action=PREPEND Received-SPFBL: $result\n\n"
        );
    }
    elsif ( $result =~ /^FAIL/ ) {
        STDOUT->print(
             "action=554 5.7.1 SPFBL message rejected due to receiver policy for SPF fail. Please see http://www.openspf.net/Why?s=mfrom;id=$params->{sender};ip=$params->{client_address}\n\n"
        );
    }
    elsif ( $result =~ /^SOFTFAIL / ) {
        STDOUT->print(
             "action=PREPEND Received-SPFBL: $result\n\n"
        );
    }
    elsif ( $result =~ /^NEUTRAL / ) {
        STDOUT->print(
             "action=PREPEND Received-SPFBL: $result\n\n"
        );
    }
    elsif ( $result =~ /^INEXISTENT/ ) {
        STDOUT->print(
             "action=550 5.1.1 SPFBL unknown user in virtual mailbox table. See http://spfbl.net/en/feedback\n\n"
        );
    }
    elsif ( $result =~ /^INEXISTENT / ) {
        STDOUT->print(
             "action=550 5.1.1 SPFBL unknown user in virtual mailbox table. See http://spfbl.net/en/feedback\n\n"
        );
    }
    else {
        STDOUT->print(
            "action=WARN SPFBL UNKNOWN ERROR\n\n"
        );
    }
}
