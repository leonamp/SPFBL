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
# adicione as seguintes linhas no arquivo master.cf:
#
#    policy-spfbl  unix  -       n       n       -       -       spawn
#        user=nobody argv=/usr/bin/spfblquery.pl
#

use strict;
use warnings;

use IO::Socket::INET;

# auto-flush on socket
$| = 1;

# configs
my $CONFIG = {
    socket => {
        PeerHost => 'matrix.spfbl.net',
        PeerPort => 9877,
        Proto    => 'tcp',
        Timeout  => 5,
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
      or die "Can't connect to SPFBL server!\n";

    # build and send query
    my $query = "SPF '$params->{client_address}' '$params->{sender}' '$params->{helo_name}' '$params->{recipient}'\n";
    $socket->send($query);

    shutdown $socket, 1;

    my $result = '';
    $socket->recv( $result, 4096 );
    $socket->close();
    $result =~ s/\s+$//;

    STDOUT->autoflush(1);

    # parse the result
    if ( $result =~ /^LISTED/ ) {
        STDOUT->print(
            "action=DEFER [RBL] you are temporarily blocked on this server.\n\n"
        );
    }
    elsif ( $result =~ /^NXDOMAIN/ ) {
        STDOUT->print(
            "action=REJECT [RBL] sender has non-existent internet domain.\n\n"
        );
    }
    elsif ( $result =~ /^BLOCKED/ ) {
        STDOUT->print(
            "action=REJECT [RBL] you are permanently blocked in this server.\n\n"
        );
    }
    elsif ( $result =~ /^GREYLIST/ ) {
        STDOUT->print(
            "action=DEFER [RBL] you are greylisted on this server.\n\n"
        );
    }
    elsif ( $result =~ /^SPAMTRAP/ ) {
        STDOUT->print(
            "action=DISCARD [RBL] discarded by spamtrap.\n\n"
        );
    }
    elsif ( $result =~ /^ERROR: INVALID SENDER/ ) {
        STDOUT->print(
            "action=REJECT [RBL] $params->{sender} is not a valid e-mail address.\n\n"
        );
    }
    elsif ( $result =~ /^ERROR: HOST NOT FOUND/ ) {
        STDOUT->print(
            "action=DEFER [SPF] A transient error occurred when checking SPF record from $params->{sender}, preventing a result from being reached. Try again later.\n\n"
        );
    }
    elsif ( $result =~ /^ERROR: QUERY/ ) {
        STDOUT->print(
            "action=DEFER [SPF] A transient error occurred when checking SPF record from $params->{sender}, preventing a result from being reached. Try again later.\n\n"
        );
    }
    elsif ( $result =~ /^ERROR: / ) {
        STDOUT->print(
             "action=REJECT [SPF] One or more SPF records from $params->{sender} could not be interpreted. Please see http://www.openspf.org/SPF_Record_Syntax for details.\n\n"
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
    elsif ( $result =~ /^FAIL/ ) {
        STDOUT->print(
             "action=REJECT [SPF] $params->{sender} is not allowed to send mail from $params->{client_address}. Please see http://www.openspf.org/why.html?sender=$params->{sender}&ip=$params->{client_address} for details.\n\n"
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
    else {
        STDOUT->print(
            "action=DEFER [SPF] A transient error occurred when checking SPF record from $params->{sender}, preventing a result from being reached. Try again later.\n\n"
        );
    }
}

