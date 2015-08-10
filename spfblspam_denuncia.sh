#!/bin/bash
# Este é um script que faz a reclamação de SPAM ao serviço SPFBL de forma recursiva.
#
# Atenção! Para utilizar este script, é nessesario que o mesmo esteja na mesm apasta onde se encontra o 
# script spfblspam.sh
#
# Este programa procura e extrai o ticket de consulta SPFBL de uma mensagem de e-mail se o parâmetro for um arquivo.
#
# Com posse do ticket, ele envia a reclamação ao serviço SPFBL para contabilização de reclamação.


for i in `find /var/vmail/vmail1/ -iname .Junk`; do

for x in `ls $i/cur`; do

./spfblspam.sh "$i/cur/$x"

done
done
