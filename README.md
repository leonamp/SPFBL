# Serviço SPFBL

### Introdução

O serviço SPFBL é uma junção dos conceitos de SPF e DNSBL.

O propósito deste serviço é melhorar o processamento SPF e reduzir a quantidade de consultas externas de um servidor de e-mail, na qual utiliza SPF e pelo menos um serviço qualquer de DNSBL.

Uma vez iniciado o serviço, as consultas podem ser feitas por programas clientes, como por exemplo o script "spfbl.sh".

A listagem é realizada através do ticket SPFBL, que é enviado juntamente com o qualificador SPF da consulta:

```
user:~# ./spfbl.sh query "200.160.7.130" "gter-bounces@eng.registro.br" "eng.registro.br" "destinatario@destino.com.br"
PASS cPo6NAde1euHf6A2oT13sNlzCqnCH+PIuY/ClbDH2RJrV08UwvNblJPJiVo0E0SwAiO/lzSW+5BKdXXxDovqQPNqcfrvpBx5wPWgEC7EJ54=
```

Este ticket deve ser incluído no cabeçalho "Received-SPFBL" da mensagem para uma possível denúncia de SPAM futura.

Caso a mensagem seja considerada SPAM pelo usuário, a mensagem deve ser processada pelo comando "spfbl.sh spam", que vai extrair o ticket contido no campo "Received-SPFBL" e enviá-lo ao serviço SPFBL:

```
user:~# ./spfbl.sh spam <caminho da mensagem SPAM>
Reclamação SPFBL enviada com sucesso.
```

Cada denúncia expira em sete dias após a data de recebimento da mensagem e só pode ser denunciada até cinco dias após o recebimento.

Se houver interesse um utilizar este serviço sem implementá-lo em servidor próprio, podemos ceder nosso próprio servidor. Para isto, basta enviar para um e-mail para leandro@allchemistry.com.br com a lista de blocos de IP utilizados pelos seus terminais de consulta para liberação do firewall.

Se este projeto for útil para sua empresa, faça uma doação de qualquer valor para ajudar a mantê-lo:

![Donate](https://github.com/leonamp/SPFBL/blob/master/bicoin.png "1HVe5J3dziyEQ1BCDQamNWas6ruVHTyESy")

### Funcionalidades

Algumas alterações foram implementadas no SPFBL com a intenção de minimizar as respostas negativas ou incoerentes do SPF convencional.

##### Correção de sintaxe SPF

As vezes alguns administradores de DNS acabam cometendo erros pequenos ao registrar um SPF para um determinado domínio. O SPFBL é capaz de fazer algumas correções destes erros.

Por exemplo, o domínio "farmaciassaorafael.com.br", com o registro SPF "v=spf1 ipv4:177.10.167.165 -all", retorna falha no SPF convencional, mas o SPFBL reconhece um REGEX CIDR dentro de um token e deduz que o administrador queria dizer "ip4" invés de "ipv4".

Além disto, se um mecanismo não puder ser reconhecido pelo SPFBL, este mesmo mecanismo é apenas ignorado, dando chance de acontecer um match em outros mecanismos que são reconhecidos pelo SPFBL.

##### Merge de múltiplos registros SPF

Se o administrador registrar vários registros SPF para um determinado domínio, o SPFBL faz o merge de todos eles e considera como se fosse apenas um.

##### Mecanismos permissivos demais

O SPF convencional não permite o registro de alguns mecanismos que são permissivos demais ao ponto de retornar sempre PASS para qualquer parâmetro utilizado na consulta.

Um destes mecanismos é o +all, que no SPFBL foi abolido e substituido por ?all sempre que encontrado.

Os mecanismos de blocos de IP que contém algum endereço IP reservado são ignorados pelo SPFBL.

##### Consideração de IPv6 para mecanismo "mx" sem máscara

Sempre que o mecaninsmo "mx" for utilizado sem a máscara num registro SPF, o SPFBL irá considerar tanto IPv4 quanto IPv6 do host para manter compatibilidade de pilha dupla neste MX.

Quando a máscara for mencionada, então não é possível utilizar esta solução pois as máscaras de IPv4 e IPv6 são incompatáveis.

O protocolo SPF convencional não prevê pilha dupla em mecanismo "mx", então é possível que uma consulta SPF convencional não resulte em PASS sendo que a mesma consulta resulte PASS no SPFBL.

##### Domínios sem registro SPF

Quando um domínio não tem registro SPF, o SPFBL considera a recomendação "best-guess" do SPF: [best-guess](http://www.openspf.org/FAQ/Best_guess_record).

Porém mesmo considerando esta recomendação, alguns domínios que não tem registro SPF não funcionam bem com o "best-guess". Nestes casos é possível registrar um "best-guess" específico para um determinado domínio. Por exemplo, o domínio "yahoo.com.br" não tem registro SPF e costuma enviar os seus e-mails pelos servidores listados no registro SPF do domínio "yahoo.com". A solução para este problema é adicionar o "best-guess" "v=spf1 redirect=yahoo.com" para o domínio "yahoo.com.br".

##### Quantidade máxima de interações DNS

O SPF convencional tem um limitador que finaliza a busca quando ele atinge 10 interações de DNS. O motivo deste limitador é garantir que não haja loop infinito, porque a estrutura de dados do SPF é um grafo, e também para evitar respostas com alta latência. O problema deste limitador é que diversos administradores de domínio utilizam o mecanismo include no SPF para transferir a responsabilidade de configuração correta aos administradores de servidores de e-mail e as vezes estes últimos abusam do mecanismo include, gerando um grafo grande demais.

O SPFBL não trabalha com grafo e sim com árvore. Isso é feito ignorando os nós já processados anteriormente.

O SPFBL não tem o limitador de 10 interações de DNS do SPF convencional porque além de trabalhar com estrutura em árvore utiliza cache de registros SPF, que agiliza o processamento. A única limitação que existe é a limitação de nós abaixo de 10 níveis na árvore, que seria um absurdo atingir este limite. Estes nós abaixo de 10 níveis são então apenas ignorados, uma poda de árvore, e atingir este limite não é considerado uma falha de SPF. Isto faz com que as falhas por limite sejam extintas no SPFBL.

Se a árvore for grande demais para ser percorrida e não houver registros desta árvore em cache, pode acontecer do cliente SPFBL considerar o timeout, fechar a conexão e gerar um erro temporário para o servidor da origem. Se acontecer isto, o SPFBL continua a varredura da árvore em background, mesmo com a conexão fechada, e quando a mesma consulta for realizada novamente, a resposta do SPFBL será imediata porque a árvore já estará toda em cache.

##### Cache dos registros SPF

O SPFBL mantém em cache todos os registros SPF encontrados e procura mantê-los atualizados em background de acordo com o volume de consultas de cada um deles.

##### Registro de provedores de e-mail

É possível registrar um provedor de e-mail no SPFBL. Sempre que um provedor for registrado, o SPFBL vai considerar os respectivos endereços de e-mail como responsável pelo envio, sendo que o provedor será isentado da responsabilidade.

##### Denúncia de SPAM

Quando o resultado da consulta SPFBL retorna um ticket, dentro dele segue informações sobre o responsável pelo envio e a data que a consulta foi realizada. Este ticket pode ser utilizado para formalizar uma denúncia, que contabiliza para o responsável o peso de denúncia. Cada denúncia expira em sete dias após a data da consulta e não pode ser feita após cinco dias da consulta.

##### Bloqueio permanente de remetentes

É possível bloquear remetentes permanentemente através da alteração de uma lista arbitrária onde o SPFBL realiza a denúncia automática e manda o MTA rejeitar a mensagem.

As opções de bloqueio são:

* Caixa postal: apenas a parte que antecede o arroba.
* Domínio: apenas a parte que precede o arroba.
* Remetente: o endereço completo do remetente.

Para visualizar a lista de bloqueios arbitrários:
```
user:~# ./spfbl.sh block show
EMPTY
```

Para adicionar um bloqueio arbitrário:
```
user:~# ./spfbl.sh block add <remetente>
ADDED
```

Para remover um bloqueio arbitrário:
```
user:~# ./spfbl.sh block drop <remetente>
DROPED
```

Os elementos que podem ser adicionados nesta lista são:
* .tld
* .domain.ltd
* .sub.domain.tld
* @domain.tld[;&lt;qualifier&gt;]
* @sub.domain.tld[;&lt;qualifier&gt;]
* sender@[;&lt;qualifier&gt;]
* sender@domain.tld[;&lt;qualifier&gt;]
* IPv4
* IPv6
* CIDRv4
* CIDRv6
* CNPJ
* CPF
* WHOIS/&lt;field&gt;[/&lt;field&gt;...]=&lt;value&gt;

Esta possibilidade de colocar um qualificador, significa que o bloqueio só será feito se o resultado SPF resultar neste qualificador. Exemplo: "@gmail.com;SOFFAIL" bloqueia qualquer tentativa de envio com remetente *@gmail.com e o SPF deu SOFTFAIL.

No caso do bloqueio por WHOIS, é possível definir criterios onde o domínio do remetente (somente .br) será consultado e a navegação pela estrutura de dados é feita pelo caracter "/". Exemplo: "WHOIS/owner-c=EJCGU" bloqueia todos os remetentes cujo domínio tenha no WHOIS o campo "owner-c" igual à "EJCGU".

##### Spamtrap

É possível adicionar destinatários na lista spamtrap do SPFBL.

Sempre que o destinatário de uma consulta está na lista spamtrap, o SPFBL realiza a denúncia automática e manda o MTA descartar silencionsamente a mensagem.

Para visualizar a lista de spamtrap:
```
user:~# ./spfbl.sh trap show
EMPTY
```

Para adicionar um spamtrap:
```
user:~# ./spfbl.sh trap add <destinatário>
ADDED
```

Para remover um spamtrap:
```
user:~# ./spfbl.sh trap drop <destinatário>
DROPED
```

Os elementos que podem ser adicionados nesta lista são:
* .tld
* .domain.ltd
* .sub.domain.tld
* @domain.tld
* @sub.domain.tld
* recipient@domain.tld

##### Whitelist

É possível adicionar remetentes na lista branca.

Para visualizar a lista branca:
```
user:~# ./spfbl.sh white show
EMPTY
```

Para adicionar um remetente:
```
user:~# ./spfbl.sh white add <remetente>
ADDED
```

Para remover um remetente:
```
user:~# ./spfbl.sh white drop <remetente>
DROPED
```

Os elementos que podem ser adicionados nesta lista são:
* .tld
* .domain.ltd
* .sub.domain.tld
* @domain.tld[;&lt;qualifier&gt;]
* @sub.domain.tld[;&lt;qualifier&gt;]
* sender@[;&lt;qualifier&gt;]
* sender@domain.tld\[;&lt;qualifier&gt;]
* IPv4
* IPv6
* CIDRv4
* CIDRv6
* CNPJ
* CPF

Quando o SPF retorna FAIL, o fluxo SPFBL rejeita imediatamente a mensagem pois isso é um padrão SPF. Porém existem alguns casos específicos onde o administrador do domínio do remetente utiliza "-all" e não coloca todos os IPs de envio, resultando em falso FAIL. Neste caso, é possível resolver o problema, sem depender do tal administrador, adicionado o token "@domain.tld;FAIL" nesta lista. Esta lista é á única lista que aceita FAIL como qualificador. O SPFBL ignora o resultado FAIL para o domínio específico quando usado. Atenção! Este comando deve ser evitado! O correto é pedir ao administrador do domínio corrigir a falha no registro SPF dele usando este comando somente durante o intervalo onde o problema está sendo corrigido.

##### Greylisting

A mensagem será atrasada 25min sempre que o responsável estiver com status GRAY.

##### Listed

A mensagem será atrasada 1 dia sempre que o responsável estiver com status BLACK.

### Funcionamento

A seguir é mostrado como o SPFBL funciona internamente.

##### Respostas SPFBL

O SPFBL retorna todos os qualificadores do SPF convencional mais quatro qualificadores novos, chamados LISTED, BLOCKED, SPAMTRAP e GREYLIST:

* PASS &lt;ticket&gt;: permite o recebimento da mensagem.
* FAIL: rejeita o recebimento da mensagem e informa à origem o descumprimento do SPF.
* SOFTFAIL &lt;ticket&gt;: permite o recebimento da mensagem mas marca como suspeita.
* NEUTRAL &lt;ticket&gt;: permite o recebimento da mensagem.
* NONE &lt;ticket&gt;: permite o recebimento da mensagem.
* LISTED: atrasa o recebimento da mensagem e informa à origem a listagem temporária em blacklist.
* BLOCKED: rejeita o recebimento da mensagem e informa à origem o bloqueio permanente.
* SPAMTRAP: descarta silenciosamente a mensagem e informa à origem que a mensagem foi recebida com sucesso.
* GREYLIST: atrasar a mensagem informando à origem ele está em greylisting.

##### Método de listagem

O SPFBL mantém uma flag para cada responsável. Esta flag tem quatro estados: WHITE, GRAY, BLACK e BLOCK. A seguinte máquina de estado é utlizada para manipular estas flags, sendo Pmin e Pmax probabilidades mínima e máxima da mensagem ser SPAM:

![flagFSM.png](https://github.com/leonamp/SPFBL/blob/master/flagFSM.png "flagFSM.png")

Quando a flag estiver no estado BLACK para o responsável, então o SPFBL retorna LISTED.

Quando a flag passar para o estado BLOCK, o responsável é colocado em bloqueio permanente, retornando BLOCKED. Esta transição é utilizada para disseminar a lista de bloqueio entre pools via P2P. Deve haver concenso total dentro do mesmo pool para passar a diante o bloqueio para outros pools associados.

##### Fluxo do SPFBL

O SPFBL utiliza deste fluxo para determinar responsável pelo envio da mensagem e qual ação o MX deve tomar:

![flowchartSPFBL](https://github.com/leonamp/SPFBL/blob/master/flowchartSPFBL.png "flowchartSPFBL.png")

##### Tipos de responsável

Sempre que o qualificador do SPFBL for PASS, o responsável considerado é o próprio remetente ou o domínio do remetente. Será considerado o remetente se o domínio dele estiver registrado no SPFBL como provedor de e-mail, como por exemplo: @hotmail.com, @gmail.com, @yahoo.com, etc. Caso contrário, o responsável é o domínio do remetente, mais o CNPJ ou CPF deste domínio quando este for da TLD BR.

Quando o qualificador for diferente de PASS, então o responsável considerado é o HELO ou o IP. Será considerado o HELO, com domínio e CNPJ ou CPF, se este for o reverso válido do IP. Caso contrário, o responsável é o IP.

Responsabilizar o HELO, quando um hostname for válido e aponta para o IP, é motivado pela seguinte ideia: se um hostname tiver funcionando em pilha dupla, então haveria duas listagens distintas, uma para o IPv4 e outra para o IPv6. Listar o HELO resolve este problema pois não importa por qual versão de IP o host envie mensagens, ele será visto pelo SPFBL como uma única entidade.

##### Checagem SPFBL

É possível fazer uma consulta de checagem SPFBL. Este tipo de consulta não retorna ticket, mas mostra todos os responsáveis considerados pelo SPFBL, de modo que o administrador possa entender melhor a resposta de uma consulta normal SPFBL.

```
user:~# ./spfbl.sh check 191.243.197.31 op4o@adsensum.com.br smtp-197-31.adsensum.com.br
PASS
.adsensum.com.br 2656±1218s GRAY 0.061
013.566.954/0001-08 2831±714s BLACK 0.108
@adsensum.com.br 2656±1218s GRAY 0.061
```

Na primeira linha, temos o qualificador SPF convencional. Nas demais linhas, temos a sequência dos responsáveis pelo envio na mensagem, sendo que a primeira coluna é o token do responsável, a segunda coluna é a frequência de envio em segundos, a terceira é a flag de listagem e a quarta coluna é a probabilidade daquele responsável enviar SPAM.

##### Integração nativa Postfix

O SPFBL tem integração nativa com o Postfix. Para utilizar o serviço SPFBL pelo Postfix, basta adicionar a seguinte linha no arquivo main.cf:
```
check_policy_service inet:<IP do servidor SPFBL>:9877
```

##### Integração nativa Zimbra

O SPFBL tem integração nativa com o Zimbra.

Para utilizar o serviço SPFBL pelo Zimbra 8.5.x, basta adicionar a seguinte linha no arquivo "/opt/zimbra/conf/postfix_recipient_restrictions.cf":
```
check_policy_service inet:<IP do servidor SPFBL>:9877
```

Para utilizar o serviço SPFBL pelo Zimbra 8.6.x, basta adicionar a seguinte linha no arquivo "/opt/zimbra/conf/zmconfigd/smtpd_recipient_restrictions.cf":
```
check_policy_service inet:<IP do servidor SPFBL>:9877
```

Após adicionar a linha, renicie o serviço:
```
zmconfigdctl restart
zmmtactl stop
zmmtactl start
```

##### Integração com Exim

Para integrar o SPFBL no Exim, basta adicionar a seguinte linha na secção "acl_check_rcpt":
```
# Use 'spfbl.sh query' to perform SPFBL check.
  drop
    message = Invalid MAIL FROM address. Use a valid e-mail address.
    log_message = invalid sender.
    condition = ${if match {$sender_address}{^([[:alnum:]][[:alnum:].+_=-]*)@([[:alnum:]_-]+\\.)+(biz|com|edu|gov|info|int|jus|mil|net|org|pro|[[:alpha:]]\{2\})\$}{false}{true}}
    condition = ${if match {$sender_address}{^SRS0(=|\\+)[[:alnum:]/+]+=[[:alnum:]]+=(([[:alnum:]_-]+\\.)+(biz|com|edu|gov|info|int|jus|mil|net|org|pro|[[:alpha:]]\{2\}))=([[:alnum:]][[:alnum:]._-]*)@(([[:alnum:]_-]+\\.)+(biz|com|edu|gov|info|int|jus|mil|net|org|pro|[[:alpha:]]\{2\}))\$}{false}{true}}
    condition = ${if match {$sender_address}{^prvs=[[:alnum:]]+=([[:alnum:]][[:alnum:]._-]*)@(([[:alnum:]_-]+\\.)+(biz|com|edu|gov|info|int|jus|mil|net|org|pro|[[:alpha:]]\{2\}))\$}{false}{true}}
  warn
    set acl_c_spfbl = ${run{/etc/spfbl/spfbl.sh query "$sender_host_address" "$sender_address" "$sender_helo_name" "$local_part@$domain"}{ERROR}{$value}}
    set acl_c_spfreceived = $runrc
    set acl_c_spfblticket = ${sg{$acl_c_spfbl}{(PASS |SOFTFAIL |NEUTRAL |NONE |FAIL )}{}}
  drop
    message = [SPF] $sender_host_address is not allowed to send mail from $sender_address. Please see http://www.openspf.org/why.html?sender=$sender_address&ip=$sender_host_address for details.
    log_message = [SPFBL] failed.
    condition = ${if eq {$acl_c_spfreceived}{3}{true}{false}}
  defer
    message = [SPF] A transient error occurred when checking SPF record from $sender_address, preventing a result from being reached. Try again later.
    log_message = [SPFBL] error.
    condition = ${if eq {$acl_c_spfreceived}{6}{true}{false}}
  deny
    message = [SPF] One or more SPF records from $sender_address_domain could not be interpreted. Please see http://www.openspf.org/SPF_Record_Syntax for details.
    log_message = [SPFBL] unknown.
    condition = ${if eq {$acl_c_spfreceived}{7}{true}{false}}
  defer
    message = [RBL] you are temporarily blocked on this server.
    log_message = [SPFBL] listed.
    condition = ${if eq {$acl_c_spfreceived}{8}{true}{false}}
  drop
    message = [RBL] you are permanently blocked in this server.
    log_message = [SPFBL] blocked.
    condition = ${if eq {$acl_c_spfreceived}{10}{true}{false}}
  discard
    log_message = [SPFBL] spamtrap.
    condition = ${if eq {$acl_c_spfreceived}{11}{true}{false}}
  defer
    message = [RBL] you are greylisted on this server.
    log_message = [SPFBL] greylisting.
    condition = ${if eq {$acl_c_spfreceived}{12}{true}{false}}
  defer
    message = [SPF] A transient error occurred when checking SPF record from $sender_address, preventing a result from being reached. Try again later.
    log_message = [SPFBL] timeout.
    condition = ${if eq {$acl_c_spfreceived}{9}{true}{false}}
  warn
    condition = ${if def:acl_c_spfbl {true}{false}}
    add_header = Received-SPFBL: $acl_c_spfbl
```

Se o Exim estiver usando anti-vírus, é possível mandar a denúnica automaticamente utilizando a seguinte configuração na seção "acl_check_data":
```
  # Deny if the message contains malware
  deny
    condition = ${if < {$message_size}{16m}{true}{false}}
    malware = *
    message = This message was detected as possible malware ($malware_name).
    log_message = malware detected. ${run{/usr/local/bin/exim4/spfblticket.sh $acl_c_spfblticket}{$value}{SPFBL ERROR}}.
```

##### Integração com Exim do cPanel

Se a configuração do Exim for feita for cPanel, basta seguir na guia "Advanced Editor", e ativar a opção "custom_begin_spam_scan" com o seguinte código:
```
  drop
    message = Invalid MAIL FROM address. Use a valid e-mail address.
    log_message = invalid sender.
    condition = ${if match {$sender_address}{^([[:alnum:]][[:alnum:].+_=-]*)@([[:alnum:]_-]+\\.)+(biz|com|edu|gov|info|int|jus|mil|net|org|pro|[[:alpha:]]\{2\})\$}{false}{true}}
    condition = ${if match {$sender_address}{^SRS0(=|\\+)[[:alnum:]/+]+=[[:alnum:]]+=(([[:alnum:]_-]+\\.)+(biz|com|edu|gov|info|int|jus|mil|net|org|pro|[[:alpha:]]\{2\}))=([[:alnum:]][[:alnum:]._-]*)@(([[:alnum:]_-]+\\.)+(biz|com|edu|gov|info|int|jus|mil|net|org|pro|[[:alpha:]]\{2\}))\$}{false}{true}}
    condition = ${if match {$sender_address}{^prvs=[[:alnum:]]+=([[:alnum:]][[:alnum:]._-]*)@(([[:alnum:]_-]+\\.)+(biz|com|edu|gov|info|int|jus|mil|net|org|pro|[[:alpha:]]\{2\}))\$}{false}{true}}
  warn
    set acl_c_spfbl = ${run{/etc/spfbl/spfbl.sh query "$sender_host_address" "$sender_address" "$sender_helo_name" "$local_part@$domain"}{ERROR}{$value}}
    set acl_c_spfreceived = $runrc
    set acl_c_spfblticket = ${sg{$acl_c_spfbl}{(PASS |SOFTFAIL |NEUTRAL |NONE |FAIL )}{}}
  drop
    message = [SPF] $sender_host_address is not allowed to send mail from $sender_address. Please see http://www.openspf.org/why.html?sender=$sender_address&ip=$sender_host_address for details.
    log_message = [SPFBL] failed.
    condition = ${if eq {$acl_c_spfreceived}{3}{true}{false}}
  defer
    message = [SPF] A transient error occurred when checking SPF record from $sender_address, preventing a result from being reached. Try again later.
    log_message = [SPFBL] error.
    condition = ${if eq {$acl_c_spfreceived}{6}{true}{false}}
  deny
    message = [SPF] One or more SPF records from $sender_address_domain could not be interpreted. Please see http://www.openspf.org/SPF_Record_Syntax for details.
    log_message = [SPFBL] unknown.
    condition = ${if eq {$acl_c_spfreceived}{7}{true}{false}}
  defer
    message = [RBL] you are temporarily blocked on this server.
    log_message = [SPFBL] listed.
    condition = ${if eq {$acl_c_spfreceived}{8}{true}{false}}
  drop
    message = [RBL] you are permanently blocked in this server.
    log_message = [SPFBL] blocked.
    condition = ${if eq {$acl_c_spfreceived}{10}{true}{false}}
  discard
    log_message = [SPFBL] spamtrap.
    condition = ${if eq {$acl_c_spfreceived}{11}{true}{false}}
  defer
    message = [RBL] you are greylisted on this server.
    log_message = [SPFBL] greylisting.
    condition = ${if eq {$acl_c_spfreceived}{12}{true}{false}}
  defer
    message = [SPF] A transient error occurred when checking SPF record from $sender_address, preventing a result from being reached. Try again later.
    log_message = [SPFBL] timeout.
    condition = ${if eq {$acl_c_spfreceived}{9}{true}{false}}
  warn
    condition = ${if def:acl_c_spfbl {true}{false}}
    add_header = Received-SPFBL: $acl_c_spfbl
```

##### Plugin de denúncia SPFBL no Roundcube

O plugin de denúncia SPFBL via webmail do Roundcube pode ser encontrada no projeto independente do Ricardo Walter:

![Roundcube-Plugin-markasjunk_spfbl](https://github.com/rikw22/Roundcube-Plugin-markasjunk_spfbl "Roundcube-Plugin-markasjunk_spfbl")

### Como iniciar o serviço SPFBL

Para instalar o serviço basta copiar o arquivo SPFBL.jar e a pasta lib deste jar em qualquer local. Se for a primeira vez que o serviço é iniciado, copie também os seguintes arquivos de cache no mesmo local: as.map, domain.map, guess.map, handle.map, helo.map, ns.map, owner.map, provider.set, spf.map, subnet4.map, subnet6.map, tld.set.

Quando todos os arquivos estiverem copiados, rode o serviço utilizando o seguinte comando no mesmo local:

```
java -jar /opt/spfbl/dist/SPFBL.jar 9875 512 >> log.001.txt &
```

O serviço necessita da JVM versão 6 instalada, ou superior, para funcionar corretamente.

### Como parar o serviço SPFBL

O serviço SPFBL não tem ainda um script para ser parado, mas é possível usar este comando para pará-lo:
```
echo "SHUTDOWN" | nc 127.0.0.1 9875
```

O script de inicio e parada do SPFBL na inicialização do sistema operacional está sendo desenvolvido.

### Descentralização do SPFBL

A descentralização do serviço SPFBL deve ser feito através de redes P2P:

![p2pNetwork](https://github.com/leonamp/SPFBL/blob/master/p2pNetwork.png "p2pNetwork.png")

Aqui vemos um exemplo de rede com três pools, onde cada pool tem um servidor, cada servidor SPFBL tem três servidores de e-mail e cada servidor de e-mail tem três usuários.

Responsabilidades dos elementos:

* Usuário: denunciar as mensagens SPAM que passam para ele utilizando de ferramentas disponibilizadas pelo administrador do seu MX.
* Administrador do MX: fornecer ferramentas de denúncia para seus usuários e bloquear permanentemente as fontes SPAM 100% comprovadas.
* Administrador do pool: criar regras de utilização do pool, onde os administradores MX decidem se desejam aderir ao pool, verifiar se as regras estão sendo cumpridas e se conectar a outros pools que tenham ideais de bloqueio semelhantes ao dele.

O ideia de se conectar a outros pool com semelhança de ideais de bloqueio serve para criar uma rede de confiança, onde um pool sempre irá enviar informações na qual seu par concorde sempre. Não é correto um pool enviar informação de bloqueio sendo que o outro pool não concorde. Neste caso o pool que recebeu a informação deve passar a rejeitar as informações do pool de origem e procurar outros pools com melhor reputação.

### Pools conhecidos em funcionamento

Aqui vemos alguns pools em funcionamento para que novos membros possam se cadastrar para consulta, quando aberto, ou para soliticar o envio de informações P2P.

Abertos:
* MatrixDefense: leandro@allchemistry.com.br

Fechados:
* MX-Protection: gtec77@gmail.com

### Forum de discussão SPFBL

Todas as discussões e dúvidas sobre o SPFBL estão sendo tratadas através do forum:

<https://groups.google.com/d/forum/spfbl>
