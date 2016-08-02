# Serviço SPFBL

### Introdução

O serviço SPFBL é uma junção dos conceitos de SPF e DNSBL.

O propósito deste serviço é melhorar o processamento SPF e reduzir a quantidade de consultas externas de um servidor de e-mail, na qual utiliza SPF e pelo menos um serviço qualquer de DNSBL.

Uma vez iniciado o serviço, as consultas podem ser feitas por programas clientes, como por exemplo o script "spfbl.sh". Atenção! O script "spfbl.sh" necessita do pacote "netcat"instalado para funcionar corretamente.

A listagem é realizada através do ticket SPFBL, que é enviado juntamente com o qualificador SPF da consulta:

```
user:~# spfbl.sh query "200.160.7.130" "gter-bounces@eng.registro.br" "eng.registro.br" "destinatario@destino.com.br"
PASS cPo6NAde1euHf6A2oT13sNlzCqnCH+PIuY/ClbDH2RJrV08UwvNblJPJiVo0E0SwAiO/lzSW+5BKdXXxDovqQPNqcfrvpBx5wPWgEC7EJ54=
```

Este ticket deve ser incluído no cabeçalho "Received-SPFBL" da mensagem para uma possível denúncia de SPAM futura.

Caso o serviço seja configurado para trabalhar com HTTP, os tickets serão enviados com seus respectivos prefixos da URL de quem gerou o ticket:
```
user:~# spfbl.sh query "200.160.7.130" "gter-bounces@eng.registro.br" "eng.registro.br" "destinatario@destino.com.br"
PASS http://<hostname>[:<port>]/spam/cPo6NAde1euHf6A2oT13sNlzCqnCH+PIuY/ClbDH2RJrV08UwvNblJPJiVo0E0SwAiO/lzSW+5BKdXXxDovqQPNqcfrvpBx5wPWgEC7EJ54=
```

Este último método de denuncia com URL facilita o desenvolvimento de novas ferramentas, como plugins de mail client por exemplo, para que as denúncias sejam feitas diretamente pelo destinatário, aonde quer que ele esteja.

Caso a mensagem seja considerada SPAM pelo usuário, a mensagem deve ser processada pelo comando "spfbl.sh spam", que vai extrair o ticket contido no campo "Received-SPFBL" e enviá-lo ao serviço SPFBL:

```
user:~# spfbl.sh spam <caminho da mensagem SPAM>
Reclamação SPFBL enviada com sucesso.
```

Cada denúncia expira em sete dias após a data de recebimento da mensagem e só pode ser denunciada até cinco dias após o recebimento.

Se houver interesse um utilizar este serviço sem implementá-lo em servidor próprio, podemos ceder nosso próprio servidor. Para isto, basta enviar para um e-mail para leandro@spfbl.net com a lista de blocos de IP utilizados, o volume diário de recebimento e o MTA utilizado pelos seus terminais MX para liberação do firewall.

Se este projeto for útil para sua empresa, faça uma doação de qualquer valor para ajudar a mantê-lo:

<a href="https://www.patreon.com/user?u=2430613&ty=h">Patreon SPFBL project</a>

![Donate](https://github.com/leonamp/SPFBL/blob/master/doc/bicoin.png "1HVe5J3dziyEQ1BCDQamNWas6ruVHTyESy")

### Funcionalidades

Algumas alterações foram implementadas no SPFBL com a intenção de minimizar as respostas negativas ou incoerentes do SPF convencional.

##### Correção de sintaxe SPF

As vezes alguns administradores de DNS acabam cometendo erros pequenos ao registrar um SPF para um determinado domínio. O SPFBL é capaz de fazer algumas correções destes erros.

Por exemplo, o domínio "farmaciassaorafael.com.br", com o registro SPF "v=spf1 ipv4:177.10.167.165 -all", retorna falha no SPF convencional, mas o SPFBL reconhece um REGEX CIDR dentro de um token e deduz que o administrador queria dizer "ip4" invés de "ipv4".

Além disto, se um mecanismo não puder ser reconhecido pelo SPFBL, este mesmo mecanismo é apenas ignorado, dando chance de acontecer um match em outros mecanismos que são reconhecidos pelo SPFBL.

##### Merge de múltiplos registros SPF

Se o administrador registrar vários registros SPF para um determinado domínio, o SPFBL faz o merge de todos eles e considera como se fosse apenas um.

##### Mecanismos permissivos demais

O SPF convencional permite o registro de alguns mecanismos que são permissivos demais ao ponto de retornar sempre PASS para qualquer parâmetro utilizado na consulta.

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
user:~# spfbl.sh block show
EMPTY
```

Para adicionar um bloqueio arbitrário:
```
user:~# spfbl.sh block add <remetente>
ADDED
```

Para remover um bloqueio arbitrário:
```
user:~# spfbl.sh block drop <remetente>
DROPED
```

Os elementos que podem ser adicionados nesta lista são:
* .tld[&gt;&lt;recipient&gt;]
* .domain.ltd[&gt;&lt;recipient&gt;]
* .sub.domain.tld[&gt;&lt;recipient&gt;]
* @domain.tld[;&lt;qualifier&gt;][&gt;&lt;recipient&gt;]
* @sub.domain.tld[;&lt;qualifier&gt;][&gt;&lt;recipient&gt;]
* sender@[;&lt;qualifier&gt;][&gt;&lt;recipient&gt;]
* sender@domain.tld[;&lt;qualifier&gt;][&gt;&lt;recipient&gt;]
* IP[&gt;&lt;recipient&gt;]
* CNPJ[&gt;&lt;recipient&gt;]
* CPF[&gt;&lt;recipient&gt;]
* CIDR=&lt;cidr&gt;
* REGEX=&lt;java regex&gt;
* WHOIS/&lt;field&gt;[/&lt;field&gt;...]\(=\|&lt;\|&gt;\)&lt;value&gt;
* DNSBL=&lt;server&gt;;&lt;value&gt;

Esta possibilidade de colocar um qualificador, significa que o bloqueio só será feito se o resultado SPF resultar neste qualificador. Exemplo: "@gmail.com;SOFTFAIL" bloqueia qualquer tentativa de envio com remetente *@gmail.com e o SPF deu SOFTFAIL.

No caso do bloqueio por WHOIS, é possível definir criterios onde o domínio do remetente (somente .br) será consultado e a navegação pela estrutura de dados é feita pelo caracter "/". Exemplo: "WHOIS/owner-c=EJCGU" bloqueia todos os remetentes cujo domínio tenha no WHOIS o campo "owner-c" igual à "EJCGU". Se for usado os sinais "<" ou ">" e o campo for de data, então o SPFBL vai converter o valor do campo em um inteiro que representan a quantidade de dias que se passaram daquela data e comparar com o valor do critério. Este último consegue resolver o problema em que alguns spammers cadastram um novo owner para enviar SPAM. Para evitar isso, é possível bloquear owners novos, com menos de sete dias por exemplo, usando o bloqueio "WHOIS/owner-c/created<7".

Deve ser utilizado o padrão Java para o bloqueio por REGEX: <http://docs.oracle.com/javase/7/docs/api/java/util/regex/Pattern.html>

Para bloqueio por DNSBL, infomar o servidor em &lt;server&gt; e o valor positivo do mesmo em &lt;value&gt;, como exemplo padrão para &lt;value&gt; 127.0.0.2.

##### Spamtrap

É possível adicionar destinatários na lista spamtrap do SPFBL.

Sempre que o destinatário de uma consulta está na lista spamtrap, o SPFBL realiza a denúncia automática e manda o MTA descartar silencionsamente a mensagem.

Para visualizar a lista de spamtrap:
```
user:~# spfbl.sh trap show
EMPTY
```

Para adicionar um spamtrap:
```
user:~# spfbl.sh trap add <destinatário>
ADDED
```

Para remover um spamtrap:
```
user:~# spfbl.sh trap drop <destinatário>
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
user:~# spfbl.sh white show
EMPTY
```

Para adicionar um remetente:
```
user:~# spfbl.sh white add <remetente>
ADDED
```

Para remover um remetente:
```
user:~# spfbl.sh white drop <remetente>
DROPED
```

Os elementos que podem ser adicionados nesta lista são:
* .tld[&gt;&lt;recipient&gt;]
* .domain.ltd[&gt;&lt;recipient&gt;]
* .sub.domain.tld[&gt;&lt;recipient&gt;]
* @domain.tld[;&lt;qualifier&gt;][&gt;&lt;recipient&gt;]
* @sub.domain.tld[;&lt;qualifier&gt;][&gt;&lt;recipient&gt;]
* sender@[;&lt;qualifier&gt;][&gt;&lt;recipient&gt;]
* sender@domain.tld[;&lt;qualifier&gt;][&gt;&lt;recipient&gt;]
* IP[&gt;&lt;recipient&gt;]
* CNPJ[&gt;&lt;recipient&gt;]
* CPF[&gt;&lt;recipient&gt;]
* CIDR=&lt;cidr&gt;
* REGEX=&lt;java regex&gt;
* WHOIS/&lt;field&gt;[/&lt;field&gt;...]=&lt;value&gt;

Internamente esta lista aceita somente identificação de remetentes com qualificador. Portanto se nenhum qualificador for definido, a lista acatará o qualificador padrão PASS.

Quando o SPF retorna FAIL, o fluxo SPFBL rejeita imediatamente a mensagem pois isso é um padrão SPF. Porém existem alguns casos específicos onde o administrador do domínio do remetente utiliza "-all" e não coloca todos os IPs de envio, resultando em falso FAIL. Neste caso, é possível resolver o problema, sem depender do tal administrador, adicionado o token "@domain.tld;FAIL" nesta lista. Esta lista é á única lista que aceita FAIL como qualificador. O SPFBL ignora o resultado FAIL para o domínio específico quando usado. Atenção! Este comando deve ser evitado! O correto é pedir ao administrador do domínio corrigir a falha no registro SPF dele usando este comando somente durante o intervalo onde o problema está sendo corrigido.

Existe uma forma de incluir remetentes na whitelist onde o próprio SPFBL descobre se melhor incluir o remetente pelo domínio ou pelo endereço completo.

Esta forma de inclusão, com operador "sender" invés de "add", o SPFBL verifica se o domínio deste remetente é um provedor de caixa postal e inclui o endereço completo se for, ou inclui o domínio se for email corporativo:
```
user:~# spfbl white sender leandro@spfbl.net
ADDED @spfbl.net
user:~# spfbl white sender user@gmail.com
ADDED user@gmail.com
```

Este script abaixo ajuda no processo de eliminação de falsos positivos usando o comando acima para incluir endereços onde os usuários do Postfix enviaram alguma mensagem para estes endereços:
```
# Autor: Kleber Rodrigues
SHELL=/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin
mes=$(date +%b)
dia=$(date +%_d)
hora=$(date +%H)
echo "$mes $dia $hora" > /usr/local/sbin/hora
grep "$mes $dia $hora" /var/log/maillog | grep "status=sent (250 2.6.0" | grep -o "to=<.*.>," | grep -o '@[^:]*' | cut -d '<' -f 2 | cut -d '>' -f 1 | sort -u > /usr/local/sbin/tmp
awk '{print "/opt/spfbl/spfbl.sh white sender "$0""}' /usr/local/sbin/tmp > /usr/local/sbin/domain-analise.sh
chmod a+x /usr/local/sbin/domain-analise.sh
bash /usr/local/sbin/domain-analise.sh
rm /usr/local/sbin/tmp
```

O script deve ser rodado em uma certa frequência.

A ideia é antecipar as respostas dos futuros remetentes destes usuários e já avisar o SPFBL que estes casos podem ser aceitos sem preocupação.

Para EXIM e servidores com cPanel/WHM, você poderá utilizar o script abaixo. Ele faz automaticamente a detecção de auto-repliers, então você não terá problemas com spammers sendo inseridos na whitelist caso o cliente tenha uma mensagem automático.

```
SECTION: PREROUTERS
whitelister:
  driver    = accept
  domains    = !+local_domains
  condition = ${if match_domain{$sender_address_domain}{+local_domains}} 
  condition = ${if or {{ !eq{$h_list-id:$h_list-post:$h_list-subscribe:}{} }{ match{$h_precedence:}{(?i)bulk|list|junk|auto_reply} } { match{$h_auto-submitted:}{(?i)auto-generated|auto-replied} } } {no}{yes}}
  transport = whlist
unseen

SECTION: TRANSPORTSTART
whlist:
  driver  = pipe
  command = /var/spool/exim/autoWH $local_part@$domain 
  return_fail_output = true

ARQUIVO /var/spool/exim/autoWH
#!/bin/sh
# Debug:
echo "Args recebidos: \$1 = $1" >> /var/spool/exim/log-transport.log
# Magica:
#/var/spool/exim/spfbl.sh white sender $1 >/dev/null 2>&1
echo "WHITE SENDER $1" | nc IP-DO-SEU-POOL-SPFBL 9877
####
```
Lembre-se de substituir 'IP-DO-SEU-POOL-SPFBL' pelo seu pool de SPFBL. No caso do matrix defense, seria 'matrix.spfbl.net'.

##### Greylisting

A mensagem será atrasada 25min sempre que o responsável estiver com status YELLOW.

##### Blacklisted

A mensagem será marcada como SPAM usando o padrão "X-Spam-Flag: YES" do Spamassassin.

##### Serviço DNSBL

O SPFBL abre a porta DNS para receber consultas padrão DNSBL.

Para utilizar este serviço, é necessário registrar um host "dnsbl" como NS apontando para o hostname dnsbl.&lt;dominio&gt;, onde este hostname aponta para o IP do servidor SPFBL.

Exemplo: dnsbl.spfbl.net (serviço disponível)

### Funcionamento

O SPFBL contém uma tabela chamada REPUTATION onde são guardados todos os identificadores de fontes denunciadas com suas respectivas informações de listagem.

O exemplo da tabela REPUTATION do MatrixDefence pode ser visto neste link: <https://github.com/leonamp/SPFBL/raw/master/doc/reputation.ods>.

A tabela REPUTATION é formada por quatro colunas:
* Responsável: o identificador do responsável pelo envio;
* Frequência: a frequência mais recente de envio naquele pool;
* Status: o status do identificador baseado no método de listagem abaixo e
* SPAM: a probabilidade mínima de uma mensagem ser SPAM para aquele identificador no mesmo pool.

##### Respostas SPFBL

O SPFBL retorna todos os qualificadores do SPF convencional mais seis qualificadores novos, chamados LISTED, BLOCKED, SPAMTRAP, GREYLIST, NXDOMAIN e INVALID:

* PASS &lt;ticket&gt;: permite o recebimento da mensagem.
* FAIL: rejeita o recebimento da mensagem e informa à origem o descumprimento do SPF.
* SOFTFAIL &lt;ticket&gt;: permite o recebimento da mensagem mas marca como suspeita.
* NEUTRAL &lt;ticket&gt;: permite o recebimento da mensagem.
* NONE &lt;ticket&gt;: permite o recebimento da mensagem.
* LISTED [&lt;ticket&gt;]: atrasa o recebimento da mensagem, informa à origem a listagem temporária em blacklist e envia e-mail com URL de liberação quando for o caso.
* BLOCKED: rejeita o recebimento da mensagem e informa à origem o bloqueio permanente.
* FLAG: aceita o recebimento e redirecione a mensagem para a pasta SPAM.
* SPAMTRAP: descarta silenciosamente a mensagem e informa à origem que a mensagem foi recebida com sucesso.
* GREYLIST: atrasar a mensagem informando à origem ele está em greylisting.
* NXDOMAIN: rejeita o recebimento e informa à origem que o domínio do remtente não existe.
* INVALID: rejeita o recebimento e informa à origem que o endereço do remetente não é válido.

##### Método de listagem

O SPFBL mantém uma flag de reputação para cada identificador. Esta flag tem três estados: GREEN, YELLOW e RED. A seguinte máquina de estado é utlizada para manipular estas flags, sendo P a probabilidade da mensagem ser SPAM segundo sua reputação atual na rede P2P:

![flagFSM.png](https://github.com/leonamp/SPFBL/blob/master/doc/flagFSM.png "flagFSM.png")

Quando a flag estiver no estado RED para o identificador, então o SPFBL retorna FLAG. Quando o MTA receber este retorno FLAG, deve incluir no cabeçalho a flag padrão do Spamassassin "X-Spam-Flag: YES" de modo ao MTA seguir o roteamento da mensagem para a pasta SPAM do usuário.

Quando a flag estiver no estado YELLOW para o identificador, então o SPFBL retorna GREYLISTED para que o MTA atrase a mensagem até a finalização do greylisting.

##### Fluxo do SPFBL

O SPFBL utiliza deste fluxo para determinar responsável pelo envio da mensagem e qual ação o MX deve tomar:

![flowchartSPFBL](https://github.com/leonamp/SPFBL/blob/master/doc/flowchartSPFBL.png "flowchartSPFBL.png")

##### Tipos de responsável

Sempre que o qualificador do SPFBL for PASS, o responsável considerado é o próprio remetente ou o domínio do remetente. Será considerado o remetente se o domínio dele estiver registrado no SPFBL como provedor de e-mail, como por exemplo: @hotmail.com, @gmail.com, @yahoo.com, etc. Caso contrário, o responsável é o domínio do remetente, mais o CNPJ ou CPF deste domínio quando este for da TLD BR.

Quando o qualificador for diferente de PASS, então o responsável considerado é o HELO ou o IP. Será considerado o HELO, com domínio e CNPJ ou CPF, se este for o reverso válido do IP. Caso contrário, o responsável é o IP.

Responsabilizar o HELO, quando um hostname for válido e aponta para o IP, é motivado pela seguinte ideia: se um hostname tiver funcionando em pilha dupla, então haveria duas listagens distintas, uma para o IPv4 e outra para o IPv6. Listar o HELO resolve este problema pois não importa por qual versão de IP o host envie mensagens, ele será visto pelo SPFBL como uma única entidade.

##### Checagem SPFBL

É possível fazer uma consulta de checagem SPFBL. Este tipo de consulta não retorna ticket, mas mostra a checagem SPF completa, os bloqueios e também todos os responsáveis considerados pelo SPFBL, de modo que o administrador possa entender melhor a resposta de uma consulta normal SPFBL.

```
user:~# spfbl.sh check 191.243.197.31 op4o@adsensum.com.br smtp-197-31.adsensum.com.br

SPF resolution results:
   adsensum.com.br:ip4:74.63.197.130 => NOT MATCH
   adsensum.com.br:ip4:191.243.196.0/22 => PASS

First BLOCK match: WHOIS/owner-c=SIR51

Considered identifiers and status:
   .smtp-197-31.adsensum.com.br UNDEFINED GREEN 0
   191.243.197.31 ~32351s RED 0.512
   @adsensum.com.br UNDEFINED GREEN 0
```

Na primeira seção, temos todos os passos de checagem SPF, sendo que o último sempre mostra o qualificador considerado.

Na segunda seção, temos o bloqueio encontrado para aquela consulta. Se houver esta seção, significa que a consulta formal será bloqueada.

Na terceira seção, temos a sequência dos responsáveis pelo envio na mensagem, sendo que a primeira coluna é o token do responsável, a segunda coluna é a frequência de envio em segundos, a terceira é a flag de listagem e a quarta coluna é a probabilidade daquele responsável enviar SPAM.

##### Integração Postfix

O SPFBL tem integração nativa com o Postfix a partir da versão 3.

Para utilizar o serviço SPFBL pelo Postfix a partir da versão 3, basta adicionar a seguinte linha no arquivo main.cf:
```
check_policy_service {
	inet:<IP_do_servidor_SPFBL>:9877,
	timeout=10s,
	default_action=DEFER
}
```

Para utilizar o serviço SPFBL pelo Postfix a antes da versão 3, basta adicionar as seguintes linhas no arquivo master.cf:
```
policy-spfbl  unix  -       n       n       -       -       spawn
   user=nobody argv=/caminho/do/script/spfblpostfix.pl
```
Depois disto, adicione a seguinte linha na seção "smtpd_recipient_restrictions" do arquivo main.cf:
```
check_policy_service unix:private/policy-spfbl
```

Após todas configurações, dê o comando reload ou restart no Postfix.

O script pode ser obtido na pasta "./client" deste projeto. Basta alterar o IP do servidor SPFBL dentro dele.

O administrador deve ficar atento à seguinte linha de configuração do arquivo master.cf, pois a mesma deve permenecer comentada:
```
# -o soft_bounce=yes
```

##### Integração Zimbra

Para utilizar o serviço SPFBL pelo Zimbra, basta adicionar as seguintes linhas no arquivo "/opt/zimbra/postfix/conf/master.cf.in":
```
policy-spfbl  unix  -       n       n       -       -       spawn
   user=nobody argv=/caminho/do/script/spfblpostfix.pl
```

Em seguida, edite o arquivo "/opt/zimbra/conf/zmconfigd/smtpd_recipient_restrictions.cf" e adicione a seguinte linha:
```
check_policy_service unix:private/policy-spfbl
```

Após adicionar as linhas, renicie o serviço:
```
zmconfigdctl restart
zmmtactl stop
zmmtactl start
```

O script pode ser obtido na pasta "./client" deste projeto. Basta alterar o IP do servidor SPFBL dentro dele.

##### Integração com Exim

Para integrar o SPFBL no Exim, basta adicionar a seguinte linha na secção "acl_check_rcpt":
```
# Use 'spfbl.sh query' to perform SPFBL check.
  warn
    set acl_c_spfbl = ${run{/usr/local/bin/spfbl query "$sender_host_address" "$sender_address" "$sender_helo_name" "$local_part@$domain"}{ERROR}{$value}}
    set acl_c_spfreceived = $runrc
    set acl_c_spfblticket = ${sg{$acl_c_spfbl}{(PASS |SOFTFAIL |NEUTRAL |NONE |FAIL |LISTED |BLOCKED |FLAG)}{}}
  deny
    message = 5.7.1 SPFBL $sender_host_address is not allowed to send mail from $sender_address.
    log_message = SPFBL check failed.
    condition = ${if eq {$acl_c_spfreceived}{3}{true}{false}}
  defer
    message = A transient error occurred when checking SPF record from $sender_address, preventing a result from being reached. Try again later.
    log_message = SPFBL check error.
    condition = ${if eq {$acl_c_spfreceived}{6}{true}{false}}
  deny
    message = One or more SPF records from $sender_address_domain could not be interpreted. Please see http://www.openspf.org/SPF_Record_Syntax for details.
    log_message = SPFBL check unknown.
    condition = ${if eq {$acl_c_spfreceived}{7}{true}{false}}
  deny
    message = 5.7.1 SPFBL sender has non-existent internet domain.
    log_message = SPFBL check nxdomain.
    condition = ${if eq {$acl_c_spfreceived}{13}{true}{false}}
  deny
    message = 5.7.1 SPFBL IP or sender is invalid.
    log_message = SPFBL check invalid.
    condition = ${if eq {$acl_c_spfreceived}{14}{true}{false}}
  defer
    message = 4.7.2 SPFBL LISTED $acl_c_spfblticket
    log_message = SPFBL check listed.
    condition = ${if eq {$acl_c_spfreceived}{8}{true}{false}}
    condition = ${if match {$acl_c_spfblticket}{^http://}{true}{false}}
  defer
    message = 4.7.2 SPFBL you are temporarily blocked on this server.
    log_message = SPFBL check listed.
    condition = ${if eq {$acl_c_spfreceived}{8}{true}{false}}
  deny
    message = 5.7.1 SPFBL BLOCKED $acl_c_spfblticket
    log_message = SPFBL check blocked.
    condition = ${if eq {$acl_c_spfreceived}{10}{true}{false}}
    condition = ${if match {$acl_c_spfblticket}{^http://}{true}{false}}
  deny
    message = 5.7.1 SPFBL you are permanently blocked on this server.
    log_message = SPFBL check blocked.
    condition = ${if eq {$acl_c_spfreceived}{10}{true}{false}}
  discard
    log_message = SPFBL check spamtrap.
    condition = ${if eq {$acl_c_spfreceived}{11}{true}{false}}
  defer
    message = 4.7.1 SPFBL you are greylisted on this server.
    log_message = SPFBL check greylisting.
    condition = ${if eq {$acl_c_spfreceived}{12}{true}{false}}
  defer
    message = A transient error occurred when checking SPF record from $sender_address, preventing a result from being reached. Try again later.
    log_message = SPFBL check timeout.
    condition = ${if eq {$acl_c_spfreceived}{9}{true}{false}}
  warn
    log_message = SPFBL check flag.
    condition = ${if eq {$acl_c_spfreceived}{16}{true}{false}}
    add_header = X-Spam-Flag: YES
  warn
    condition = ${if eq {$acl_c_spfreceived}{16}{false}{true}}
    add_header = Received-SPFBL: $acl_c_spfbl
```

Para mandar o Exim bloquear o campo From e Reply-To da mensagem, basta adicionar esta configuração na seção "acl_check_data":
```
  # Deny if From or Reply-To is blocked in SPFBL.
  deny
    condition = ${if match {${address:$h_From:}}{^([[:alnum:]][[:alnum:].+_-]*)@([[:alnum:]_-]+\\.)+([[:alpha:]]\{2,5\})\$}{true}{false}}
    condition = ${if eq {${run{/usr/local/bin/spfbl block find ${address:$h_From:}}{NONE\n}{$value}}}{NONE\n}{false}{true}}
    message = 5.7.1 SPFBL you are permanently blocked on this server.
    log_message = SPFBL check blocked. From:${address:$h_From:}. ${run{/usr/local/bin/spfbl spam $acl_c_spfblticket}{$value}{ERROR}}.
  deny
    condition = ${if match {${address:$h_Reply-To:}}{^([[:alnum:]][[:alnum:].+_-]*)@([[:alnum:]_-]+\\.)+([[:alpha:]]\{2,5\})\$}{true}{false}}
    condition = ${if eq {${address:$h_From:}}{${address:$h_Reply-To:}}{false}{true}}
    condition = ${if eq {${run{/usr/local/bin/spfbl block find ${address:$h_Reply-To:}}{NONE\n}{$value}}}{NONE\n}{false}{true}}
    message = 5.7.1 SPFBL you are permanently blocked on this server.
    log_message = SPFBL check blocked. Reply-To:${address:$h_Reply-To:}. ${run{/usr/local/bin/spfbl spam $acl_c_spfblticket}{$value}{ERROR}}.
```

Se o Exim estiver usando anti-vírus, é possível mandar a denúnica automaticamente utilizando a seguinte configuração na seção "acl_check_data":
```
  # Deny if the message contains malware
  deny
    condition = ${if < {$message_size}{16m}{true}{false}}
    malware = *
    message = 5.7.1 SPFBL this message was detected as possible malware.
    log_message = SPFBL malware detected. ${run{/usr/local/bin/exim4/spfblticket.sh $acl_c_spfblticket}{$value}{ERROR}}.
```

##### Integração com Exim do cPanel

Se a configuração do Exim for feita for cPanel, basta seguir na guia "Advanced Editor", e ativar a opção "custom_begin_rbl" com o seguinte código:
```
  warn
    set acl_c_spfbl = ${run{/usr/local/bin/spfbl query "$sender_host_address" "$sender_address" "$sender_helo_name" "$local_part@$domain"}{ERROR}{$value}}
    set acl_c_spfreceived = $runrc
    set acl_c_spfblticket = ${sg{$acl_c_spfbl}{(PASS |SOFTFAIL |NEUTRAL |NONE |FAIL |LISTED |BLOCKED |FLAG)}{}}
  deny
    message = 5.7.1 SPFBL $sender_host_address is not allowed to send mail from $sender_address.
    log_message = SPFBL check failed.
    condition = ${if eq {$acl_c_spfreceived}{3}{true}{false}}
  defer
    message = A transient error occurred when checking SPF record from $sender_address, preventing a result from being reached. Try again later.
    log_message = SPFBL check error.
    condition = ${if eq {$acl_c_spfreceived}{6}{true}{false}}
  deny
    message = One or more SPF records from $sender_address_domain could not be interpreted. Please see http://www.openspf.org/SPF_Record_Syntax for details.
    log_message = SPFBL check unknown.
    condition = ${if eq {$acl_c_spfreceived}{7}{true}{false}}
  deny
    message = 5.7.1 SPFBL sender has non-existent internet domain.
    log_message = SPFBL check nxdomain.
    condition = ${if eq {$acl_c_spfreceived}{13}{true}{false}}
  deny
    message = 5.7.1 SPFBL IP or sender is invalid.
    log_message = SPFBL check invalid.
    condition = ${if eq {$acl_c_spfreceived}{14}{true}{false}}
  defer
    message = 4.7.2 SPFBL LISTED $acl_c_spfblticket
    log_message = SPFBL check listed.
    condition = ${if eq {$acl_c_spfreceived}{8}{true}{false}}
    condition = ${if match {$acl_c_spfblticket}{^http://}{true}{false}}
  defer
    message = 4.7.2 SPFBL you are temporarily blocked on this server.
    log_message = SPFBL check listed.
    condition = ${if eq {$acl_c_spfreceived}{8}{true}{false}}
  deny
    message = 5.7.1 SPFBL BLOCKED $acl_c_spfblticket
    log_message = SPFBL check blocked.
    condition = ${if eq {$acl_c_spfreceived}{10}{true}{false}}
    condition = ${if match {$acl_c_spfblticket}{^http://}{true}{false}}
  deny
    message = 5.7.1 SPFBL you are permanently blocked on this server.
    log_message = SPFBL check blocked.
    condition = ${if eq {$acl_c_spfreceived}{10}{true}{false}}
  discard
    log_message = SPFBL check spamtrap.
    condition = ${if eq {$acl_c_spfreceived}{11}{true}{false}}
  defer
    message = 4.7.1 SPFBL you are greylisted on this server.
    log_message = SPFBL check greylisting.
    condition = ${if eq {$acl_c_spfreceived}{12}{true}{false}}
  defer
    message = A transient error occurred when checking SPF record from $sender_address, preventing a result from being reached. Try again later.
    log_message = SPFBL check timeout.
    condition = ${if eq {$acl_c_spfreceived}{9}{true}{false}}
  warn
    log_message = SPFBL check flag.
    condition = ${if eq {$acl_c_spfreceived}{16}{true}{false}}
    add_header = X-Spam-Flag: YES
  warn
    condition = ${if eq {$acl_c_spfreceived}{16}{false}{true}}
    add_header = Received-SPFBL: $acl_c_spfbl
```

### Como iniciar o serviço SPFBL

Para instalar o serviço, basta copiar os arquivos "./dist/SPFBL.jar" e "./run/spfbl.conf" do projeto em "/opt/spfbl/".

Copie também e as pastas "./lib" e "./data/" do projeto em "/opt/spfbl/".

Crie a pasta "/var/log/spfbl", se esta não existir, com permissões de leitura e escrita para o usuário que rodará o serviço.

O script client "./client/spfbl.sh" deve ser copiado na pasta "/usr/local/bin" com permissão de execução.

Quando todos os arquivos e pastas estiverem copiados, configure o serviço editando o arquivo "/opt/spfbl/spfbl.conf".

Após a configuração, rode o serviço utilizando o seguinte comando na mesma pasta:

```
user:~# java -jar /opt/spfbl/SPFBL.jar &
```

Caso seja necessário iniciar o serviço com DNSBL, é importante lembrar que o sistema operacional pode requerer permissão especial:

```
user:~# sudo java -jar /opt/spfbl/SPFBL.jar &
```

O serviço necessita da JVM versão 6 instalada, ou superior, para funcionar corretamente.

Nós disponibilizamos aqui uma lista de bloqueios atualizada pela rede SPFBL via P2P para um inicio de instalação:

<https://github.com/leonamp/SPFBL/raw/master/doc/block.txt>

Esta lista de bloqueios pode ser usada por conta e risco do novo administrador do serviço SPFBL, sendo que este administrdaor deve inserir a lista no SPFBL através de script próprio.

### Como parar o serviço SPFBL

Este este comando pode ser usado para parar o SPFBL:
```
user:~# spfbl.sh shutdown
```

O script de inicio e parada do SPFBL na inicialização do sistema operacional está sendo desenvolvido.

### Descentralização do SPFBL

A descentralização do serviço SPFBL deve ser feito através de redes P2P:

![p2pNetwork](https://github.com/leonamp/SPFBL/blob/master/doc/p2pNetwork.png "p2pNetwork.png")

Aqui vemos um exemplo de rede com três pools, onde cada pool tem um servidor, cada servidor SPFBL tem três servidores de e-mail e cada servidor de e-mail tem três usuários.

Responsabilidades dos elementos:

* Usuário: denunciar as mensagens SPAM que passam para ele utilizando de ferramentas disponibilizadas pelo administrador do seu MX.
* Administrador do MX: fornecer ferramentas de denúncia para seus usuários e bloquear permanentemente as fontes SPAM 100% comprovadas.
* Administrador do pool: criar regras de utilização do pool, onde os administradores MX decidem se desejam aderir ao pool, verifiar se as regras estão sendo cumpridas e se conectar a outros pools que tenham ideais de bloqueio semelhantes ao dele.

O ideia de se conectar a outros pool com semelhança de ideais de bloqueio serve para criar uma rede de confiança, onde um pool sempre irá enviar informações na qual seu par concorde sempre. Não é correto um pool enviar informação de bloqueio sendo que o outro pool não concorde. Neste caso o pool que recebeu a informação deve passar a rejeitar as informações do pool de origem e procurar outros pools com melhor reputação.

### Como cadastrar peers

Para cadastrar um peer, primeiro é necessário que a máquina esteja rodando com um IP público e existir um hostname de aponte para este IP.

Com posse do hostname da máquina, supondo que seja "sub.domain.tld", altere o arquivo de configuração "spfbl.conf", que deve ficar junto do arquivo executável JAR:
```
# Hostname that point to this server.
# Define a valid hostname to use P2P network.
hostname=sub.domain.tld
```

Descomente e defina também o e-mail de contato para questões P2P:
```
# Service administrator e-mail.
# Uncoment to receive report of P2P problems.
#admin_email=part@domain.tld
```

A porta escolhida para o serviço SPFBL trabalha com os dois protolocos, sendo TCP para consulta e UDP para P2P.

O firewall deve estar com a porta UDP escolhida para o serviço SPFBL completamente aberta para entrada e saída.

Após esta modificação, reinicie o serviço e rode este comando na porta administrativa para adicionar o peer, supondo que este peer seja "sub.domain2.tld:9877":
```
spfbl.sh peer add sub.domain2.tld:9877 <send> <receive>
sub.domain2.tld:9877 <send> <receive> 0 DEAD >100ms UNDEFINED
```

A variável &lt;send&gt; pode admitir estes valores:
* NEVER: nunca enviar anúncios para este peer.
* ALWAYS: sempre enviar anúncios para este peer. 
* REPASS: repassar imediatamente todos os anúncios aceitos dos demais peers para este peer.

A variável &lt;receive&gt; pode admitir estes valores:
* ACCEPT: aceitar todos os anúncios deste peer.
* REJECT: rejeitar todos os anúncios deste peer.
* DROP: dropar os pacotes deste peer (funcionalidade de firewall não implementada ainda).
* RETAIN: reter todos os anúncios deste peer para confirmação posterior.
* REPASS: repassar todos os anúncios deste peer para os demais peers.

Assim que a inclusão estiver completa, o peer adicionado receberá um pacote de apresentação. Este pacote contém o hostname, porta e e-mail de contato do seu peer. No mesmo intante o peer remoto adcionará o seu na lista dele, onde os parâmetros de envio e recebimento estarão fechados por padrão.

Assim que o administrador do peer remoto analisar este novo peer adicionado na lista dele, vai decidir por liberar ou não. A visualização da lista de peers pode ser feita executando o seguinte comando:
```
user:~# spfbl.sh peer show
sub.domain.tld:9877 NEVER REJECT 0 ALIVE >100ms UNDEFINED
```

Caso decida pela liberação, ele vai usar o seguinte comando, usando valores abertos para &lt;send&gt; e &lt;receive&gt;:
```
user:~# spfbl.sh peer set sub.domain.tld <send> <receive>
sub.domain.tld:9877 NEVER REJECT 0 ALIVE >100ms UNDEFINED
UPDATED SEND=<send>
UPDATED RECEIVE=<receive>
```

Apartir da liberação, o peer dele vai passar a pingar no seu peer na frequência de uma hora, assim como o seu também fará o mesmo para ele, fazendo com que o status do peer passe a ficar ALIVE:
```
user:~# spfbl.sh peer show
sub.domain2.tld:9877 NEVER REJECT 0 ALIVE >100ms UNDEFINED
```

### Como administrar listas de retenção dos peers

Sempre que o status <receive> do peer for RETAIN, o SPFBL vai criar uma lista separada para aquele peer e guardar todos os identificadores que receber dele.

Quando os peers tiverem identificadores retidos, a lista deles poderão ser vistas através deste comando:
```
user:~# spfbl.sh retention show (<peer>|all)
```
Exemplo:
```
user:~# spfbl.sh retention show all
<peer1_hostame>:.br.netunoserver.net.br
<peer1_hostame>:.carrosvermelhos.top
<peer1_hostame>:.rdns-3.k7mail.com.br
<peer1_hostame>:@carrosvermelhos.top
<peer2_hostame>:.cloud2fun.com.br
<peer2_hostame>:.cloudmask.com.br
<peer2_hostame>:.cloversend.com.br
<peer2_hostame>:.email-a.first.cloudmask.com.br
<peer2_hostame>:.email.cloversend.com.br
<peer2_hostame>:.first.cloudmask.com.br
<peer2_hostame>:.marisa.email.cloversend.com.br
<peer2_hostame>:@cloud2fun.com.br
<peer2_hostame>:@email-a.first.cloudmask.com.br
<peer3_hostame>:.br.netunoserver.net.br
<peer3_hostame>:.carrosvermelhos.top
<peer3_hostame>:.rdns-3.k7mail.com.br
<peer3_hostame>:@carrosvermelhos.top
```

Para liberar todas as retenções, fazendo com que o SPFBL considere todos para BLOCK, utilie este comando:
```
user:~# spfbl.sh retention release (all|<identificador>)
```
Exemplo:
```
user:~# spfbl.sh retention release all
<peer1_hostame>:.br.netunoserver.net.br => ADDED
<peer1_hostame>:.carrosvermelhos.top => EXISTS
<peer1_hostame>:.rdns-3.k7mail.com.br => ADDED
<peer1_hostame>:@carrosvermelhos.top => EXISTS
<peer2_hostame>:.cloud2fun.com.br => EXISTS
<peer2_hostame>:.cloudmask.com.br => EXISTS
<peer2_hostame>:.cloversend.com.br => EXISTS
<peer2_hostame>:.email-a.first.cloudmask.com.br => EXISTS
<peer2_hostame>:.email.cloversend.com.br => EXISTS
<peer2_hostame>:.first.cloudmask.com.br => EXISTS
<peer2_hostame>:.marisa.email.cloversend.com.br => EXISTS
<peer2_hostame>:@cloud2fun.com.br => EXISTS
<peer2_hostame>:@email-a.first.cloudmask.com.br => ADDED
<peer3_hostame>:.br.netunoserver.net.br => EXISTS
<peer3_hostame>:.carrosvermelhos.top => EXISTS
<peer3_hostame>:.rdns-3.k7mail.com.br => EXISTS
<peer3_hostame>:@carrosvermelhos.top => EXISTS
```

Para rejeitar os identificadores retidos, utilize este comando:
```
user:~# spfbl.sh retention reject (ALL|<identificador>)
```

### Pools conhecidos em funcionamento

Aqui vemos alguns pools em funcionamento para que novos membros possam se cadastrar para consulta, quando aberto, ou para cadastrar conexão P2P.

Abertos:
* MatrixDefense: leandro@spfbl.net
* MX-Protection: gianspfbl@gmail.com
* Spamlet: noc@lhost.net.br
* Papuda: antispam@stoppay.net

Para se conectar, basta entrar em contato com cada administrador pelo endereço de e-mail e fazer a solicitação.

### Noticias sobre o SPFBL

<a href="https://suporte.icewarp.com.br/index.php?/News/NewsItem/View/59/nova-dnsbl-brasileira-spfbl">07/12/2015 IceWarp Brasil: Nova DNSBL Brasileira (SPFBL).</a></br>

<a href="http://abemd.org.br/noticias/eec-brasil016">27/04/2016 EEC: Painel sobre entregabilidade com representantes da SPFBL, UOL e Return Path.</a></br>

<a href="https://www.base64.com.br/suporte/multirbl">25/07/2016 Base64: O SPFBL.net entra na lista MultiRBL da Base64.</a></br>


### Forum de discussão SPFBL

Todas as discussões e dúvidas sobre o SPFBL estão sendo tratadas através do forum:

<https://groups.google.com/d/forum/spfbl>
