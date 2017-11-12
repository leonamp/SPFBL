# Serviço SPFBL

### Introdução

O serviço SPFBL é uma junção dos conceitos de SPF e DNSBL.

O propósito deste serviço é melhorar o processamento SPF e reduzir a quantidade de consultas externas de um servidor de e-mail, na qual utiliza SPF e pelo menos um serviço qualquer de DNSBL.

Uma vez iniciado o serviço, as consultas podem ser feitas por programas clientes, como por exemplo o script "spfbl.sh". Atenção! O script "spfbl.sh" necessita do pacote "netcat" (command "nc") instalado para funcionar corretamente.

A listagem é realizada através do ticket SPFBL, que é enviado juntamente com o qualificador SPF da consulta:

```
user:~# spfbl.sh query "200.160.7.130" "gter-bounces@eng.registro.br" "eng.registro.br" "destinatario@destino.com.br"
PASS u2QbRApbumU-hCrf-vhKQd7NInkDRkwlrKnz9WaJBlatLpxXWR8C8Qwbw5LEe4bGz91CMbTzv_2nNS0LQv3C18z9oWgP6t7jr1N0qLmsuEk
```

Este ticket deve ser incluído no cabeçalho "Received-SPFBL" da mensagem para uma possível denúncia de SPAM futura.

Caso o serviço seja configurado para trabalhar com HTTP, os tickets serão enviados com seus respectivos prefixos da URL de quem gerou o ticket:
```
user:~# spfbl.sh query "200.160.7.130" "gter-bounces@eng.registro.br" "eng.registro.br" "destinatario@destino.com.br"
PASS http://<hostname>[:<port>]/u2QbRApbumU-hCrf-vhKQd7NInkDRkwlrKnz9WaJBlatLpxXWR8C8Qwbw5LEe4bGz91CMbTzv_2nNS0LQv3C18z9oWgP6t7jr1N0qLmsuEk
```

Este último método de denuncia com URL facilita o desenvolvimento de novas ferramentas, como plugins de mail client por exemplo, para que as denúncias sejam feitas diretamente pelo destinatário, aonde quer que ele esteja.

Caso a mensagem seja considerada SPAM pelo usuário, a mensagem deve ser processada pelo comando "spfbl.sh spam", que vai extrair o ticket contido no campo "Received-SPFBL" e enviá-lo ao serviço SPFBL:

```
user:~# spfbl.sh spam <caminho da mensagem SPAM>
Reclamação SPFBL enviada com sucesso.
```

Cada denúncia expira em sete dias após a data de recebimento da mensagem e só pode ser denunciada até cinco dias após o recebimento.

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

##### Greylisting

A mensagem será atrasada 25min sempre que o responsável estiver com reputação YELLOW.

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

O SPFBL retorna todos os qualificadores do SPF convencional mais dez qualificadores novos, chamados LISTED, BLOCKED, SPAMTRAP, INEXISTENT, HOLD, WHITE, FLAG, GREYLIST, NXDOMAIN e INVALID:

* PASS &lt;ticket&gt;: permite o recebimento da mensagem.
* FAIL: rejeita o recebimento da mensagem e informa à origem o descumprimento do SPF.
* SOFTFAIL &lt;ticket&gt;: permite o recebimento da mensagem mas marca como suspeita.
* NEUTRAL &lt;ticket&gt;: permite o recebimento da mensagem.
* NONE &lt;ticket&gt;: permite o recebimento da mensagem.
* LISTED [&lt;url&gt;]: atrasa o recebimento da mensagem, informa à origem a listagem temporária em blacklist e envia e-mail com URL de liberação quando for o caso.
* BLOCKED [&lt;url&gt;]: rejeita o recebimento da mensagem e informa à origem o seu bloqueio manual, com possibilidade de solicitar desbloqueio diretamente ao destinatário com auxílio da URL.
* FLAG: aceita o recebimento e redirecione a mensagem para a pasta SPAM.
* SPAMTRAP: descarta silenciosamente a mensagem e informa à origem que a mensagem foi recebida com sucesso.
* INEXISTENT: rejeita a mensagem e informa à origem que o destinatário não existe.
* GREYLIST: atrasar a mensagem informando à origem ele está em greylisting.
* NXDOMAIN: rejeita o recebimento e informa à origem que o domínio do remetente não existe.
* INVALID: rejeita o recebimento e informa à origem que o IP ou o endereço do remetente não é válido.
* WHITE: aceita a mensagem e a encaminha imediatamente para roteamento sem passar por outros filtros, exceto antivírus.
* HOLD: congelar a mensagem e aguardar pela definição do usuário.

##### Método de listagem

O SPFBL mantém uma flag de reputação para cada identificador. Esta flag tem três estados: GREEN, YELLOW e RED. A seguinte máquina de estado é utlizada para manipular estas flags, sendo P a probabilidade da mensagem ser SPAM segundo sua reputação atual na rede P2P:

![flagFSM.png](https://github.com/leonamp/SPFBL/blob/master/doc/flagFSM.png "flagFSM.png")

Quando a flag estiver no estado RED para o identificador, então o SPFBL retorna FLAG. Quando o MTA receber este retorno FLAG, deve incluir no cabeçalho a flag padrão do Spamassassin "X-Spam-Flag: YES" de modo ao MTA seguir o roteamento da mensagem para a pasta SPAM do usuário.

Quando a flag estiver no estado YELLOW para o identificador, então o SPFBL retorna GREYLISTED para que o MTA atrase a mensagem até a finalização do greylisting.

##### Sistema de feedback

Devido à natureza descentralizada do SPFBL, todo feedback é passado na própria camada SMTP. Isso facilita o trabalho do enviador pois ele não precisa se cadastrar, como ocorre em sistemas de feeback loop de grandes provedores. Tudo que ele precisa fazer é olhar nos registros de LOG do MTA de saída.

O prefixo de rejeição do SPFBL segue este padrão e o uso deste prefixo é obrigatório para todos que utilizam o sistema SPFBL:
```
5.7.1 SPFBL <message>
```

A mensagem da rejeição deve esplicar o motivo da mesma de tal forma que o enviador seja capaz de tomar providências para reduzir o volume de envio de mensagens indesejadas na Internet.

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


##### Painel de controle

O SPFBL possui um painel de controle simples para o usuário manipular corretamente listas de bloqueio e liberação dos remetentes.

![Panel](https://github.com/leonamp/SPFBL/blob/master/doc/panel.png "Painel de controle")

Para usar o painel de controle, é necessário ter MTA cliente e usuário devidamente cadastrados:
```
spfbl.sh client add <cidr> <zone> SPFBL <email>
spfbl.sh user add <email> <name>
```

Feito isso, o painel de controle pode ser acessado pela URL:
```
http://<hostname>/<email>
```

Na primeira vez que o usuário entrar nesta URL, o SPFBL iniciará um processo de cadastro TOTP, enviando um e-mail para o usuário com o QRcode contendo o segredo TOPT dele.

Para acessar corretamente o QRcode, é necessário baixar o aplicativo Google Authenticator, em seu celular, e ler o mesmo QRcode com este aplicativo.

O aplicativo irá gerar uma senha TOPT a cada minuto para que o usuário possa entrar com segurança na plataforma.


### Descentralização do SPFBL

A descentralização do serviço SPFBL deve ser feito através de redes P2P:

![p2pNetwork](https://github.com/leonamp/SPFBL/blob/master/doc/p2pNetwork.png "p2pNetwork.png")

Aqui vemos um exemplo de rede com três pools, onde cada pool tem um servidor, cada servidor SPFBL tem três servidores de e-mail e cada servidor de e-mail tem três usuários.

Responsabilidades dos elementos:

* Usuário: denunciar as mensagens SPAM que passam para ele utilizando de ferramentas disponibilizadas pelo administrador do seu MX.
* Administrador do MX: fornecer ferramentas de denúncia para seus usuários e bloquear permanentemente as fontes SPAM 100% comprovadas.
* Administrador do pool: criar regras de utilização do pool, onde os administradores MX decidem se desejam aderir ao pool, verifiar se as regras estão sendo cumpridas e se conectar a outros pools que tenham ideais de bloqueio semelhantes ao dele.

O ideia de se conectar a outros pool com semelhança de ideais de bloqueio serve para criar uma rede de confiança, onde um pool sempre irá enviar informações na qual seu par concorde sempre. Não é correto um pool enviar informação de bloqueio sendo que o outro pool não concorde. Neste caso o pool que recebeu a informação deve passar a rejeitar as informações do pool de origem e procurar outros pools com melhor reputação.


##### Como iniciar o serviço SPFBL

https://github.com/leonamp/SPFBL/wiki/Primeiros-passos-para-iniciar-o-SPFBL

##### Blocklist

https://github.com/leonamp/SPFBL/wiki/Primeiros-Passos---Comando:-block

##### Spamtrap

https://github.com/leonamp/SPFBL/wiki/Primeiros-Passos---Comando:-trap

##### Whitelist

https://github.com/leonamp/SPFBL/wiki/Primeiros-Passos---Comando:-white

##### Automação da Whitelist

https://github.com/leonamp/SPFBL/wiki/Automa%C3%A7%C3%A3o-da-Whitelist

##### Integração com Dovecot

https://github.com/leonamp/SPFBL/wiki/Integra%C3%A7%C3%A3o-com-Dovecot---SPFBL

##### Integração com Postfix

https://github.com/leonamp/SPFBL/wiki/Integra%C3%A7%C3%A3o-com-Postfix---SPFBL

##### Integração com Zimbra

https://github.com/leonamp/SPFBL/wiki/Integra%C3%A7%C3%A3o-com-Zimbra---SPFBL

##### Integração com Exim

https://github.com/leonamp/SPFBL/wiki/Integra%C3%A7%C3%A3o-com-Exim-SPFBL

##### Integração com Exim do cPanel

https://github.com/leonamp/SPFBL/wiki/Integra%C3%A7%C3%A3o-com-Exim-do-cPanel---SPFBL

##### Como cadastrar peers

https://github.com/leonamp/SPFBL/wiki/Primeiros-Passos---Comando:-peer

##### Como administrar listas de retenção dos peers

https://github.com/leonamp/SPFBL/wiki/peer---administrando-listas-de-reten%C3%A7%C3%A3o


### Pools conhecidos em funcionamento

Aqui vemos alguns pools em funcionamento para que novos membros possam se cadastrar para consulta, quando aberto, ou para cadastrar conexão P2P.

Abertos:
* MatrixDefense: leandro@spfbl.net
* MX-Protection: gian.spfbl@gmail.com
* Spamlet: noc@lhost.net.br
* Papuda: antispam@stoppay.net

Para se conectar, basta entrar em contato com cada administrador pelo endereço de e-mail e fazer a solicitação.


### O desenvolvedor

Se houver interesse um utilizar este serviço sem implementá-lo em servidor próprio, podemos ceder nosso próprio servidor. Para isto, basta enviar para um e-mail para leandro@spfbl.net com a lista de blocos de IP utilizados, o volume diário de recebimento e o MTA utilizado pelos seus terminais MX para liberação do firewall.

Se este projeto for útil para sua empresa, faça uma doação de qualquer valor para ajudar a mantê-lo:

PayPal em Real:<br>
[![](https://www.paypalobjects.com/pt_BR/BR/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=7FKHCPESUWH4L)

PayPal em Dólar:<br>
[![](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=77CP8774HLDU8)

Patreon:<br>
<a href="https://www.patreon.com/bePatron?u=2430613">Patreon SPFBL project</a>

Bitcoin:<br>
![Donate](https://github.com/leonamp/SPFBL/blob/master/doc/bicoin.png "1HVe5J3dziyEQ1BCDQamNWas6ruVHTyESy")

Página oficial:<br>
<a href="http://spfbl.net">SPFBL oficial website</a>

Palestra GTER 42:<br>
[![GTER42](https://img.youtube.com/vi/7OAL9ulMEy4/0.jpg)](https://www.youtube.com/watch?v=7OAL9ulMEy4)

Lojas:<br>
<a href="https://www.montink.com.br/loja/spfbl">Camisetas SPFBL.net</a>


### Noticias sobre o SPFBL

<a href="https://suporte.icewarp.com.br/index.php?/News/NewsItem/View/59/nova-dnsbl-brasileira-spfbl">07/12/2015 IceWarp Brasil: Nova DNSBL Brasileira (SPFBL).</a></br>

<a href="http://abemd.org.br/noticias/eec-brasil016">27/04/2016 EEC: Painel sobre entregabilidade com representantes da SPFBL, UOL e Return Path.</a></br>

<a href="https://www.base64.com.br/suporte/multirbl">25/07/2016 Base64: O SPFBL.net entra na lista MultiRBL da Base64.</a></br>

<a href="http://www.abrahosting.org.br/Evento/RodadadeNegocios.html">01/09/2016 Abrahosting: participação do SPFBL.net na Rodada de Negócios.</a></br>

<a href="http://multirbl.valli.org/lookup/">14/09/2016 Valli.org: O SPFBL.net entra na lista MultiRBL da valli.org.</a></br>

<a href="http://nic.br/semanainfrabr/">09/12/2016 Nic.Br: VI Semana de Infraestrutura da Internet no Brasil.</a></br>

<a href="http://www.dnsbl.info/">20/08/2017 DNSBL.info: O SPFBL.net entra na lista MultiRBL da dnsbl.info.</a></br>


### Forum de discussão SPFBL

Todas as discussões e dúvidas sobre o SPFBL estão sendo tratadas através do forum:

<https://groups.google.com/d/forum/spfbl>
