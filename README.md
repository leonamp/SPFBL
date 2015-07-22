# Serviço SPFBL

### Introdução

O serviço SPFBL é uma junção dos conceitos de SPF e DNSBL.

O propósito deste serviço é melhorar o processamento SPF e reduzir a quantidade de consultas externas de um servidor de e-mail, na qual utiliza SPF e pelo menos um serviço qualquer de DNSBL.

Uma vez iniciado o serviço, as consultas podem ser feitas por programas clientes, onde um exemplo é o script "spfblquery.sh".

A listagem é realizada através do ticket SPFBL, que é enviado juntamente com o qualificador SPF da consulta:

```
user:~# ./spfblquery.sh 200.160.7.130 gter-bounces@eng.registro.br eng.registro.br
PASS cPo6NAde1euHf6A2oT13sNlzCqnCH+PIuY/ClbDH2RJrV08UwvNblJPJiVo0E0SwAiO/lzSW+5BKdXXxDovqQPNqcfrvpBx5wPWgEC7EJ54=
```

Este ticket deve ser incluído no cabeçalho "Received-SPFBL" da mensagem para uma possível denúncia de SPAM futura.

Caso a mensagem seja considerada SPAM pelo usuário, a mensagem deve ser processada pelo script "spfblspam.sh", que vai extrair o ticket contido no campo "Received-SPFBL" e enviá-lo ao serviço SPFBL:

```
user:~# ./spfblspam.sh <caminho da mensagem SPAM>
Reclamação SPFBL enviada com sucesso.
```

Cada denúncia expira em sete dias após a data de recebimento da mensagem e só pode ser denunciada até três dias após o recebimento.

Se este projeto for útil para sua empresa, faça uma doação de qualquer valor para ajudar a mantê-lo:

![Donate](https://github.com/leonamp/SPFBL/blob/master/bicoin.png "1HVe5J3dziyEQ1BCDQamNWas6ruVHTyESy")

### Funcionalidades

Algumas alterações foram implementadas no SPFBl com a intenção de minimizar as respostas negativas ou incoerentes do SPF convencional.

##### Correção de sintaxe SPF

As vezes alguns administradores de DNS acabam cometendo erros pequenos ao registrar um SPF para um determinado domínio. O SPFBL é capaz de fazer algumas correções destes erros.

Por exemplo, o domínio "farmaciassaorafael.com.br", com o registro SPF "v=spf1 ipv4:177.10.167.165 -all", retorna falha no SPF convencional, mas o SPFBL reconhece um REGEX CIDR dentro de um token e deduz que o administrador queria dizer ip4 ou ip6.

Além disto, se um mecanismo não puder ser reconhecido pelo SPFBL, este mesmo mecanismo é apenas ignorado, dando chance de acontecer um match em outros mecanismos que são reconhecidos pelo SPFBL.

##### Merge de múltiplos registros SPF

Se o administrador registrar vários registros SPF para um determinado domínio, o SPFBL faz o merge de todos eles e considera como se fosse apenas um.

##### Mecanismos permissivos demais

O SPF convencional premite o registro de alguns mecanismos que são permissivos demais ao ponto de retornar sempre PASS para qualquer parâmetro utilizado na consulta.

Um destes mecanismos é o +all, que no SPFBL foi abolido e substituido por ?all sempre que encontrado.

Os mecanismos de blocos de IP que contém algum endereço IP reservado são ignorados pelo SPFBL.

##### Domínios sem registro SPF

Quando um domínio não tem registro SPF, o SPFBL considera a recomendação "best-guess" do SPF: [best-guess](http://www.openspf.org/FAQ/Best_guess_record).

Porém mesmo considerando esta recomendação, alguns domínios que não tem registro SPF não funcionam bem com o "best-guess". Nestes casos é possível registrar um "best-guess" específico para um determinado domínio. Por exemplo, o domínio "yahoo.com.br" não tem registro SPF e custuma enviar os seus e-mails pelos servidores listados no registro SPF do domínio "yahoo.com". A solução para este problema é adicionar o "best-guess" "v=spf1 redirect=yahoo.com" para o domínio "yahoo.com.br".

##### Cache dos registros SPF

O SPFBL mantém em cache todos os registros SPF encontrados e procura mantê-los atualizados em background de acordo com o volume de consultas de cada um deles.

##### Denúncia de SPAM

Quando o resultado da consulta SPFBL retorna um ticket, dentro dele segue informações sobre o responsável pelo envio e a data que a consulta foi realizada. Este ticket pode ser utilizado para formalizar uma denúncia,, que contabiliza para o responsável o peso de denúncia. Cada denúncia expira em sete dias após a data da consulta e não pode ser feita após três dias da consulta.

### Funcionamento

A seguir é mostrado como o SPFBL funciona internamente.

##### Respostas SPFBL

O SPFBL pode retorna todos os qualificadores do SPF convencional mais um qualifidador novo, chamado LISTED:

PASS <ticket>: permitir o recebimento da mensagem.
FAIL: rejeitar o recebimento da mensagem e informar à origem o descumprimento do SPF.
SOFTFAIL <ticket>: permitir o recebimento da mensagem mas marcar como suspeita.
NEUTRAL <ticket>: permitir o recebimento da mensagem.
NONE <ticket>: permitir o recebimento da mensagem.
LISTED: rejeitar o recebimento da mensagem e informar à origem a listagem em blacklist por sete dias.

##### Método de listagem

O SPFBL mantém uma flag para cada responsável. Esta flag tem três estados: WHITE, GRAY e BLACK. A seguinte máquina de estado é utlizada para manipular estas flags, sendo Pmin e Pmax probabilidades mínima e máxima de se tratar de SPAM:

![flagFSM.png](https://github.com/leonamp/SPFBL/blob/master/flagFSM.png "flagFSM.png")

Quando a flag estiver no estado BLACK para o responsável, então o SPFBL retorna LISTED.

##### Registro de provedores de e-mail

É possível registrar um provedor de e-mail no SPFBL. Sempre que um provedor for registrado, o SPFBL vai considerar os respectivos endereços de e-mail como responsável pelo envio, sendo que o provedor será isentado da responsabilidade.

##### Tipos de responsável

Sempre que o qualificador do SPFBL der PASS, o responsável considerado é o próprio remetente ou o domínio do remetente. Será considerado o remetente se o domínio dele estiver registrado no SPFBL como provedor de e-mail, como por exemplo: @hotmail.com, @gmail.com, @yahoo.com, etc. Caso contrário, o responsável é o domínio do remetente, mais o CNPJ ou CPF deste domínio quando este for da TDL BR.

Quando o qualificador for diferente de PASS, então o responsável considerado é o HELO ou o IP. Será considerado o HELO, com domínio e CNPJ ou CPF, se este for o reverso válido do IP. Caso contrário, o responsável é o IP.

##### Consulta de checagem SPFBL

É possível fazer uma consulta de checagem SPFBL. Este tipo de consulta não retorna ticket, mas mostra todos os responsáveis considerados pelo SPFBL, de modo que o administrador possa entender melhor a resposta de uma consulta normal SPFBL.

```
user:~# ./spfblcheck.sh 191.243.197.31 op4o@adsensum.com.br smtp-197-31.adsensum.com.br
PASS
.adsensum.com.br 2656±1218s GRAY 0.061
013.566.954/0001-08 2831±714s BLACK 0.108
@adsensum.com.br 2656±1218s GRAY 0.061
```

Na primeira linha, temos o qualificados SPF convencional. Nas demais linhas, temos uma sequencia dos responsáveis pelo envio na mensagem, sendo que a primeira coluna é o token do responsável, a segunda coluna é a frequência de envio, a terceira é a flag de listagem e a quarta coluna é a probabilidade daquele responsável estar enviando SPAM.

