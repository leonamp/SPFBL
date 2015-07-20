# Serviço SPFBL

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

Se este projeto for útil para sua empresa, faça uma doação de qualquer valor em Bitcoin para ajudar a manter as atualizações:

1HVe5J3dziyEQ1BCDQamNWas6ruVHTyESy

![alt tag](/bitcoin.png)
