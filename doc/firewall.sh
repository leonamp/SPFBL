#!/bin/bash
# Firewall example
# Copyright: Alexandre Pereira Bühler and Simão & Bühler Ltda
# English: https://creativecommons.org/licenses/by/4.0/
# Portuguese: https://creativecommons.org/licenses/by/4.0/deed.pt_BR
# e-mail: alexandre@simaoebuhler.com.br

# Observação:
# 1) Não especifiquei interfaces eth0, eth1 pois há servidores com várias interfaces respondendo pelos mesmos serviços.
# Logo, se colocasse no firewall para bloquear a interface eth0, os abelhudos ainda poderiam usar a eth0:0 , eth1 e etc para acessar.
# 2) Onde se lê xxx.xxx.xxx.xxx/xx entenda como a rede interna do seu servidor. Ou seja a range de ips do seu servidor.
# 3) Onde se lê zzz.zzz.zzz.zzz/zz entenda como a rede externa do seu servidor. Ou seja a range de ips  liberada para um cliente seu.


### Apaga e limpa a chain SPFBL (somente na primeira execução haverá erro pois a chain SPFBL não existe)

# Limpa todas as regras somente na chain do SPFBL para não atrapalhar o firewall preexistente (Netfilter/Iptables)
iptables -t filter -F SPFBL
ip6tables -t filter -F SPFBL

# apaga a chamada da chain
iptables -t filter -D INPUT -j SPFBL
ip6tables -t filter -D INPUT -j SPFBL

# apaga a chain
iptables -t filter -X SPFBL
ip6tables -t filter -X SPFBL

### Cria chain SPFBL

# criamos a  chain SPFBL para que não interfira com regras preexistentes no Netfilter (Iptables)

iptables -t filter -N SPFBL
ip6tables -t filter -N SPFBL


# criamos um pulo (-j) do chain INPUT para o chain SPFBL e o adicionamos como primeira regra via INPUT 1 de forma a ser consultada antes de tudo.

iptables -t filter -I INPUT 1 -j SPFBL
ip6tables -t filter -I INPUT 1 -j SPFBL

### SPFBL ADMIN

# Abre a porta para consultas internas e "Log and drop" todas as outras.
iptables -t filter -A SPFBL -s 127.0.0.1/32 -p tcp --dport 9875 -j ACCEPT
iptables -t filter -A SPFBL -s xxx.xxx.xxx.xxx/xx  -p tcp --dport 9875 -j ACCEPT
iptables -t filter -A SPFBL  -p tcp --dport 9875 -j LOG --log-prefix "ADMIN "
ip6tables -t filter  -A SPFBL  -p tcp --dport 9875 -j LOG --log-prefix "ADMIN "
iptables -t filter  -A SPFBL  -p tcp --dport 9875 -j DROP
ip6tables -t filter  -A SPFBL  -p tcp --dport 9875 -j DROP

### SPFBL HTTP

# Abre a consulta via http
iptables -t filter  -A SPFBL -p tcp --dport 8090 -j ACCEPT
ip6tables -t filter -A SPFBL  -p tcp --dport 8090 -j ACCEPT

### SPFBL P2P

# Abre a consulta na rede P2P
iptables -t filter  -A SPFBL  -p udp --dport 9877 -j ACCEPT
ip6tables -t filter  -A SPFBL  -p udp --dport 9877 -j ACCEPT

### SPFBL QUERY

# Aceita o seu usuário postmaster <postmaster@xxxxxxxx.xxx.xx>.
iptables -t filter  -A SPFBL  -s 127.0.0.1/32 -p tcp --dport 9877 -j ACCEPT
iptables -t filter  -A SPFBL  -s xxx.xxx.xxx.xxx/xx -p tcp --dport 9877 -j ACCEPT

# Aceita um usuário/(servidor MTA) externo. Se quiser liberar a consulta descomente a linha abaixo e crie quantas forem necessárias.
# iptables -t filter -A SPFBL -s zzz.zzz.zzz.zzz/zz -p tcp --dport 9877 -j ACCEPT


#  "Log and drop" todas as outras portas.
iptables -t filter  -A SPFBL  -p tcp --dport 9877 -j LOG --log-prefix "SPFBL "
ip6tables -t filter  -A SPFBL  -p tcp --dport 9877 -j LOG --log-prefix "SPFBL "
iptables  -t filter -A SPFBL  -p tcp --dport 9877 -j DROP
ip6tables -t filter  -A SPFBL  -p tcp --dport 9877 -j DROP
