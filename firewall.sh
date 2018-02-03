#!/bin/bash

### BEGIN INIT INFO
# Provides:          firewall.sh
# Required-Start:    $local_fs $remote_fs $network $syslog
# Required-Stop:     $local_fs $remote_fs $network $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start firewall.sh at boot time
# Description:       Enable service provided by firewall.sh.
### END INIT INFO

iniciar_firewall(){
echo "################################################"
echo "# SCRIPT FIREWALL - COMPARTILHAMENTO DE REDE   #"                                                     #"
echo "# 08/05/2016                                   #"
echo "################################################"

externa="eth0"
interna="eth1"
rede_interna="192.168.50.0/24"

echo "Interface Rede Externa .......................... "$externa
echo "Interface Rede Interna .......................... "$interna
echo "Faixa de IP Rede Interna ........................ "$rede_interna

echo "Limpando Politicas .............................. [ OK ]" 
iptables -X
iptables -Z
iptables -F INPUT
iptables -F OUTPUT
iptables -F FORWARD
iptables -F -t nat
iptables -F -t filter
iptables -F -t mangle

echo "Aplicando nova politica ......................... [ OK ]"
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

echo "Ativa Modulos Basicos ........................... [ OK ]"
modprobe ip_tables
modprobe ip_conntrack
modprobe iptable_filter
modprobe iptable_mangle
modprobe iptable_nat
modprobe ipt_LOG
modprobe ipt_limit
modprobe ipt_state
modprobe ipt_REDIRECT
modprobe ipt_owner
modprobe ipt_REJECT
modprobe ipt_MASQUERADE
modprobe ip_conntrack_ftp
modprobe ip_nat_ftp

echo "Roteamento de Kernal ............................ [ OK ]"
echo 1 > /proc/sys/net/ipv4/ip_forward

echo "Compartilhar Internet ........................... [ OK ]"
iptables -t nat -A POSTROUTING -o $externa -j MASQUERADE

echo "Mantendo conexões estabelecidas ................. [ OK ]"
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED,NEW -j ACCEPT
iptables -A OUTPUT -m state --state RELATED,ESTABLISHED,NEW -j ACCEPT

echo "Logs de bloqueios ............................... [ OK ]"
iptables -A INPUT -j LOG
iptables -A OUTPUT -j LOG
iptables -A FORWARD -j LOG

echo "Regras DNAT para servidor WEB ................... [ OK ]"
iptables -t nat -A PREROUTING -i $externa -p tcp --dport 80 -j DNAT --to 192.168.50.5:80

echo "Bloqueio de sites ............................... [ OK ]"
iptables -A FORWARD -d 173.252.91.4/25 -j REJECT
iptables -A FORWARD -d 31.13.73.1/25 -j REJECT

#REGRAS FORWARD
echo "Permite ping pra Rede Externa ................... [ OK ]"
iptables -A FORWARD -i $interna -o $externa -p icmp -j ACCEPT

echo "Permite conexões da Rede Interna pra Externa .... [ OK ]"
iptables -A FORWARD -i $interna -o $externa -p tcp -m multiport --dports 80,443,3128,110,20,21,587,995,143,22,3389,25,5900,5100,3389 -j ACCEPT

echo "Regras cliente .................................. [ OK ]"
iptables -A OUTPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT

echo "Regras servidor ................................. [ OK ]"
iptables -A INPUT -p tcp -i $interna --dport 22 -j ACCEPT
iptables -A INPUT -p tcp -i $interna -m multiport --dports 3128,443,445,113,80,587,25,22,110,53,139,5900,5100,3389 -j ACCEPT
iptables -A INPUT -p udp -i $interna -m multiport --dports 53,110,67,68,137,113,443,138 -j ACCEPT 

#echo "Redirecionamento de porta ....................... [ OK ]"
#iptables -t nat -A PREROUTING -i $interna -p tcp --dport 80 -j REDIRECT --to-port 3128 

echo "Liberando ping ICMP ............................. [ OK ]"
iptables -A INPUT -p icmp -m limit --limit 1/s --limit-burst 1 -j ACCEPT
iptables -A INPUT -p icmp -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix PING-DROP:
iptables -A INPUT -p icmp -j DROP
iptables -A OUTPUT -p icmp -j ACCEPT

echo "Permite conexões loopback ....................... [ OK ]"
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

echo "##################### SEGURANÇA ########################"

echo "Segurança contra IP Spoofing .................... [ OK ]"
echo 1 > /proc/sys/net/ipv4/conf/default/rp_filter
iptables -A INPUT -m state --state INVALID -j DROP

echo "Proteção contra alteração de rota ............... [ OK ]"
echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects

echo "Proteção contra alteração de caminho ............ [ OK ]"
echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route

echo "Proteção contra responses bogus ................. [ OK ]"
echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses

echo "Bloqueando traceroute ........................... [ OK ]"
iptables -A INPUT -p udp -s 0/0 -i $interna --dport 33435:33525 -j DROP

echo "Proteção para SYN flood ......................... [ OK ]"
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
iptables -A FORWARD -p tcp --syn -m limit --limit 1/s -j ACCEPT
iptables -A FORWARD -p tcp --syn -j DROP

echo "Negando portas invalidas (trojans, trinoo) ...... [ OK ]"
iptables -A INPUT -p tcp -i $externa -m multiport --dports 666,4000,6000,6006,16660,27444,27665,31335,34555,35555 -j DROP
iptables -A INPUT -p tcp -i $interna -m multiport --dports 1433,6670,6711,6712,6713,12345,12346,20034,31337,6000 -j DROP

echo "Proteção contra telnet .......................... [ OK ]"
iptables -A INPUT -p TCP -i $externa --dport telnet -j DROP

echo "Dropando pacotes TCP indesejaveis ............... [ OK ]"
iptables -A FORWARD -p tcp ! --syn -m state --state NEW -j DROP

echo "Proteção contra worms ........................... [ OK ]"
iptables -A FORWARD -p tcp --dport 135 -i $externa -j REJECT

echo "Proteção contra ICMP Broadcasting ............... [ OK ]"
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

echo "Proteção contra Port Scanners ocultos ........... [ OK ]"
iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT
iptables -A FORWARD -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT

echo "Proteção contra Ping da morte ................... [ OK ]"
iptables -A FORWARD -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT

echo "Proteção contra IP Spoofing ..................... [ OK ]"
iptables -A INPUT -s 172.16.0.0/12 -i $externa -j DROP
iptables -A INPUT -s 127.0.0.0/8 -i $externa -j DROP
iptables -A INPUT -s 10.0.0.0/8 -i $externa -j DROP
iptables -A INPUT -s 192.168.0.0/16 -i $externa -j DROP

echo "Bloqueando Pacotes Fragmentados.................. [ OK ]"
iptables -A INPUT -i $externa -f -j LOG --log-prefix "Pacote Fragmentado: "
iptables -A INPUT -i $externa -f -j DROP
iptables -A INPUT -i $interna -f -j LOG --log-prefix "Pacote Fragmentado: "
iptables -A INPUT -i $interna -f -j DROP

}
parar_firewall(){

echo "Parando Firewall ................................ [ OK ]"
iptables -X
iptables -F 
iptables -t nat -F
iptables -t filter -F
iptables -t mangle -F

echo "Liberando Politicas ............................. [ OK ]"
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT

echo "Parando  ................................ [ OK ]"
echo 0 > /proc/sys/net/ipv4/ip_forward

echo "Firewall Desativado............................. [ OK ]"
}

case "$1" in
"start") iniciar_firewall ;;
"stop") parar_firewall ;;
"restart") parar_firewall; iniciar_firewall;;
*) echo "Use os parametros | start | stop | restart |"
esac
