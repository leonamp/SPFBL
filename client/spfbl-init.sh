#!/bin/sh
####
# SPFBL - controle do serviço
# Original: Roberto Almeida <falecom@robertoalmeida.com>
#
# Uso (como root): spfbl-init {start|stop|restart|status|force-stop|run}
#   start       inicia em segundo plano, só se não houver outra instância
#   stop        SHUTDOWN pela porta de administração e espera até 480 s
#   restart     stop e, só se parou, start
#   status      mostra se está rodando, o PID e a memória disponível
#   force-stop  TERM e, depois de 120 s, KILL (último recurso)
#   run         inicia em primeiro plano (para uma unidade do systemd)
#
# Proteções do start:
#   - recusa se já existe processo do SPFBL.jar;
#   - recusa se a porta de administração já está ocupada;
#   - recusa se a memória disponível não comporta o heap mais a margem
#     (com -Xms igual ao -Xmx e AlwaysPreTouch, a JVM ocupa o heap inteiro
#     na partida: duas instâncias esgotam a RAM e travam a máquina);
#   - uma operação de controle por vez (flock).
####

JAVA=/usr/bin/java
SPFBL_DIR=/opt/spfbl
JAR=$SPFBL_DIR/SPFBL.jar
LOG_DIR=/var/log/spfbl
PID_FILE=/run/spfbl.pid
LOCK_FILE=/run/spfbl-init.lock
ADMIN_PORT=9875
# RAM nominal da instância, em MB (32768 para uma instância de 32 GB), e
# não o que o sistema enxerga, que vem abaixo disso: o MemTotal perde o que
# o kernel reserva, e os blocos de memória online do /sys (a soma do lsmem)
# perdem o buraco de endereços abaixo de 4 GB (32256 MB numa de 32 GB).
# Os blocos do /sys chegam mais perto; sem eles, vale o MemTotal. Os dois
# são arredondados para cima no passo dos tipos de instância: múltiplos de
# 4 GB acima de 3 GB, e de 512 MB nas menores (1 GB, 2 GB).
instance_mb() {
    dir=/sys/devices/system/memory
    mb=0
    if [ -r "$dir/block_size_bytes" ]; then
        size=$(cat "$dir/block_size_bytes")
        count=$(grep -l '^online' "$dir"/memory*/state 2>/dev/null | wc -l)
        mb=$(( count * 0x$size / 1048576 ))
    fi
    if [ "$mb" -le 0 ]; then
        mb=$(awk '/^MemTotal:/ { print int(($2 + 1023) / 1024) }' /proc/meminfo)
    fi
    if [ "$mb" -gt 3072 ]; then
        step=4096
    else
        step=512
    fi
    echo $(( (mb + step - 1) / step * step ))
}

# Heap (-Xms e -Xmx): sempre 50% da RAM da instância, em múltiplos de
# 256 MB. Ao trocar o tipo da instância, o heap acompanha sozinho no
# próximo start (64 GB dão 32 GB; 8 GB dão 4 GB).
HEAP_MB=$(( $(instance_mb) / 2 / 256 * 256 ))
MARGIN_MB=3072          # memória livre exigida além do heap
# Espera pelo SHUTDOWN: o SPFBL espera até 5 minutos as operações críticas
# em andamento (USER MOVE, captura do PayPal) e depois grava tudo em disco.
STOP_WAIT=480           # segundos de espera pelo SHUTDOWN
# Espera pelo TERM no force-stop: o TERM também faz o desligamento
# ordenado (gancho na JVM), mas aqui o SHUTDOWN já falhou.
TERM_WAIT=120

JAVA_OPTS="-Xms${HEAP_MB}m -Xmx${HEAP_MB}m -XX:+AlwaysPreTouch \
 -Xlog:gc*:file=$LOG_DIR/gc-%t.log:time,uptime:filecount=10,filesize=50m \
 -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=$LOG_DIR/"

# PIDs da JVM do SPFBL. O padrão começa no caminho do java, então não
# pega o sudo, o shell nem este script.
running_pids() {
    pgrep -f "^$JAVA .*-jar $JAR"
}

is_running() {
    [ -n "$(running_pids)" ]
}

port_busy() {
    # Sem o -H do ss, que o iproute2 antigo não tem: a quarta coluna é o
    # endereço local, terminado em :porta.
    ss -ltn 2>/dev/null | awk -v p=":$ADMIN_PORT" 'NR > 1 && substr($4, length($4) - length(p) + 1) == p { found = 1 } END { exit !found }'
}

mem_available_mb() {
    # MemAvailable só existe a partir do kernel 3.14; antes, a estimativa
    # é MemFree + Buffers + Cached.
    awk '/^MemAvailable:/ { a = $2 } /^MemFree:/ { f = $2 } /^Buffers:/ { b = $2 } /^Cached:/ { c = $2 }
         END { print int((a != "" ? a : f + b + c) / 1024) }' /proc/meminfo
}

check_start() {
    PIDS=$(running_pids | tr '\n' ' ')
    if [ -n "$PIDS" ]; then
        echo "[start] SPFBL já está rodando (PID $PIDS). Start recusado."
        return 1
    fi
    if port_busy; then
        echo "[start] A porta $ADMIN_PORT já está em uso por outro processo. Start recusado."
        ss -ltnp "sport = :$ADMIN_PORT" 2>/dev/null
        return 1
    fi
    AVAIL=$(mem_available_mb)
    NEED=$((HEAP_MB + MARGIN_MB))
    if [ "${AVAIL:-0}" -lt "$NEED" ]; then
        echo "[start] Memória disponível ${AVAIL} MB, abaixo dos ${NEED} MB exigidos (heap ${HEAP_MB} MB + margem ${MARGIN_MB} MB). Start recusado."
        return 1
    fi
    if [ ! -f "$JAR" ]; then
        echo "[start] $JAR não encontrado."
        return 1
    fi
    mkdir -p "$LOG_DIR"
    return 0
}

start() {
    check_start || return 1
    cd "$SPFBL_DIR" || return 1
    echo "[start] Iniciando o SPFBL"
    # 9>&- fecha o descritor da trava: a JVM não pode herdá-la.
    nohup setsid $JAVA $JAVA_OPTS -jar "$JAR" >> "$LOG_DIR/console.log" 2>&1 < /dev/null 9>&- &
    PID=$!
    echo "$PID" > "$PID_FILE"
    sleep 3
    if kill -0 "$PID" 2>/dev/null; then
        echo "[start] SPFBL iniciado (PID $PID). Saída da JVM em $LOG_DIR/console.log."
        return 0
    else
        echo "[start] A JVM terminou logo na partida. Últimas linhas de $LOG_DIR/console.log:"
        tail -n 20 "$LOG_DIR/console.log"
        rm -f "$PID_FILE"
        return 1
    fi
}

run() {
    check_start || return 1
    cd "$SPFBL_DIR" || return 1
    echo $$ > "$PID_FILE"
    exec $JAVA $JAVA_OPTS -jar "$JAR" 9>&-
}

stop() {
    PID=$(running_pids | head -n 1)
    if [ -z "$PID" ]; then
        echo "[stop] SPFBL não está rodando."
        rm -f "$PID_FILE"
        return 0
    fi
    echo "[stop] Parando o SPFBL (PID $PID)"
    if command -v jstack > /dev/null 2>&1; then
        timeout 30 jstack "$PID" > "$SPFBL_DIR/threaddump.txt" 2>&1
    fi
    echo "SHUTDOWN" | timeout 10 nc localhost "$ADMIN_PORT" > /dev/null 2>&1
    i=0
    while [ "$i" -lt "$STOP_WAIT" ]; do
        is_running || break
        sleep 1
        i=$((i + 1))
    done
    if is_running; then
        echo "[stop] O SPFBL não parou em ${STOP_WAIT} s e continua rodando. Veja o log; em último caso, use force-stop."
        return 1
    fi
    rm -f "$PID_FILE"
    echo "[stop] SPFBL parado em ${i} s."
    return 0
}

force_stop() {
    PIDS=$(running_pids)
    if [ -z "$PIDS" ]; then
        echo "[force-stop] SPFBL não está rodando."
        rm -f "$PID_FILE"
        return 0
    fi
    echo "[force-stop] TERM para $PIDS"
    kill -TERM $PIDS
    i=0
    while [ "$i" -lt "$TERM_WAIT" ]; do
        is_running || break
        sleep 1
        i=$((i + 1))
    done
    PIDS=$(running_pids)
    if [ -n "$PIDS" ]; then
        echo "[force-stop] KILL para $PIDS"
        kill -KILL $PIDS
        sleep 2
    fi
    rm -f "$PID_FILE"
    is_running && return 1
    return 0
}

wait_memory() {
    # Depois do stop, o kernel ainda devolve as páginas do heap antigo
    # (-XX:+AlwaysPreTouch ocupa todas): espera até 60 s pela memória.
    # Se não bastar, o check_start do start recusa como sempre.
    NEED=$((HEAP_MB + MARGIN_MB))
    i=0
    while [ "$i" -lt 60 ] && [ "$(mem_available_mb)" -lt "$NEED" ]; do
        sleep 1
        i=$((i + 1))
    done
    [ "$i" -gt 0 ] && echo "[restart] Memória liberada em ${i} s."
    return 0
}

status() {
    PIDS=$(running_pids | tr '\n' ' ')
    if [ -n "$PIDS" ]; then
        echo "SPFBL rodando (PID $PIDS)."
    else
        echo "SPFBL parado."
    fi
    echo "Memória disponível: $(mem_available_mb) MB."
    [ -n "$PIDS" ]
}

if [ "$(id -u)" -ne 0 ]; then
    echo "Rode como root: sudo $0 $1"
    exit 1
fi

# Uma operação de controle por vez: um segundo start enquanto o primeiro
# ainda está subindo é recusado na hora.
exec 9> "$LOCK_FILE"
if [ "$1" != "status" ] && ! flock -n 9; then
    echo "Outra operação de controle do SPFBL está em andamento. Tente de novo em instantes."
    exit 1
fi

case "$1" in
    start)
        start
    ;;
    run)
        run
    ;;
    stop)
        stop
    ;;
    restart)
        stop && wait_memory && start
    ;;
    force-stop)
        force_stop
    ;;
    status)
        status
    ;;
    *)
        echo "*** Uso: $0 {start|stop|restart|status|force-stop|run}"
        exit 1
esac
exit $?
