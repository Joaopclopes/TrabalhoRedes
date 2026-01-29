import socket
import time
import matplotlib.pyplot as plt
from packet import PacketUtils, CryptoHandler, MSS, SYN, ACK, FIN, DATA

# --- Configurações do Cliente ---
SERVER_ADDR = ('127.0.0.1', 12345)
TIMEOUT = 0.5  # Segundos
TOTAL_PACKETS = 1000  # Reduzi para teste, aumente para 10.000 (Item 6.1)

# Variáveis de Controle de Congestionamento (Item 4.2)
cwnd = 1.0       # Janela de congestionamento (em pacotes)
ssthresh = 64.0  # Slow Start Threshold
rwnd = 1000      # Receive Window (estimado/fixo para simplificar)

# Estados do Congestionamento
SLOW_START = 0
CONGESTION_AVOIDANCE = 1
state = SLOW_START

# Métricas para Gráficos
history_cwnd = []
history_time = []

def run_client():
    global cwnd, ssthresh, state
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)

    # 1. Criptografia e Handshake (Item 5)
    crypto_handler = CryptoHandler()
    print("Iniciando Handshake e troca de chaves...")
    
    # Envia SYN com a chave
    syn_packet = PacketUtils.make_packet(0, 0, SYN, crypto_handler.key)
    sock.sendto(syn_packet, SERVER_ADDR)

    try:
        data, _ = sock.recvfrom(1024)
        _, ack_num, flags, _ = PacketUtils.parse_packet(data)
        if (flags & SYN) and (flags & ACK):
            print("Handshake concluído! Conexão estabelecida.")
            base = ack_num # SeqNum inicial esperado pelo server
        else:
            print("Falha no handshake.")
            return
    except socket.timeout:
        print("Timeout no Handshake.")
        return

    # 2. Geração de Dados (Item 6.1 - Dados Sintéticos)
    # Criando "arquivo" virtual
    all_data = [f"Pct {i:04d} ".encode() * 10 for i in range(TOTAL_PACKETS)] 
    # Cada entrada em all_data é um payload descriptografado

    next_seq_num = base
    window_base = base # O pacote mais antigo não confirmado
    packets_in_flight = {} # Buffer de envio {seq: packet}

    start_time = time.time()
    dup_acks = 0
    last_ack = -1

    while window_base < base + TOTAL_PACKETS:
        # --- Envio (respeitando CWND e RWND) ---
        # Janela efetiva = min(cwnd, rwnd)
        effective_window = int(min(cwnd, rwnd))
        
        while next_seq_num < window_base + effective_window and next_seq_num < base + TOTAL_PACKETS:
            idx = next_seq_num - base
            payload = crypto_handler.encrypt(all_data[idx])
            pkt = PacketUtils.make_packet(next_seq_num, 0, DATA, payload)
            
            sock.sendto(pkt, SERVER_ADDR)
            packets_in_flight[next_seq_num] = pkt
            next_seq_num += 1

        # --- Recebimento de ACKs ---
        try:
            data, _ = sock.recvfrom(1024)
            _, ack_num, flags, _ = PacketUtils.parse_packet(data)

            if flags & ACK:
                if ack_num > window_base:
                    # ACK Novo: Avança a janela
                    packets_acked = ack_num - window_base
                    window_base = ack_num
                    
                    # Remove do buffer
                    for i in range(packets_acked):
                         packets_in_flight.pop(window_base - 1 - i, None)

                    # --- Lógica de Controle de Congestionamento (Item 4) ---
                    if state == SLOW_START:
                        cwnd += packets_acked # Crescimento exponencial
                        if cwnd >= ssthresh:
                            state = CONGESTION_AVOIDANCE
                    elif state == CONGESTION_AVOIDANCE:
                        # Crescimento linear (aproximado): 1 / cwnd por ACK
                        cwnd += packets_acked * (1.0 / cwnd)
                    
                    dup_acks = 0
                    last_ack = ack_num

                elif ack_num == last_ack:
                    # ACK Duplicado
                    dup_acks += 1
                    if dup_acks == 3:
                        # Fast Retransmit (Opcional, mas recomendado TCP Reno)
                        # Reduz ssthresh e cwnd (corta pela metade)
                        ssthresh = max(cwnd / 2, 1)
                        cwnd = ssthresh + 3
                        # Reenvia pacote perdido
                        if window_base in packets_in_flight:
                            sock.sendto(packets_in_flight[window_base], SERVER_ADDR)

        except socket.timeout:
            # --- Timeout: Congestão Severa ---
            print(f"Timeout! Seq Base: {window_base}, CWND: {cwnd:.2f} -> 1")
            ssthresh = max(cwnd / 2, 1)
            cwnd = 1
            state = SLOW_START
            dup_acks = 0
            
            # Retransmite pacote base (Go-Back-N simplificado)
            if window_base in packets_in_flight:
                sock.sendto(packets_in_flight[window_base], SERVER_ADDR)
        
        # Coleta dados para o gráfico
        history_cwnd.append(cwnd)
        history_time.append(time.time() - start_time)

    # 3. Finalização
    print("Envio concluído. Enviando FIN...")
    fin_pkt = PacketUtils.make_packet(next_seq_num, 0, FIN)
    sock.sendto(fin_pkt, SERVER_ADDR)
    sock.close()

    # 4. Gerar Gráficos (Para o Relatório)
    plot_results(history_time, history_cwnd)

def plot_results(times, cwnds):
    plt.figure(figsize=(10, 5))
    plt.plot(times, cwnds, label="CWND (Tamanho da Janela)")
    plt.xlabel("Tempo (s)")
    plt.ylabel("Pacotes")
    plt.title("Controle de Congestionamento (TCP Reno Simulator)")
    plt.grid(True)
    plt.legend()
    plt.savefig("grafico_congestionamento.png")
    print("Gráfico salvo como 'grafico_congestionamento.png'")
    plt.show()

if __name__ == "__main__":
    run_client()