import socket
import random
import time
from packet import PacketUtils, MSS, SYN, ACK, FIN, DATA
from cryptography.fernet import Fernet

# --- Configurações do Servidor ---
SERVER_IP = '127.0.0.1'
SERVER_PORT = 12345
LOSS_PROBABILITY = 0.1  # 10% de chance de perder pacote (Simulação)
BUFFER_SIZE = 65535 # Tamanho do buffer de recepção (RWND)

def run_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SERVER_IP, SERVER_PORT))
    print(f"Servidor ouvindo em {SERVER_IP}:{SERVER_PORT}")

    expected_seq_num = 0
    crypto = None # Será inicializado no Handshake
    received_buffer = {} # Para armazenar pacotes fora de ordem (se necessário)
    
    # Arquivo de saída para validar integridade
    output_file = open("recebido_final.txt", "wb")
    
    start_time = None

    while True:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE + 100)
            
            # --- Simulação de Perda (Item 6.2) ---
            if random.random() < LOSS_PROBABILITY:
                # print(f"Simulando perda de pacote de {addr}")
                continue 

            seq_num, ack_num, flags, payload = PacketUtils.parse_packet(data)

            # --- Handshake (Início da Conexão e Troca de Chave) ---
            if flags & SYN:
                print("Recebido SYN. Iniciando Handshake.")
                # O payload do SYN contém a chave de criptografia (Item 5)
                key = payload
                crypto = Fernet(key)
                
                # Envia SYN-ACK
                response = PacketUtils.make_packet(0, seq_num + 1, SYN | ACK)
                sock.sendto(response, addr)
                expected_seq_num = seq_num + 1
                start_time = time.time()
                continue

            # --- Finalização (FIN) ---
            if flags & FIN:
                print("Recebido FIN. Encerrando conexão.")
                response = PacketUtils.make_packet(0, seq_num + 1, ACK | FIN)
                sock.sendto(response, addr)
                break

            # --- Processamento de Dados (Entrega Ordenada - Item 1) ---
            if flags & DATA:
                if seq_num == expected_seq_num:
                    # Pacote na ordem correta
                    decrypted_data = crypto.decrypt(payload)
                    output_file.write(decrypted_data)
                    
                    expected_seq_num += 1
                    
                    # ACK Acumulativo (Item 2)
                    # Envia ACK pedindo o próximo
                    ack_packet = PacketUtils.make_packet(0, expected_seq_num, ACK)
                    sock.sendto(ack_packet, addr)
                
                elif seq_num > expected_seq_num:
                    # Pacote fora de ordem (futuro). Opcional: Bufferizar ou descartar.
                    # Aqui vamos reenviar o ACK do último recebido corretamente (Go-Back-N style)
                    ack_packet = PacketUtils.make_packet(0, expected_seq_num, ACK)
                    sock.sendto(ack_packet, addr)

        except Exception as e:
            print(f"Erro: {e}")

    output_file.close()
    sock.close()
    if start_time:
        duration = time.time() - start_time
        print(f"Transferência concluída em {duration:.2f} segundos.")

if __name__ == "__main__":
    run_server()