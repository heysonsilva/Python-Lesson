import struct
from datetime import datetime

# Função para converter IPs em formato legível
def converter_ip(endereco):
    return ".".join(map(str, endereco.to_bytes(4, 'big')))

# Função para calcular média
def calcular_media(total, quantidade):
    return total / quantidade if quantidade > 0 else 0

# Inicializando variáveis
pares_ips = []
maior_tcp = 0
udp_total = 0
udp_contagem = 0
pacotes_truncados = 0
pacotes_ip = 0
inicio_tempo = None
fim_tempo = None

try:
    # Abrir e ler todo o conteúdo do arquivo
    with open("2024-nov-05--cap01.pcap", "rb") as arquivo:
        dados = arquivo.read()

    # Processar cabeçalho global
    posicao = 24  # Cabeçalho global do PCAP ocupa os primeiros 24 bytes

    while posicao < len(dados):
        # Ler cabeçalho do pacote (16 bytes)
        cabecalho_pacote = dados[posicao:posicao + 16]
        posicao += 16

        if len(cabecalho_pacote) < 16:
            break  # Terminar se não houver mais cabeçalhos completos

        ts, mTs, caplen, origlen = struct.unpack("<IIII", cabecalho_pacote)
        timestamp = ts + mTs / 1_000_000
        if inicio_tempo is None:
            inicio_tempo = timestamp
        fim_tempo = timestamp

        # Verificar pacotes truncados
        if caplen < origlen:
            pacotes_truncados += 1

        # Ler o pacote
        pacote = dados[posicao:posicao + caplen]
        posicao += caplen

        # Verificar se o pacote é Ethernet com IPv4 (EtherType 0x0800)
        if len(pacote) >= 34 and pacote[12:14] == b'\x08\x00':
            pacotes_ip += 1

            # Processar cabeçalho IPv4 (20 bytes)
            cabecalho_ip = pacote[14:34]
            valores_ip = struct.unpack("!BBHHHBBHII", cabecalho_ip)
            versao_ihl, _, total_length, _, _, _, protocolo, _, ip_origem, ip_destino = valores_ip

            # Extrair IPs e adicioná-los à lista de pares
            ip_origem_str = converter_ip(ip_origem)
            ip_destino_str = converter_ip(ip_destino)
            pares_ips.append((ip_origem_str, ip_destino_str))

            # Analisar protocolos TCP e UDP
            if protocolo == 6:  # TCP
                tamanho_tcp = caplen - 34
                maior_tcp = max(maior_tcp, tamanho_tcp)
            elif protocolo == 17:  # UDP
                tamanho_udp = caplen - 34
                udp_total += tamanho_udp
                udp_contagem += 1

    # Exibir resultados
    print(f"Tempo inicial da captura: {datetime.fromtimestamp(inicio_tempo)}")
    print(f"Tempo final da captura: {datetime.fromtimestamp(fim_tempo)}")
    print(f"Pacotes IPv4 analisados: {pacotes_ip}")
    print(f"Pacotes truncados: {pacotes_truncados}")
    print(f"Maior pacote TCP: {maior_tcp} bytes")
    print(f"Média de tamanho de pacotes UDP: {calcular_media(udp_total, udp_contagem):.2f} bytes")

    # Analisar IP mais frequente
    ip_frequencias = {}
    for src, dst in pares_ips:
        ip_frequencias[src] = ip_frequencias.get(src, 0) + 1
        ip_frequencias[dst] = ip_frequencias.get(dst, 0) + 1

    ip_mais_frequente = max(ip_frequencias, key=ip_frequencias.get, default="Nenhum IP encontrado")
    print(f"O IP mais ativo foi: {ip_mais_frequente} com {ip_frequencias.get(ip_mais_frequente, 0)} interações.")

except FileNotFoundError:
    print("Erro: O arquivo especificado não foi encontrado.")
except Exception as e:
    print(f"Ocorreu um erro: {e}")
