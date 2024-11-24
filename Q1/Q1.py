# Solicita os parâmetros de entrada ao usuário
origem = str(input("Digite o nome do arquivo origem.txt: "))
destino = str(input("Digite o nome do arquivo destino.txt: "))
palavra_passe = str(input("Digite a palavra passe: "))

# Converte cada letra da palavra-passe para o código ASCII
ascii_passe = [ord(letra) for letra in palavra_passe]
tamanho_passe = len(ascii_passe)

# Abre os arquivos de origem e destino
original = open(origem, "rb")
destinado = open(destino, "wb")

# Lê o primeiro byte do arquivo de origem
byte_origem = original.read(1)
contador_passe = 0

# Processa cada byte do arquivo de origem
while byte_origem:
    # Faz a operação XOR com o valor ASCII da palavra-passe
    byte_destino = bytes([byte_origem[0] ^ ascii_passe[contador_passe]])

    # Escreve o byte resultante no arquivo de destino
    destinado.write(byte_destino)

    # Atualiza o contador para a próxima letra da palavra-passe
    contador_passe = (contador_passe + 1) % tamanho_passe

    # Lê o próximo byte do arquivo de origem
    byte_origem = original.read(1)

# Fecha os arquivos
original.close()
destinado.close()

print(f"Arquivo {destino} criado com sucesso.")



