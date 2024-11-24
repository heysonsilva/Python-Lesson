import hashlib
import time

def findNonce(dataToHash: bytes, bitsToBeZero: int):
    
    # Função que encontra o nonce que satisfaz os critérios de mineração.
    # Args:
    #     dataToHash (bytes): Conjunto de bytes a serem minerados.
    #     bitsToBeZero (int): Número de bits iniciais que devem ser zero no hash.
    # Returns:
    #     int: O nonce encontrado.
    #     float: Tempo (em segundos) necessário para encontrar o nonce.
   
    nonce = 0
    target = (1 << (256 - bitsToBeZero)) - 1  # Valor máximo permitido para o hash
    start_time = time.time()

    while True:
        # Concatena o nonce em formato big endian aos bytes de entrada
        nonce_bytes = nonce.to_bytes(4, byteorder='big')
        hash_result = hashlib.sha256(nonce_bytes + dataToHash).hexdigest()
        
        # Converte o hash hexadecimal para inteiro para comparação
        if int(hash_result, 16) <= target:
            break
        
        nonce += 1
    
    elapsed_time = time.time() - start_time
    return nonce, elapsed_time

def preencher_tabela():
    """
    Preenche a tabela conforme o enunciado e salva os resultados em um arquivo.
    """
    entradas = [
        ("Esse é fácil", 8),
        ("Esse é fácil", 10),
        ("Esse é fácil", 15),
        ("Texto maior muda o tempo?", 8),
        ("Texto maior muda o tempo?", 10),
        ("Texto maior muda o tempo?", 15),
        ("É possível calcular esse?", 18),
        ("É possível calcular esse?", 19),
        ("É possível calcular esse?", 20)
    ]

    resultados = []
    for texto, bits in entradas:
        data_to_hash = texto.encode('utf-8')  # Converte o texto para bytes
        nonce, tempo = findNonce(data_to_hash, bits)
        resultados.append((texto, bits, nonce, tempo))
        print(f"Texto: '{texto}', Bits: {bits}, Nonce: {nonce}, Tempo: {tempo:.4f} s")

    # Salvando os resultados em um arquivo
    try:
        with open("tabela_resultados.txt", "w") as file:
            file.write("Texto a validar\tBits em zero\tNonce\tTempo (s)\n")
            for texto, bits, nonce, tempo in resultados:
                file.write(f"{texto}\t{bits}\t{nonce}\t{tempo:.4f}\n")
        print("Tabela salva com sucesso no arquivo 'tabela_resultados.txt'.")
    except Exception as e:
        print(f"Erro ao salvar o arquivo: {e}")


# Chamando a função diretamente
preencher_tabela()
