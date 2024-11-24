import json
import sys
import time

# Tratamento de erro para entrada incorreta do usuário ou indisponibilidade do arquivo
try:
    ano = int(input("=="*32 + "\n|| INSIRA O ANO QUE VOCÊ DESEJA ACESSAR:\n|| - 2021\n|| - 2022\n" + "=="*30 + "\n>>> ").strip().upper())

    with open(f"cartola_fc_{ano}.txt", "r", encoding="utf-8") as arquivo:
        conteudo = json.load(arquivo)  # Fazendo o parse do conteúdo JSON do arquivo

except FileNotFoundError:
    print(" ❓ O ARQUIVO NÃO FOI ENCONTRADO ❓ ")
    time.sleep(2)
    print("ENCERRANDO PROGRAMA...")
    exit()
except IOError:
    print("⚠ ERRO AO ACESSAR ARQUIVO ⚠")
    time.sleep(2)
    print("ENCERRANDO PROGRAMA...")
    exit()
except json.JSONDecodeError:
    print("❗ ERRO AO DECODIFICAR O ARQUIVO JSON. VERIFIQUE O FORMATO DO ARQUIVO. ❗")
    exit()

# Escolha de esquemas táticos
escalacao_disponiveis = {
    1: '3-4-3',
    2: '3-5-2',
    3: '4-3-3',
    4: '4-4-2',
    5: '4-5-1',
    6: '5-3-2',
    7: '5-4-1'
}
print("\nESCOLHA UMA DAS FORMAÇÕES TÁTICAS DISPONÍVEIS PARA SUA SELEÇÃO:")
for num, esquema in escalacao_disponiveis.items():
    print(f"{num} - {esquema}")

# Solicitando o esquema tático ao usuário
try:
    escalacao_escolhida = int(input("DIGITE O NÚMERO CORRESPONDENTE À FORMAÇÃO DESEJADA: ").strip().upper())
except ValueError:
    sys.exit("ERRO: A ESCOLHA DEVE SER UM NÚMERO INTEIRO.")

while escalacao_escolhida < 1 or escalacao_escolhida > 7:
    try:
        escalacao_escolhida = int(input("ESCOLHA INVÁLIDA. INFORME UM NÚMERO VÁLIDO (1 A 7): ").strip().upper())
    except ValueError:
        sys.exit("ERRO: A ESCOLHA DEVE SER UM NÚMERO INTEIRO.")

# Definindo o esquema tático escolhido
esquema_selecionado = escalacao_disponiveis[escalacao_escolhida]
esquemas_taticos = {
    '3-4-3': {'goleiro': 1, 'zagueiro': 3, 'lateral': 0, 'meia': 4, 'atacante': 3, 'tecnico': 1},
    '3-5-2': {'goleiro': 1, 'zagueiro': 3, 'lateral': 0, 'meia': 5, 'atacante': 2, 'tecnico': 1},
    '4-3-3': {'goleiro': 1, 'zagueiro': 2, 'lateral': 2, 'meia': 3, 'atacante': 3, 'tecnico': 1},
    '4-4-2': {'goleiro': 1, 'zagueiro': 2, 'lateral': 2, 'meia': 4, 'atacante': 2, 'tecnico': 1},
    '4-5-1': {'goleiro': 1, 'zagueiro': 2, 'lateral': 2, 'meia': 5, 'atacante': 1, 'tecnico': 1},
    '5-3-2': {'goleiro': 1, 'zagueiro': 3, 'lateral': 2, 'meia': 3, 'atacante': 2, 'tecnico': 1},
    '5-4-1': {'goleiro': 1, 'zagueiro': 3, 'lateral': 2, 'meia': 4, 'atacante': 1, 'tecnico': 1},
}
quantidade_posicoes = esquemas_taticos[esquema_selecionado]

# Selecionando os melhores jogadores
selecionados = {}
for posicao, quantidade in quantidade_posicoes.items():
    posicao_id = {
        'goleiro': 1,
        'zagueiro': 3,
        'lateral': 2,
        'meia': 4,
        'atacante': 5,
        'tecnico': 6
    }[posicao]

    jogadores = [atleta for atleta in conteudo['atletas'] if atleta['posicao_id'] == posicao_id]

    for atleta in jogadores:
        atleta['pontuacao_total'] = round(atleta.get('media_num', 0) * atleta.get('jogos_num', 0), 2)

    jogadores = sorted(jogadores, key=lambda x: x.get('pontuacao_total', 0), reverse=True)[:quantidade]
    selecionados[posicao] = jogadores

# Preparando os dados para salvar em um arquivo .txt
with open(f"selecao_cartola_fc_{ano}.txt", "w", encoding="utf-8") as file:
    file.write(f"{'Nome':<} {'Posição':<15} {'Pontuação':<10} {'Clube':<20}\n")
    file.write("=" * 65 + "\n")
    for posicao, atletas in selecionados.items():
        for atleta in atletas:
            clube_id = str(atleta['clube_id'])
            clube_nome = conteudo['clubes'].get(clube_id, {}).get('nome', 'Clube Desconhecido')
            file.write(f"{atleta['nome']:<20} {posicao.capitalize():<15} {atleta['pontuacao_total']:<10.2f} {clube_nome:<20}\n")

print("\nTABELA DA SELEÇÃO DO CARTOLA FC FOI GRAVADA EM 'selecao_cartola_fc_{ano}.txt'.")