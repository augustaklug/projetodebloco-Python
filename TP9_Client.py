import pygame
import sys
import psutil
import socket
import time
import nmap
import threading
import sched
import pickle
from art import *

# INICIA O PYGAME
pygame.init()

# CORES
FUNDO = (0, 0, 0)
PRIMARIA = (242, 174, 114)
TEXTO = (88, 140, 126)
SECUNDARIA = (179, 64, 51)
DESTAQUE = (242, 227, 148)

# Fontes
pygame.font.init()
font = pygame.font.SysFont("consolas", 24)
body_font = pygame.font.SysFont("consolas", 16)

# Iniciando a janela principal
LARGURA_TELA = 800
ALTURA_TELA = 600
TELA = pygame.display.set_mode((LARGURA_TELA, ALTURA_TELA))
pygame.display.set_caption("Monitor do sistema")
pygame.display.init()

# Menu superior
# Textos
textos = ["CPU", "Memória", "Disco", "IPs", "Arquivos", "Processos", "Sub-rede", "Resumo"]

# Posição inicial do marcador
circle_x = 11
# Lista das posições do marcador
posicoes_marcador = [11, 107, 207, 307, 407, 507, 607, 707]

# Cria relógio
clock = pygame.time.Clock()

# Criação das telas
tela_cpu = pygame.surface.Surface((LARGURA_TELA, ALTURA_TELA - 20))
tela_mem = pygame.surface.Surface((LARGURA_TELA, ALTURA_TELA - 20))
tela_disco = pygame.surface.Surface((LARGURA_TELA, ALTURA_TELA - 20))
tela_ip = pygame.surface.Surface((LARGURA_TELA, ALTURA_TELA - 20))
tela_arquivos = pygame.surface.Surface((LARGURA_TELA, ALTURA_TELA - 20))
tela_processos = pygame.surface.Surface((LARGURA_TELA, ALTURA_TELA - 20))
tela_subrede = pygame.surface.Surface((LARGURA_TELA, ALTURA_TELA - 20))
tela_resumo = pygame.surface.Surface((LARGURA_TELA, ALTURA_TELA - 20))

# Lista das telas
telas = [tela_cpu, tela_mem, tela_disco, tela_ip, tela_arquivos, tela_processos, tela_subrede, tela_resumo]
# Define a tela inicial da visualização
view = telas[0]
# variável para controle da tela atual
n = 0


def request_from_server(mensagem):
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    host = '127.0.0.1'
    port = 5000
    udp.sendto(mensagem.encode('ascii'), (host, port))
    dados = pickle.loads(udp.recv(65535))
    udp.close()
    return dados


info_cpu = request_from_server('cpu')


# Gateway e máscara por IP
def obtem_gateway_mascara():
    end = "Endereço"
    mask = "Máscara"
    gate = "Gateway"
    print("")
    tprint("IPs SERVIDOR", font='cybermedium')
    print(f"{end:^15} | {mask:^15} | {gate:^15}")
    device_list = request_from_server('gateway')
    for d_addr, d_info in device_list.items():
        print(f"{d_addr:^15} | {d_info['mascara']:^15} | {d_info['gateway']:^15}")


# Funções para informações de rede por PID
def obtem_nome_familia(familia):
    if familia == socket.AF_INET:
        return ("IPv4")
    elif familia == socket.AF_INET6:
        return ("IPv6")
    elif familia == socket.AF_UNIX:
        return ("Unix")
    else:
        return ("-")


def obtem_tipo_socket(tipo):
    if tipo == socket.SOCK_STREAM:
        return ("TCP")
    elif tipo == socket.SOCK_DGRAM:
        return ("UDP")
    elif tipo == socket.SOCK_RAW:
        return ("IP")
    else:
        return ("-")


def rede_por_pid():
    print("")
    tprint("REDE / PIDs", font='cybermedium')
    lista_processos = request_from_server('lista_pid')
    for p_id, p_info in lista_processos.items():
        conn = p_info['connections']
        if len(conn) > 0:
            if conn[0].status == "ESTABLISHED":
                endl = conn[0].laddr.ip
                portl = str(conn[0].laddr.port)
                endr = ""
                portr = ""
                if conn[0].raddr:
                    endr = conn[0].raddr.ip
                    portr = str(conn[0].raddr.port)
                print(
                    f"PID: {p_id} - {p_info['name']} | Família: {obtem_nome_familia(conn[0].family)} | Tipo: {obtem_tipo_socket(conn[0].type)} | Status: {conn[0].status} | End. local: {endl}:{portl} | End. remoto: {endr}:{portr}")


def get_cpu_percent():
    return request_from_server('cpu_percent')


# Obtém o IP do servidor
def get_ip():
    return request_from_server('IP')


# Funções para mapear os hosts da sub-rede
def verifica_hosts():
    return request_from_server('net')


# Port Scanner
def scan_host(host):
    nm = nmap.PortScanner()
    nm.scan(host)
    try:
        print(f"\nIP: {host} - {socket.gethostbyaddr(host)[0]}")
    except:
        print(f"\nIP: {host}")
    print('----------')

    try:
        if not nm[host].all_protocols():
            print(f"Não há portas abertas no host {host}")
        else:
            for proto in nm[host].all_protocols():
                print('Protocolo : %s' % proto)

                lport = nm[host][proto].keys()

                for port in lport:
                    print('Porta: %s\t Estado: %s' % (port, nm[host][proto][port]['state']))
    except KeyError as exkey:
        print(f"Não foi possível escanear o host {host}")
        print(decor('angry1'))


# Ping e scan de portas na sub-rede
def analisa_subrede():
    ip_string = get_ip()['local']
    ip_lista = ip_string.split('.')
    base_ip = ".".join(ip_lista[0:3]) + '.'
    linha1 = f"Hosts encontrados na sub rede {base_ip}*:"
    text1 = font.render(linha1, True, TEXTO)
    tela_subrede.blit(text1, (20, 30))
    print(f"\n** Aguarde, escaneando hosts na sub-rede **")
    host_validos = verifica_hosts()
    imprime_ip(host_validos, tela_subrede)
    texto_portas = " ** Informações sobre portas no console ** "
    txt_portas = body_font.render(texto_portas, True, SECUNDARIA)
    y_portas = 60 + (len(host_validos) * 20) + 20
    tela_subrede.blit(txt_portas, (20, y_portas))
    print("")
    tprint("NMAP", font='cybermedium')
    threads = []
    for host in host_validos:
        print(f"Executando nmap no IP {host}")
        t = threading.Thread(target=scan_host, args=(host,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    deco = decor('chess1', both=True)
    print(f"\n {deco[0]} Escaneamento de portas concluído! {deco[1]}")


# Função para listar os arquivos por tipo
def lista_arquivos():
    texto_barra = "Arquivos no diretório do servidor: "
    text = font.render(texto_barra, True, TEXTO)
    tela_arquivos.blit(text, (20, 30))
    dic_arq = request_from_server('arquivos')
    y = 70
    for i in dic_arq:
        texto_tipo = f"Arquivos {i}"
        text_tp = body_font.render(texto_tipo, True, DESTAQUE)
        tela_arquivos.blit(text_tp, (20, y))
        y += 30
        for j in dic_arq[i]:
            texto_arq = f" * {j}"
            txt_arq = body_font.render(texto_arq, True, TEXTO)
            tela_arquivos.blit(txt_arq, (20, y))
            y += 20


# Informações sobre processos
def info_processo(p_id, p_info):
    try:
        texto = '{:6}'.format(p_id)
        texto = texto + '{:11}'.format(p_info['num_threads'])
        texto = texto + " " + time.ctime(p_info['create_time']) + " "
        texto = texto + '{:8.2f}'.format(p_info['cpu_times.user'])
        texto = texto + '{:8.2f}'.format(p_info['cpu_times.system'])
        texto = texto + '{:10.2f}'.format(p_info['memory_percent']) + " MB"
        rss = p_info['memory_info.rss'] / 1024 / 1024
        texto = texto + '{:10.2f}'.format(rss) + " MB"
        vms = p_info['memory_info.vms'] / 1024 / 1024
        texto = texto + '{:10.2f}'.format(vms) + " MB"
        texto = texto + " " + p_info['exe']
        print(texto)
    except:
        pass


def listar_processos():
    t_inicio = time.time()
    clock_inicio = time.process_time()
    texto_barra = "Informações no console"
    text = font.render(texto_barra, True, SECUNDARIA)
    tela_processos.blit(text, (20, 30))
    print("")
    tprint("PROCESSOS", font='cybermedium')
    titulo = '{:^7}'.format("PID")
    titulo = titulo + '{:^11}'.format("# Threads")
    titulo = titulo + '{:^26}'.format("Criação")
    titulo = titulo + '{:^9}'.format("T. Usu.")
    titulo = titulo + '{:^9}'.format("T. Sis.")
    titulo = titulo + '{:^12}'.format("Mem. (%)")
    titulo = titulo + '{:^12}'.format("RSS")
    titulo = titulo + '{:^12}'.format("VMS")
    titulo = titulo + " Executável"
    print(titulo)
    lista_processos = request_from_server('lista_pid')
    for p_id, p_info in lista_processos.items():
        info_processo(p_id, p_info)
        time.sleep(0.01)
    t_fim = time.time()
    clock_fim = time.process_time()
    print(f"Tempo da função: {t_fim - t_inicio}")
    print(f"Clocks da função: {clock_fim - clock_inicio}")


# Mostrar uso de CPU
def mostra_uso_cpu(s, l_cpu_percent):
    s.fill(FUNDO)
    num_cpu = len(l_cpu_percent)
    x = 10
    y = 20
    desl = 10
    alt = s.get_height() // 2 - 2 * y
    larg = (s.get_width() - 2 * y - (num_cpu + 1) * desl) / num_cpu
    d = x + desl
    for i in l_cpu_percent:
        pygame.draw.rect(s, SECUNDARIA, (d, y, larg, alt))
        pygame.draw.rect(s, PRIMARIA, (d, y, larg, (1 - i / 100) * alt))
        d = d + larg + desl


def mostra_info_cpu():
    mostra_texto(tela_cpu, "Nome:", "brand_raw", 310)
    mostra_texto(tela_cpu, "Arquitetura:", "arch", 340)
    mostra_texto(tela_cpu, "Palavra (bits):", "bits", 370)
    mostra_texto(tela_cpu, "Frequência (MHz):", "freq", 400)
    mostra_texto(tela_cpu, "Núcleos (físicos):", "nucleos", 430)


# Mostra texto de acordo com uma chave:
def mostra_texto(s1, nome, chave, pos_y):
    text1 = font.render(nome, True, TEXTO)
    s1.blit(text1, (20, pos_y))
    if chave == "freq":
        s = f"{round(psutil.cpu_freq().current, 2)} (atual) | {psutil.cpu_freq().max} (máx.)"
    elif chave == "nucleos":
        s = str(psutil.cpu_count())
        s = s + " (" + str(psutil.cpu_count(logical=False)) + ")"
    else:
        s = str(info_cpu[chave])
    text2 = font.render(s, True, DESTAQUE)
    s1.blit(text2, (text1.get_width() + 30, pos_y))


# Mostar uso de memória
def mostra_uso_memoria():
    tela_mem.fill(FUNDO)
    mem = request_from_server("ram")
    larg = LARGURA_TELA - 2 * 20
    pygame.draw.rect(tela_mem, PRIMARIA, (20, 70, larg, 70))
    larg = larg * mem['percent'] / 100
    pygame.draw.rect(tela_mem, SECUNDARIA, (20, 70, larg, 70))
    usada = round(mem['used'] / (1024 * 1024 * 1024), 2)
    total = round(mem['total'] / (1024 * 1024 * 1024), 2)
    texto_barra = "Uso de Memória (" + str(usada) + " de " + str(total) + "GB):"
    text = font.render(texto_barra, True, TEXTO)
    tela_mem.blit(text, (20, 30))


# Mostrar o uso de disco local
def mostra_uso_disco():
    tela_disco.fill(FUNDO)
    disco = request_from_server('disco')
    larg = LARGURA_TELA - 2 * 20
    pygame.draw.rect(tela_disco, PRIMARIA, (20, 70, larg, 70))
    larg = larg * disco['percent'] / 100
    pygame.draw.rect(tela_disco, SECUNDARIA, (20, 70, larg, 70))
    total = round(disco['total'] / (1024 * 1024 * 1024), 2)
    texto_barra = "Uso de Disco: (Total: " + str(total) + "GB):"
    text = font.render(texto_barra, True, TEXTO)
    tela_disco.blit(text, (20, 30))


# Função que itera a lista de IPs
def imprime_ip(lista, surface):
    y = 60
    for address in lista:
        texto = body_font.render(f"{address}", True, DESTAQUE)
        surface.blit(texto, (20, y))
        y += 20


# Mostrar endereços IP
def mostra_ip():
    tela_ip.fill(FUNDO)
    ipv4s = request_from_server('interfaces')
    texto_barra = font.render("Interfaces de rede do servidor: ", True, TEXTO)
    tela_ip.blit(texto_barra, (20, 30))
    imprime_ip(ipv4s, tela_ip)


def mostra_resumo():
    tela_resumo.fill(FUNDO)
    cpu_name = info_cpu['brand_raw']
    texto_cpu = font.render(f"Processador: {cpu_name}", True, DESTAQUE)
    disco = request_from_server('disco')
    texto_disco = font.render(
        f"Disco: {round(disco['used'] / (1024 * 1024 * 1024), 2)} de {round(disco['total'] / (1024 * 1024 * 1024), 2)}GB usados",
        True, DESTAQUE)
    mem = request_from_server('ram')
    texto_memoria = font.render(
        f"Memória: {round(mem['used'] / (1024 * 1024 * 1024), 2)} de {round(mem['total'] / (1024 * 1024 * 1024), 2)}GB usados",
        True, DESTAQUE)
    ip_servidor = get_ip()
    texto_ip_local = font.render(f"IP local do servidor: {ip_servidor['local']}", True, DESTAQUE)
    texto_ip_publico = font.render(f"IP público do servidor: {ip_servidor['publico']}", True, DESTAQUE)
    tela_resumo.blit(texto_cpu, (20, 30))
    tela_resumo.blit(texto_disco, (20, 70))
    tela_resumo.blit(texto_memoria, (20, 110))
    tela_resumo.blit(texto_ip_local, (20, 150))
    tela_resumo.blit(texto_ip_publico, (20, 190))


cont = 60

# Scheduler - funções fora do loop
s = sched.scheduler(time.time, time.sleep)
s.enter(1, 1, lista_arquivos)
s.enter(1, 1, listar_processos)
s.enter(2, 1, obtem_gateway_mascara)
s.enter(5, 1, rede_por_pid)
s.enter(8, 1, analisa_subrede)
threading.Thread(target=s.run).start()

# Loop principal
while True:
    # Checar os eventos aqui:
    for event in pygame.event.get():

        if event.type == pygame.KEYDOWN:
            if event.key == pygame.K_RIGHT:
                if n < len(telas) - 1:
                    n += 1
                else:
                    n = 0
                view = telas[n]
                circle_x = posicoes_marcador[n]
            if event.key == pygame.K_LEFT:
                if n > 0:
                    n -= 1
                else:
                    n = len(telas) - 1
                view = telas[n]
                circle_x = posicoes_marcador[n]
            if event.key == pygame.K_SPACE:
                n = len(telas) - 1
                view = telas[-1]
                circle_x = posicoes_marcador[-1]

        if event.type == pygame.QUIT:
            pygame.quit()
            sys.exit()

    TELA.fill(FUNDO)

    # Chamadas das funções
    if cont == 60:
        mostra_uso_memoria()
        mostra_uso_disco()
        mostra_uso_cpu(tela_cpu, get_cpu_percent())
        mostra_info_cpu()
        mostra_ip()
        mostra_resumo()
        cont = 0

    # Posiciona menu superior
    for i in range(len(textos)):
        if i == 0:
            TELA.blit(body_font.render(textos[i], True, TEXTO), (20, 5))
        elif i == 1:
            TELA.blit(body_font.render(textos[i], True, TEXTO), (15 + LARGURA_TELA // 8, 5))
        else:
            TELA.blit(body_font.render(textos[i], True, TEXTO), (15 + i * LARGURA_TELA // 8, 5))

    # Atualiza a view
    TELA.blit(view, (0, 20))
    # Cursor da tela selecionada
    pygame.draw.circle(TELA, SECUNDARIA, (circle_x, 12), 5)

    # Atualiza o desenho na tela
    pygame.display.update()

    # 60 frames por segundo
    clock.tick(60)
    cont += 1
