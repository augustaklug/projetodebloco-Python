import socket
import psutil
import cpuinfo
import os
import ping_multiprocessing
import pickle
import platform
import netifaces
import re
import time
from urllib.request import urlopen
from art import *


def send_info(mensagem):
    inicio = time.time()
    func = ''
    if mensagem == 'cpu':
        func = info_processador()
    if mensagem == 'cpu_percent':
        func = cpu_percent()
    if mensagem == 'ram':
        func = memoria_ram()
    if mensagem == 'disco':
        func = info_disco()
    if mensagem == 'gateway':
        func = mascara_subrede()
    if mensagem == 'IP':
        func = get_ip()
    if mensagem == 'interfaces':
        func = lista_interfaces()
    if mensagem == 'arquivos':
        func = lista_arquivos()
    if mensagem == 'lista_pid':
        func = lista_pids()
    if mensagem == 'net':
        func = ping_multiprocessing.map_network()
    msg_servidor = pickle.dumps(func)
    udp.sendto(msg_servidor, cliente)
    fim = time.time()
    print(f" {(fim - inicio):.2f}s")


def info_processador():
    info_cpu = cpuinfo.get_cpu_info()
    dict_cpu = {
        'brand_raw': info_cpu['brand_raw'],
        'system': f"{platform.system()} ({platform.platform()})",
        'freq': f"{psutil.cpu_freq().max}",
        'freq_atual': f"{psutil.cpu_freq().current}",
        'arch': info_cpu['arch'],
        'bits': f"{info_cpu['bits']}",
        'threads': psutil.cpu_count(),
        'nucleos': psutil.cpu_count(logical=False),
        'uso_cpu': psutil.cpu_percent(percpu=True),
        'uso_cpu_todos': psutil.cpu_percent()
    }
    return dict_cpu


def cpu_percent():
    return psutil.cpu_percent(percpu=True)


def memoria_ram():
    memoria = psutil.virtual_memory()
    dict_memory = {
        'percent': memoria.percent,
        'total': memoria.total,
        'used': memoria.used,
        'free': memoria.free
    }
    return dict_memory


def info_disco():
    disco = psutil.disk_usage('.')
    dict_disco = {
        'percent': disco.percent,
        'total': disco.total,
        'used': disco.used,
        'free': disco.free
    }
    return dict_disco


def mascara_subrede():
    dict_rede = {}
    for i in netifaces.interfaces():
        try:
            # Address
            endereco_ip = netifaces.ifaddresses(i)[netifaces.AF_INET][0]['addr']
            mascara = netifaces.ifaddresses(i)[netifaces.AF_INET][0]['netmask']
            gateway = netifaces.gateways()['default'][netifaces.AF_INET][0]
            dict_rede[endereco_ip] = {
                'mascara': mascara,
                'gateway': gateway
            }

        except:
            pass
    return dict_rede


def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1))
        local = s.getsockname()[0]
    except Exception:
        local = '127.0.0.1'
    finally:
        s.close()

    try:
        data = str(urlopen('http://checkip.dyndns.com/').read())
        publico = re.compile(r'Address: (\d+\.\d+\.\d+\.\d+)').search(data).group(1)
    except Exception:
        publico = "Error."

    dict_IP = {
        'local': local,
        'publico': publico
    }

    return dict_IP


def interfaces_rede(family=socket.AF_INET):
    for interface, snics in psutil.net_if_addrs().items():
        for snic in snics:
            if snic.family == family:
                yield interface, snic.address


def lista_interfaces():
    return list(interfaces_rede())


def lista_arquivos():
    lista = os.listdir()

    dic_arq = {}

    for i in lista:
        if os.path.isfile(i):
            ext = os.path.splitext(i)[1]
            if not ext in dic_arq:
                dic_arq[ext] = []
            dic_arq[ext].append(i)

    return dic_arq


def lista_pids():
    dic_pids = {}
    lista_pids = psutil.pids()
    for pid in lista_pids:
        try:
            p = psutil.Process(pid)
            dic_pids[p.pid] = {
                'name': p.name(),
                'connections': p.connections(),
                'num_threads': p.num_threads(),
                'create_time': p.create_time(),
                'exe': p.exe(),
                'cpu_times.user': p.cpu_times().user,
                'cpu_times.system': p.cpu_times().system,
                'memory_percent': p.memory_percent(),
                'memory_info.rss': p.memory_info().rss,
                'memory_info.vms': p.memory_info().vms
            }
        except:
            pass
    return dic_pids


if __name__ == '__main__':
    tprint("PyMonitor Server", font='big')

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    HOST = '127.0.0.1'
    PORT = 5000
    orig = (HOST, PORT)
    udp.bind(orig)

    print(f"Esperando receber na porta {PORT}...")
    while True:
        (msg, cliente) = udp.recvfrom(65535)
        mensagem = msg.decode('ascii')
        print(cliente, mensagem, end='')
        send_info(mensagem)
    udp.close()
