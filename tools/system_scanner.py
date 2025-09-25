# tools/system_info.py
import platform
import psutil
import socket

def get_system_info():
    system = platform.system()
    node_name = platform.node() 
    release = platform.release()
    version = platform.version()
    machine = platform.machine()
    processor = platform.processor()
    cpu_cores = psutil.cpu_count(logical=True)
    total_ram = round(psutil.virtual_memory().total / (1024 ** 3), 2)  # in GB
    return {
        'system': system,
        'node_name': node_name,
        'release': release,
        'version': version,
        'machine': machine,
        'processor': processor,
        'cpu_cores': cpu_cores,
        'total_ram': total_ram
    }

def get_system_metrics():
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    memory_percent = memory.percent
    disk = psutil.disk_usage('/')
    disk_percent = disk.percent
    net = psutil.net_io_counters()
    net_sent = round(net.bytes_sent / (1024 * 1024), 2)  # MB
    net_recv = round(net.bytes_recv / (1024 * 1024), 2)  # MB

    return {
        'cpu_usage': cpu_percent,
        'memory_usage': memory_percent,
        'disk_usage': disk_percent,
        'network_sent': net_sent,
        'network_recv': net_recv
    }
