# Recon PRO PTES - Interface Gráfica com Filtragem de IPs/Subdomínios + Subfinder
# Autor: Você + ChatGPT

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import subprocess
import threading
import queue
import time
import socket
import requests
import os
from concurrent.futures import ThreadPoolExecutor

# --- Validação DNS e HTTP ---
def subdominio_ativo(subdominio):
    try:
        socket.gethostbyname(subdominio)
    except socket.gaierror:
        return False
    for protocolo in ['http://', 'https://']:
        try:
            r = requests.get(protocolo + subdominio, timeout=3)
            if r.status_code < 500:
                return True
        except:
            continue
    return False

def validar_subdominios(subdominios, output_queue):
    output_queue.put("[*] Validando subdomínios via DNS e HTTP...")
    validos_http = set()
    validos_dns = set()
    with ThreadPoolExecutor(max_workers=20) as executor:
        resultados = list(executor.map(lambda s: (s, subdominio_ativo(s)), subdominios))
    for sub, ativo in resultados:
        try:
            socket.gethostbyname(sub)
            validos_dns.add(sub)
        except:
            pass
        if ativo:
            validos_http.add(sub)
            output_queue.put(f"[VALIDO] {sub}")
        else:
            output_queue.put(f"[INVALIDO] {sub}")
    return validos_http, validos_dns

def salvar_resultado(lista, caminho):
    os.makedirs(os.path.dirname(caminho), exist_ok=True)
    with open(caminho, 'w') as f:
        for item in sorted(lista):
            f.write(item + '\n')

# --- Enumeração usando subfinder ---
def subfinder_enum(domain, output_queue):
    output_queue.put("[*] Executando subfinder para enumeração de subdomínios...")
    cmd = f"subfinder -d {domain} -silent"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            output_queue.put(f"[!] Erro ao executar subfinder: {result.stderr.strip()}")
            return []
        subs = set(line.strip() for line in result.stdout.splitlines() if line.strip())
        output_queue.put(f"[+] {len(subs)} subdomínios encontrados via subfinder")
        return sorted(subs)
    except Exception as e:
        output_queue.put(f"[!] Exceção ao executar subfinder: {e}")
        return []

# --- Worker Thread ---
def worker(filepath, output_queue):
    nome_arquivo = os.path.basename(filepath)
    data = time.strftime("%d-%m-%Y")
    output_dir = f"Recon-{nome_arquivo}-{data}"

    output_queue.put(f"=== Início do Recon para: {nome_arquivo} em {data} ===")

    try:
        with open(filepath, 'r') as f:
            dominios = [l.strip() for l in f if l.strip()]
    except:
        output_queue.put("[ERRO] Falha ao ler arquivo.")
        return

    if not dominios:
        output_queue.put("[ERRO] Arquivo vazio.")
        return

    dominio_principal = dominios[0]
    output_queue.put(f"[+] Dominio alvo: {dominio_principal}")

    # Enumeração via subfinder
    subdominios = subfinder_enum(dominio_principal, output_queue)

    conhecidos_path = 'conhecidos.txt'
    if os.path.exists(conhecidos_path):
        with open(conhecidos_path, 'r') as f:
            conhecidos = set([l.strip() for l in f if l.strip()])
        novos = set(subdominios) - conhecidos
        output_queue.put(f"[*] {len(novos)} novos subdomínios após filtragem")
    else:
        novos = set(subdominios)
        output_queue.put("[!] Arquivo de conhecidos 'conhecidos.txt' não encontrado. Ignorando filtragem.")

    validos_http, validos_dns = validar_subdominios(novos, output_queue)

    salvar_resultado(validos_http, f"{output_dir}/validos/itens_ativos_http.txt")
    salvar_resultado(validos_dns, f"{output_dir}/dns_ok/itens_ativos_dns.txt")
    salvar_resultado(novos - validos_http, f"{output_dir}/invalidos/itens_invalidos.txt")

    output_queue.put(f"[+] {len(validos_http)} subdomínios válidos HTTP salvos em: {output_dir}/validos/itens_ativos_http.txt")
    output_queue.put(f"[+] {len(validos_dns)} subdomínios válidos DNS salvos em: {output_dir}/dns_ok/itens_ativos_dns.txt")
    output_queue.put(f"[+] {len(novos - validos_http)} subdomínios inválidos salvos em: {output_dir}/invalidos/itens_invalidos.txt")
    output_queue.put("=== Recon finalizado ===")

# --- Interface gráfica ---
class ReconApp:
    def __init__(self, master):
        self.master = master
        master.title("Recon PRO PTES")
        master.geometry("700x500")

        self.q = queue.Queue()
        self.thread = None

        ttk.Label(master, text="Selecione um arquivo contendo o domínio principal (ex: indrive.com na primeira linha):").pack(pady=10)
        self.path_var = tk.StringVar()
        ttk.Entry(master, textvariable=self.path_var, width=80).pack(padx=10)
        ttk.Button(master, text="Procurar", command=self.browse_file).pack(pady=5)

        ttk.Button(master, text="Iniciar Recon", command=self.start_recon).pack(pady=10)

        self.output_box = scrolledtext.ScrolledText(master, wrap=tk.WORD, height=20)
        self.output_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.master.after(100, self.check_queue)

    def browse_file(self):
        filepath = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if filepath:
            self.path_var.set(filepath)

    def start_recon(self):
        path = self.path_var.get().strip()
        if not os.path.isfile(path):
            messagebox.showerror("Erro", "Arquivo inválido.")
            return
        self.output_box.delete('1.0', tk.END)
        self.thread = threading.Thread(target=worker, args=(path, self.q), daemon=True)
        self.thread.start()

    def check_queue(self):
        try:
            while True:
                msg = self.q.get_nowait()
                self.output_box.insert(tk.END, msg + '\n')
                self.output_box.see(tk.END)
        except queue.Empty:
            pass
        self.master.after(100, self.check_queue)

if __name__ == '__main__':
    root = tk.Tk()
    app = ReconApp(root)
    root.mainloop()