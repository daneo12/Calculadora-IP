import tkinter as tk
from tkinter import ttk
import ipaddress

def validar_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validar_mascara(mascara):
    try:
        mascara_int = int(mascara)
        return 0 <= mascara_int <= 32
    except ValueError:
        return False


def validar_entrada(campo):
    return campo.isdigit() or campo == "."


def calcular():
    ip = ip_daneo.get().strip()
    mascara = mascara_daneo.get().strip()

    if not validar_ip(ip):
        valores["Erro"].set("Erro: Endereço IP inválido!")
        limpar_valores()
        return

    if not validar_mascara(mascara):
        valores["Erro"].set("Erro: Use um valor entre 0 e 32!")
        limpar_valores()
        return

    try:
        rede = ipaddress.ip_network(f"{ip}/{mascara}", strict=False)
        hosts = list(rede.hosts())

        endereco_rede = rede.network_address
        endereco_broadcast = rede.broadcast_address
        primeiro_host = hosts[0] if hosts else None
        ultimo_host = hosts[-1] if hosts else None
        hosts_por_subredes = 2 ** (32 - int(mascara)) - 2

        identificar_classe = int(ip.split('.')[0])
        if 1 <= identificar_classe <= 127:
            classe = "Classe A"
        elif 128 <= identificar_classe <= 191:
            classe = "Classe B"
        elif 192 <= identificar_classe <= 223:
            classe = "Classe C"
        else:
            classe = "Indefinido"

        numero_subredes = 2 ** (int(mascara) - rede.prefixlen)

        if (
            (10 <= identificar_classe <= 10)
            or (172 <= identificar_classe <= 172 and 16 <= int(ip.split('.')[1]) <= 31)
            or (192 <= identificar_classe <= 192 and int(ip.split('.')[1]) == 168)
        ):
            classe_publico = "Privado"
        else:
            classe_publico = "Público"

        valores["Endereço de Rede"].set(str(endereco_rede))
        valores["Primeiro Host"].set(str(primeiro_host))
        valores["Último Host"].set(str(ultimo_host))
        valores["Endereço de Broadcast"].set(str(endereco_broadcast))
        valores["Classe do Endereço IP"].set(classe)
        valores["Número de Sub-redes"].set(numero_subredes)
        valores["Hosts por Sub-rede"].set(hosts_por_subredes)
        valores["Endereço Público/Privado"].set(classe_publico)
        valores["Erro"].set("")

    except ValueError as erro:
        limpar_valores()
        valores["Erro"].set(f"Erro: {erro}")


def limpar_valores():
    for chave in valores:
        if chave != "Erro":
            valores[chave].set("")


janela = tk.Tk()
janela.title("Calculadora de Sub-redes")
janela.geometry("500x500")
janela.resizable(False, False)

daneo_titulo = ttk.Label(janela, text="Calculadora de Sub-redes", font=("Arial", 18, "bold"))
daneo_titulo.grid(row=0, column=0, pady=10)

style = ttk.Style()
style.configure("TLabel", font=("Arial", 12))
style.configure("TEntry", font=("Arial", 12))
style.configure("TButton", font=("Arial", 12), padding=5)

opcoes = ttk.Frame(janela, padding="20 10 20 10")
opcoes.grid(row=1, column=0)

numeros = (janela.register(validar_entrada), "%S")

ttk.Label(opcoes, text="Endereço IP:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
ip_daneo = ttk.Entry(opcoes, width=30, validate="key", validatecommand=numeros)
ip_daneo.grid(row=0, column=1, padx=5, pady=10)

ttk.Label(opcoes, text="Máscara de Sub-rede (CIDR):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
mascara_daneo = ttk.Entry(opcoes, width=15)
mascara_daneo.grid(row=1, column=1, padx=5, pady=5)

calcular_daneo = tk.Button(opcoes, text="Calcular", command=calcular, bg="#388E3C", width=20, height=2, fg="white")
style.configure("TButton", font=("Arial", 12), padding=5, foreground="black")
calcular_daneo.grid(row=2, column=0, columnspan=2, pady=15)

valores = {
    "Endereço de Rede": tk.StringVar(),
    "Primeiro Host": tk.StringVar(),
    "Último Host": tk.StringVar(),
    "Endereço de Broadcast": tk.StringVar(),
    "Classe do Endereço IP": tk.StringVar(),
    "Número de Sub-redes": tk.StringVar(),
    "Hosts por Sub-rede": tk.StringVar(),
    "Endereço Público/Privado": tk.StringVar(),
    "Erro": tk.StringVar(),
}

resultados = ttk.LabelFrame(opcoes, text="Resultados", padding="10")
style.configure("TLabelframe.Label", font=("Arial", 12, "bold"))
resultados.grid(row=3, column=0, columnspan=2, pady=15, sticky=(tk.W, tk.E))

for i, (parametro, variavel) in enumerate(valores.items()):
    ttk.Label(resultados, text=parametro + ":").grid(row=i, column=0, sticky=tk.W, padx=5, pady=2)
    ttk.Label(resultados, textvariable=variavel, relief="sunken", anchor="w", font=("Arial", 11)).grid(
        row=i, column=1, sticky=(tk.W, tk.E), padx=5, pady=2
    )

opcoes.columnconfigure(1, weight=1)
resultados.columnconfigure(1, weight=1)

janela.mainloop()
