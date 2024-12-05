import tkinter as tk
from tkinter import scrolledtext
import nmap
import threading

import subprocess

def test_latency(site):
    try:
        # Commande ping adaptée à Windows
        result = subprocess.run(
            ["ping", "-n", "1", site],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Analyser la sortie pour trouver le temps de réponse
        if "temps" in result.stdout or "time" in result.stdout:  # Vérifie la langue de sortie
            for line in result.stdout.splitlines():
                if "temps" in line or "time" in line:
                    # Extraire le temps (fonctionne pour les sorties fr/en)
                    latency = line.split("temps=" if "temps" in line else "time=")[1].split("ms")[0].strip()
                    return f"{latency} ms"
        return "Latence non disponible"
    except Exception as e:
        return f"Erreur : {str(e)}"


def run_nmap_scan():
    target = entry.get()
    if not target:
        output_text.insert(tk.END, "Veuillez entrer une cible valide (ex: 192.168.1.0/24).\n")
        return

    scanner = nmap.PortScanner()
    try:
        output_text.insert(tk.END, f"Lancement du scan sur {target}...\n")
        output_text.see(tk.END)
        
        # Lancer le scan sur la plage
        scanner.scan(hosts=target, arguments='-sn')  # Scan ping seulement
        
        # Initialiser un compteur pour les machines détectées
        machine_count = 0
        
        for host in scanner.all_hosts():
            machine_count += 1  # Incrémenter pour chaque machine détectée
            output_text.insert(tk.END, f"\nRésultats pour {host}:\n")
            output_text.insert(tk.END, f"État : {scanner[host].state()}\n")
        
        # Afficher le nombre de machines détectées
        output_text.insert(tk.END, f"\nNombre total de machines détectées : {machine_count}\n")
        
        # Test de latence vers des sites externes
        output_text.insert(tk.END, "\nTest de latence vers des sites externes :\n")
        for site in ["google.com", "orange.fr"]:
            latency = test_latency(site)
            output_text.insert(tk.END, f"Latence vers {site} : {latency}\n")
        
        output_text.insert(tk.END, "Scan terminé.\n")
    except Exception as e:
        output_text.insert(tk.END, f"Erreur : {str(e)}\n")



def start_scan_thread():
    thread = threading.Thread(target=run_nmap_scan)
    thread.start()

# Interface graphique
root = tk.Tk()
root.title("Scanner Nmap")

# Champ pour entrer l'adresse cible
frame = tk.Frame(root)
frame.pack(pady=10)

label = tk.Label(frame, text="Cible (IP ou domaine) :")
label.pack(side=tk.LEFT, padx=5)

entry = tk.Entry(frame, width=30)
entry.pack(side=tk.LEFT, padx=5)

# Bouton pour lancer le scan
scan_button = tk.Button(root, text="Lancer le scan", command=start_scan_thread)
scan_button.pack(pady=10)

# Zone pour afficher les résultats
output_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=70, height=20)
output_text.pack(pady=10)

# Boucle principale
root.mainloop()
