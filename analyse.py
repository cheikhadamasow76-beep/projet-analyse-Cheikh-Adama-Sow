"""Analyse des journaux d'un pare-feu - Projet 1.

Lancement : python analyse.py
Le script lit data/logs_reseau.csv, nettoie les données, calcule 5 résultats
(resultats.json) et enregistre des figures PNG dans figures/.
"""
import json
import os

import matplotlib
matplotlib.use("Agg")  # pas de fenêtre : on enregistre seulement les images
import matplotlib.pyplot as plt
import pandas as pd

CHEMIN_CSV = "data/logs_reseau.csv"
DOSSIER_FIGURES = "figures"


def charger_et_nettoyer(chemin):
    """Lit le CSV puis applique les 3 étapes de nettoyage de l'énoncé."""
    df = pd.read_csv(chemin)

    # 1. Doublons exacts (lignes identiques sur toutes les colonnes)
    df = df.drop_duplicates()

    # 2. Casse incohérente : tcp -> TCP
    df["protocol"] = df["protocol"].str.upper()

    # 3. Valeurs manquantes : médiane calculée APRÈS suppression des doublons
    mediane = df["bytes_sent"].median()
    df["bytes_sent"] = df["bytes_sent"].fillna(mediane)

    # Conversion en vrai type date (utile pour les graphiques par heure/jour)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def calculer_resultats(df):
    """Calcule les 5 résultats demandés."""
    return {
        "nb_lignes_apres_nettoyage": int(len(df)),
        "top_port": int(df["dst_port"].value_counts().idxmax()),
        "taux_deny_pct": round(float((df["action"] == "DENY").mean() * 100), 2),
        # IP qui a contacté le plus de ports DISTINCTS
        "ip_scanner": str(df.groupby("src_ip")["dst_port"].nunique().idxmax()),
        # IP avec le plus grand TOTAL d'octets envoyés
        "ip_exfiltration": str(df.groupby("src_ip")["bytes_sent"].sum().idxmax()),
    }


def sauver_figure(nom, titre, xlabel, ylabel):
    plt.title(titre)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.tight_layout()
    plt.savefig(os.path.join(DOSSIER_FIGURES, nom), dpi=120)
    plt.close()


def faire_figures(df):
    os.makedirs(DOSSIER_FIGURES, exist_ok=True)

    # Figure 1 : top 10 des ports de destination
    df["dst_port"].value_counts().head(10).plot(kind="bar")
    sauver_figure("top_ports.png", "Top 10 des ports de destination",
                  "Port de destination", "Nombre de connexions")

    # Figure 2 : connexions par jour
    df.groupby(df["timestamp"].dt.date).size().plot(kind="bar")
    sauver_figure("connexions_par_jour.png", "Connexions par jour",
                  "Jour", "Nombre de connexions")

    # Figure 3 : volume d'octets par type d'appareil
    df.groupby("device_type")["bytes_sent"].sum().plot(kind="bar")
    sauver_figure("octets_par_appareil.png", "Octets envoyés par type d'appareil",
                  "Type d'appareil", "Octets envoyés (total)")

    # Figure 4 : répartition ALLOW / DENY
    df["action"].value_counts().plot(kind="bar", color=["tab:green", "tab:red"])
    sauver_figure("allow_deny.png", "Répartition ALLOW / DENY",
                  "Action", "Nombre de connexions")

    # Figure 5 : connexions par heure de la journée
    df.groupby(df["timestamp"].dt.hour).size().plot(kind="bar")
    sauver_figure("connexions_par_heure.png", "Connexions par heure de la journée",
                  "Heure", "Nombre de connexions")


def main():
    df = charger_et_nettoyer(CHEMIN_CSV)
    resultats = calculer_resultats(df)
    with open("resultats.json", "w", encoding="utf-8") as f:
        json.dump(resultats, f, indent=2, ensure_ascii=False)
    faire_figures(df)
    print("Terminé :", resultats)


if __name__ == "__main__":
    main()
