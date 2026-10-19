#!/usr/bin/env python3
"""Icône de Vanguard : un V en bouclier, un cadenas au centre, des arcs cyan, sur une plaque noire arrondie.

Le dessin vient d'une image générée par l'auteur (assets/logo-source.jpg, l'emblème découpé au carré, couleurs
d'origine). Ce script en tire toutes les tailles :
- le fond bleu nuit devient noir pur, comme le menu et le thème du bureau. Le dessin est en aplats : chaque pixel est
  « démêlé » du fond (son opacité d'après l'écart au fond, puis sa vraie couleur), et posé sur le noir ; une simple
  soustraction du fond ternirait les couleurs ;
- le V passe du bleu au rouge, les arcs restent cyan : rouge d'un côté, cyan de l'autre, comme le thème et le menu ;
- un seul cadrage pour toutes les tailles : des aplats se lisent encore en 16 px.

Lancer depuis n'importe où (les images vont toujours dans le dépôt) :
    uv run --no-project --with numpy --with pillow python outils/icone.py
Produit assets/icones/vanguard-<taille>.png (Linux, 16 à 512 px) et assets/vanguard.ico (Windows, 16 à 256 px).
"""

from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFilter

# Lancé depuis un autre dossier, le script écrivait dans un « assets » de ce dossier-là, ou s'arrêtait.
ASSETS = Path(__file__).resolve().parent.parent / "assets"
SOURCE = ASSETS / "logo-source.jpg"

# Une image par taille, réduite depuis la source : le système n'a jamais à la réduire lui-même.
# Linux : les dossiers de hicolor (la barre et le lanceur prennent la taille la plus proche).
TAILLES_LINUX = [16, 22, 24, 32, 48, 64, 128, 256, 512]
# Windows : ses tailles de base (16, 24, 32, 48, 256) et leurs versions pour les écrans agrandis de 125 à 300 %.
TAILLES_WINDOWS = [16, 20, 24, 30, 32, 36, 40, 48, 60, 64, 72, 80, 96, 256]

COIN = 0.18  # arrondi de la plaque, en fraction du côté
# Rouge de l'accent du thème (#ff0a1e) : la teinte que prend le bleu du V.
TEINTE_ROUGE = 355.0


def sur_noir(a):
    """Le dessin posé sur du noir pur au lieu du bleu nuit de l'image. Fond : la médiane des bords. Opacité d'un pixel :
    son écart au fond (l'anticrénelage des bords donne les valeurs entre deux) ; sa couleur : ce qui reste une fois le
    fond retiré dans cette proportion."""
    bords = np.concatenate([a[:15].reshape(-1, 3), a[-15:].reshape(-1, 3), a[:, :15].reshape(-1, 3), a[:, -15:].reshape(-1, 3)])
    fond = np.median(bords, axis=0)
    alpha = np.clip((np.abs(a - fond).max(axis=2) - 0.04) / 0.18, 0, 1)[..., None]
    couleur = np.clip((a - fond * (1 - alpha)) / np.maximum(alpha, 1e-3), 0, 1)
    return couleur * alpha


def rouge_cyan(a):
    """Le bleu du V (200 à 250°, saturé) → rouge, un peu éclairci ; le cyan des arcs (vers 185°) et le gris du cadenas
    ne bougent pas."""
    hsv = np.asarray(Image.fromarray((a * 255 + 0.5).astype(np.uint8)).convert("HSV"), dtype=np.float64)
    deg = hsv[..., 0] / 255 * 360
    bleu = (deg > 200) & (deg < 250) & (hsv[..., 1] > 80)
    hsv[..., 0] = np.where(bleu, TEINTE_ROUGE / 360 * 255, hsv[..., 0])
    hsv[..., 2] = np.where(bleu, np.minimum(hsv[..., 2] * 1.1, 255), hsv[..., 2])
    return np.asarray(Image.fromarray(hsv.astype(np.uint8), "HSV").convert("RGB"), dtype=np.float64) / 255


def icone(image, t):
    """Icône de t px : réduite en une fois, un peu de netteté en petit, plaque arrondie."""
    im = image.resize((t, t), Image.Resampling.LANCZOS)
    if t <= 32:
        im = im.filter(ImageFilter.UnsharpMask(radius=0.6, percent=60, threshold=0))
    # Plaque dessinée 4 fois plus grande puis réduite : un bord net même en 16 px.
    plaque = Image.new("L", (4 * t, 4 * t), 0)
    ImageDraw.Draw(plaque).rounded_rectangle([0, 0, 4 * t - 1, 4 * t - 1], radius=4 * t * COIN, fill=255)
    im.putalpha(plaque.resize((t, t), Image.Resampling.LANCZOS))
    return im


def main():
    a = np.asarray(Image.open(SOURCE).convert("RGB"), dtype=np.float64) / 255
    image = Image.fromarray((rouge_cyan(sur_noir(a)) * 255 + 0.5).astype(np.uint8))
    dossier = ASSETS / "icones"
    dossier.mkdir(exist_ok=True)
    for t in TAILLES_LINUX:
        icone(image, t).save(dossier / f"vanguard-{t}.png", optimize=True)
    windows = [icone(image, t) for t in TAILLES_WINDOWS]
    # Le fichier part de la plus grande ; les autres y sont mises telles quelles au lieu d'être recalculées.
    windows[-1].save(ASSETS / "vanguard.ico", sizes=[im.size for im in windows], append_images=windows[:-1])
    print(f"{dossier}/ et {ASSETS / 'vanguard.ico'} écrits.")


if __name__ == "__main__":
    main()
