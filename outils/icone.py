#!/usr/bin/env python3
"""Icône de Vanguard : un rapace sur un bouclier d'acier, des circuits rouges, des orbites cyan, sur une plaque noire
arrondie.

Le dessin vient d'une image générée par l'auteur (assets/logo-source.jpg, l'emblème découpé au carré, couleurs
d'origine). Ce script en tire toutes les tailles :
- le fond bleu nuit devient noir pur, comme le menu et le thème du bureau (un halo ne brille que sur du noir) ;
- le vert des circuits et de l'œil passe au rouge, le cyan des orbites reste : rouge d'un côté, cyan de l'autre ;
- chaque taille a son cadrage : l'emblème entier n'est plus qu'une bouillie en 16 à 32 px (barre, onglet), où seule
  la tête du rapace se lit encore ; le bouclier entre les deux.

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

# Cadrages (côté en fraction de la source, décalage du centre) : du plus petit au plus grand, la taille maximale
# de l'icône qui le prend.
CADRAGES = [
    (40, (0.40, 0.06, -0.04)),  # tête du rapace
    (72, (0.72, 0.0, 0.02)),  # bouclier, départ des orbites
    (None, (1.0, 0.0, 0.0)),  # emblème entier
]
COIN = 0.18  # arrondi de la plaque, en fraction du côté

# Rouge de l'accent du thème (#ff0a1e), un peu adouci : teinte que prennent les verts.
TEINTE_ROUGE = 355.0


def sans_fond(a):
    """Retire le bleu nuit du fond : sa couleur (médiane des bords) est soustraite, puis le reste ramené à pleine
    échelle. Le fond devient noir pur et les lueurs gardent leur dégradé."""
    bords = np.concatenate([a[:20].reshape(-1, 3), a[-20:].reshape(-1, 3), a[:, :20].reshape(-1, 3), a[:, -20:].reshape(-1, 3)])
    fond = np.median(bords, axis=0) * 1.05
    return np.clip((a - fond) / (1 - fond), 0, 1)


def rouge_cyan(a):
    """Verts (75 à 185°) → rouge ; le cyan et le bleu des orbites ne bougent pas. Le passage s'adoucit aux deux
    bouts : sinon le vert d'eau, entre les deux, se découpe en taches."""
    hsv = Image.fromarray((a * 255 + 0.5).astype(np.uint8)).convert("HSV")
    h, s, v = (np.asarray(c, dtype=np.float64) for c in hsv.split())
    deg = h / 255 * 360
    poids = np.clip((185 - deg) / 20, 0, 1) * np.clip((deg - 75) / 15, 0, 1)
    deg = np.where(poids > 0.5, TEINTE_ROUGE, deg)
    s = np.clip(s * (1 + 0.25 * poids), 0, 255)
    plans = [deg / 360 * 255, s, v]
    hsv = Image.merge("HSV", [Image.fromarray(p.astype(np.uint8)) for p in plans])
    return np.asarray(hsv.convert("RGB"), dtype=np.float64) / 255


def cadrage(t):
    return next(c for limite, c in CADRAGES if limite is None or t <= limite)


def icone(image, t):
    """Icône de t px : le bon cadrage, réduit en une fois, un peu de netteté en petit, plaque arrondie."""
    n = image.size[0]
    cote, dx, dy = cadrage(t)
    c, cx, cy = n * cote, n * (0.5 + dx), n * (0.5 + dy)
    im = image.crop((round(cx - c / 2), round(cy - c / 2), round(cx + c / 2), round(cy + c / 2)))
    im = im.resize((t, t), Image.Resampling.LANCZOS)
    if t <= 48:
        im = im.filter(ImageFilter.UnsharpMask(radius=0.8, percent=80, threshold=0))
    # Plaque dessinée 4 fois plus grande puis réduite : un bord net même en 16 px.
    plaque = Image.new("L", (4 * t, 4 * t), 0)
    ImageDraw.Draw(plaque).rounded_rectangle([0, 0, 4 * t - 1, 4 * t - 1], radius=4 * t * COIN, fill=255)
    im.putalpha(plaque.resize((t, t), Image.Resampling.LANCZOS))
    return im


def main():
    a = np.asarray(Image.open(SOURCE).convert("RGB"), dtype=np.float64) / 255
    image = Image.fromarray((rouge_cyan(sans_fond(a)) * 255 + 0.5).astype(np.uint8))
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
