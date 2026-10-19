#!/usr/bin/env python3
"""Icône et bannière de Vanguard, dessinées dans l'écriture de la bannière du terminal : des lettres pleines (█) et
leur ombre en traits doubles (╔ ╗ ╚ ╝ ═ ║). L'icône est le V seul ; la bannière, le nom entier (tête du README).

Chaque caractère est une case dessinée en formes géométriques, pas une police : le rendu ne dépend d'aucune police
installée et reste net à toutes les tailles. En blanc sur une plaque noire arrondie, comme la bannière dans un
terminal.

Lancer depuis n'importe où (les images vont toujours dans le dépôt) :
    uv run --no-project --with pillow python outils/icone.py
Produit assets/icones/vanguard-<taille>.png (Linux, 16 à 512 px), assets/vanguard.ico (Windows, 16 à 256 px) et
assets/banniere.png.
"""

from pathlib import Path

from PIL import Image, ImageDraw

# Lancé depuis un autre dossier, le script écrivait dans un « assets » de ce dossier-là, ou s'arrêtait.
ASSETS = Path(__file__).resolve().parent.parent / "assets"

BANNIERE = """\
██╗   ██╗ █████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
██║   ██║██╔══██╗████╗  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██║   ██║███████║██╔██╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
╚██╗ ██╔╝██╔══██║██║╚██╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
 ╚████╔╝ ██║  ██║██║ ╚████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝"""
# Le V : les neuf premières colonnes de la bannière.
V = "\n".join(ligne[:9] for ligne in BANNIERE.splitlines())

BLANC = (0xFF, 0xFF, 0xFF)
NOIR = (0, 0, 0)
COIN = 0.18  # arrondi de la plaque, en fraction du petit côté
SURECH = 8  # dessin 8 fois plus grand, puis réduit : des bords lisses

# Une image par taille : le système n'a jamais à réduire lui-même la plus grande.
# Linux : les dossiers de hicolor (la barre et le lanceur prennent la taille la plus proche).
TAILLES_LINUX = [16, 22, 24, 32, 48, 64, 128, 256, 512]
# Windows : ses tailles de base (16, 24, 32, 48, 256) et leurs versions pour les écrans agrandis de 125 à 300 %.
TAILLES_WINDOWS = [16, 20, 24, 30, 32, 36, 40, 48, 60, 64, 72, 80, 96, 256]

# Traits doubles : chaque coin relie une direction horizontale (-1 gauche, +1 droite) et une verticale (-1 haut,
# +1 bas) ; ═ et ║ traversent la case.
COINS = {"╗": (-1, 1), "╔": (1, 1), "╝": (-1, -1), "╚": (1, -1)}


def case(d, c, x, y, l, h, ombre):
    """Dessine le caractère `c` dans la case (x, y, l × h). Un terminal fait des cases deux fois plus hautes que
    larges ; les deux traits d'une ligne double sont écartés d'un quart de la largeur."""
    if c == "█":
        d.rectangle([x, y, x + l, y + h], fill=BLANC)
        return
    cx, cy = x + l / 2, y + h / 2
    ecart, trait = l * 0.22, max(1.0, l * 0.13)

    def ligne(x0, y0, x1, y1):
        d.rectangle([min(x0, x1) - trait / 2, min(y0, y1) - trait / 2, max(x0, x1) + trait / 2, max(y0, y1) + trait / 2], fill=ombre)

    if c == "═":
        for s in (-1, 1):
            ligne(x, cy + s * ecart, x + l, cy + s * ecart)
    elif c == "║":
        for s in (-1, 1):
            ligne(cx + s * ecart, y, cx + s * ecart, y + h)
    elif c in COINS:
        sh, sv = COINS[c]
        bord_h = x if sh < 0 else x + l
        bord_v = y if sv < 0 else y + h
        # Trait extérieur puis intérieur du coin : chacun va du bord de la case au point où il tourne.
        for s in (1, -1):
            yh = cy - s * sv * ecart
            xv = cx - s * sh * ecart
            ligne(bord_h, yh, xv, yh)
            ligne(xv, yh, xv, bord_v)


def dessin(texte, cellule):
    """Le texte en cases de `cellule` × 2·`cellule` px, fond transparent."""
    lignes = texte.splitlines()
    colonnes = max(len(l) for l in lignes)
    l, h = cellule, 2 * cellule
    im = Image.new("RGBA", (colonnes * l, len(lignes) * h), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    for j, ligne in enumerate(lignes):
        for i, c in enumerate(ligne):
            if c != " ":
                case(d, c, i * l, j * h, l, h, BLANC)
    return im


def sur_plaque(motif, largeur, hauteur, marge):
    """Le motif centré sur une plaque noire arrondie de largeur × hauteur (en px du dessin agrandi), `marge` autour."""
    plaque = Image.new("RGBA", (largeur, hauteur), (0, 0, 0, 0))
    ImageDraw.Draw(plaque).rounded_rectangle([0, 0, largeur - 1, hauteur - 1], radius=min(largeur, hauteur) * COIN, fill=NOIR + (255,))
    echelle = min((largeur - 2 * marge) / motif.width, (hauteur - 2 * marge) / motif.height)
    m = motif.resize((round(motif.width * echelle), round(motif.height * echelle)), Image.Resampling.LANCZOS)
    plaque.alpha_composite(m, ((largeur - m.width) // 2, (hauteur - m.height) // 2))
    return plaque


def icone(t):
    """Le V sur sa plaque, t px."""
    n = t * SURECH
    grand = sur_plaque(dessin(V, n // 8), n, n, n * 0.16)
    return grand.resize((t, t), Image.Resampling.LANCZOS)


def banniere():
    """Le nom entier, 1200 px de large, sur une plaque noire arrondie (lisible sur le fond clair de GitHub)."""
    motif = dessin(BANNIERE, 12 * SURECH)
    largeur = 1200 * SURECH
    hauteur = round(largeur * (motif.height / motif.width) + 2 * 48 * SURECH)
    grand = sur_plaque(motif, largeur, hauteur, 48 * SURECH)
    return grand.resize((1200, round(hauteur / SURECH)), Image.Resampling.LANCZOS)


def main():
    dossier = ASSETS / "icones"
    dossier.mkdir(exist_ok=True)
    for t in TAILLES_LINUX:
        icone(t).save(dossier / f"vanguard-{t}.png", optimize=True)
    windows = [icone(t) for t in TAILLES_WINDOWS]
    # Le fichier part de la plus grande ; les autres y sont mises telles quelles au lieu d'être recalculées.
    windows[-1].save(ASSETS / "vanguard.ico", sizes=[im.size for im in windows], append_images=windows[:-1])
    banniere().save(ASSETS / "banniere.png", optimize=True)
    print(f"{dossier}/, {ASSETS / 'vanguard.ico'} et {ASSETS / 'banniere.png'} écrits.")


if __name__ == "__main__":
    main()
