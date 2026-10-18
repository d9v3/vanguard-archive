#!/usr/bin/env python3
"""Icône de Gardien : un bouclier ouvert sur un trou noir, calculé par lancer de rayons dans la métrique de
Schwarzschild.

Chaque pixel est un rayon de lumière suivi à rebours depuis la caméra, courbé par la gravité.
Le disque d'accrétion vu « par-dessus » et « par-dessous » l'ombre (effet Interstellar) n'est
pas dessiné : il sort tout seul du calcul. Ses couleurs aussi : le disque tourne presque à la vitesse de la lumière,
le côté qui vient vers nous bleuit et brille plus (effet Doppler), celui qui s'éloigne rougit. Cyan du menu d'un
côté, rouge du thème de l'autre.

Le trou noir est posé sur un bouclier noir : un halo est de la lumière, il ne brille que sur du noir (sur un fond
clair, Explorateur de Windows, GitHub, il devenait une tache rose-brun). Un liseré du rouge au cyan dessine le
bouclier sur un fond noir aussi (barre, mode sombre de GitHub), où le noir seul ne se voyait pas.

Lancer depuis la racine du dépôt :
    uv run --no-project --with numpy --with pillow python outils/icone.py
Produit assets/icones/gardien-<taille>.png (Linux, 16 à 512 px) et assets/gardien.ico (Windows, 16 à 256 px).
"""

from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFilter

# Unités : rayon de Schwarzschild = 1 (sphère des photons à 1,5, dernière orbite stable à 3).
TAILLE = 512
SURECH = 3  # suréchantillonnage : 3 × 3 rayons par pixel final
DISTANCE = 26.0  # caméra
ELEVATION = np.radians(9.0)  # au-dessus du plan du disque : presque de profil, comme Gargantua
INCLINAISON = np.radians(16.0)  # roulis de l'image : le disque monte de gauche à droite
CHAMP = np.radians(13.6)  # demi-angle de vue : cadrage serré, les pointes du disque touchent le bord du bouclier
DISQUE_INT, DISQUE_EXT = 2.6, 8.6
# Sens de rotation du disque : le côté droit vient vers nous (cyan), le gauche s'éloigne (rouge).
SENS = 1.0
REMONTEE = 0.04  # le trou noir monte un peu dans le bouclier, plus large en haut qu'en bas (fraction du côté)

# Une image par taille, réduite depuis le grand rendu : le système n'a jamais à la réduire lui-même.
# Linux : les dossiers de hicolor (la barre et le lanceur prennent la taille la plus proche).
TAILLES_LINUX = [16, 22, 24, 32, 48, 64, 128, 256, 512]
# Windows : ses tailles de base (16, 24, 32, 48, 256) et leurs versions pour les écrans agrandis de 125 à 300 %.
TAILLES_WINDOWS = [16, 20, 24, 30, 32, 36, 40, 48, 60, 64, 72, 80, 96, 256]

# Palettes, du plus froid au plus chaud : côté qui s'éloigne (rouge du thème Rouge OLED), gaz vu de face (blanc
# chaud), côté qui approche (cyan des titres du menu, #29b8db dans les captures).
ROUGE = np.array(
    [[0x3a, 0x05, 0x05], [0x7e, 0x0c, 0x0c], [0xd4, 0x20, 0x20], [0xff, 0x5a, 0x4f], [0xff, 0x9a, 0x70], [0xff, 0xf1, 0xe6]],
    dtype=np.float64,
) / 255.0
BLANC = np.array(
    [[0x24, 0x14, 0x12], [0x66, 0x3c, 0x34], [0xc0, 0x7c, 0x6c], [0xf4, 0xbc, 0xa8], [0xff, 0xe4, 0xd8], [0xff, 0xfb, 0xf8]],
    dtype=np.float64,
) / 255.0
BLEU = np.array(
    [[0x02, 0x18, 0x20], [0x06, 0x3a, 0x4c], [0x0e, 0x78, 0x96], [0x1f, 0xb0, 0xd6], [0x4f, 0xd2, 0xf2], [0xb8, 0xf0, 0xff]],
    dtype=np.float64,
) / 255.0
# Liseré du bouclier : rouge à gauche, cyan à droite, comme le disque.
LISERE_GAUCHE = np.array([0xd4, 0x20, 0x20]) / 255.0
LISERE_DROITE = np.array([0x1f, 0xb0, 0xd6]) / 255.0


def couleur(palette, t):
    """Interpole une palette pour t entre 0 et 1."""
    t = np.clip(t, 0.0, 1.0) * (len(palette) - 1)
    i = np.minimum(t.astype(int), len(palette) - 2)
    f = (t - i)[:, None]
    return palette[i] * (1 - f) + palette[i + 1] * f


def texture(r, phi):
    """Turbulence du disque : filaments étirés en spirale par la rotation."""
    rng = np.random.default_rng(7)
    s = np.zeros_like(r)
    lr = np.log(r)
    for k in range(1, 6):
        n = rng.integers(1, 4) * k  # nombre de bras
        cisaillement = rng.uniform(2.0, 4.0)
        phase = rng.uniform(0, 2 * np.pi)
        s += np.sin(n * phi + cisaillement * k * lr + phase) / k**0.8
    anneaux = 0.5 + 0.5 * np.sin(14.0 * lr + 1.3) * np.sin(31.0 * lr)
    s = 0.5 + 0.5 * s / 2.2
    return np.clip(0.55 + 0.6 * (s - 0.5) + 0.25 * (anneaux - 0.5), 0.15, 1.2)


def emission(p, k):
    """Couleur et opacité du disque au point p (dans le plan y = 0), vu par un photon qui part dans la direction k."""
    r = np.hypot(p[:, 0], p[:, 2])
    phi = np.arctan2(p[:, 2], p[:, 0])
    # Profil de température : maximum juste après le bord intérieur, puis décroissance.
    x = DISQUE_INT / r
    chaleur = (x**1.6) * (1.0 - 0.55 * np.sqrt(x)) * 5.6
    bords = np.clip((r - DISQUE_INT) / 0.4, 0, 1) * np.clip((DISQUE_EXT - r) / 3.5, 0, 1)
    tex = texture(r, phi)
    # Orbite circulaire (M = 0,5 dans ces unités) : vitesse locale sqrt(M / (r - 2M)), plus de la moitié de celle de
    # la lumière au bord intérieur. Facteur Doppler : > 1 quand le gaz vient vers nous.
    beta = np.sqrt(0.5 / (r - 1.0))
    tangente = np.stack([-np.sin(phi), np.zeros_like(phi), np.cos(phi)], axis=1) * SENS
    gamma = 1 / np.sqrt(1 - beta**2)
    doppler = 1 / (gamma * (1 - beta * np.sum(tangente * k, axis=1)))
    # Éclat adouci (la physique dirait puissance 4 : un côté disparaîtrait).
    intensite = chaleur * tex * bords * np.clip(doppler, 0.5, 1.8) ** 0.9
    alpha = np.clip(intensite * 1.6, 0.0, 0.97)
    # Teinte : blanc chaud de face, vers le cyan ou le rouge selon le décalage.
    t = np.clip(np.log(doppler) / np.log(1.4), -1, 1)[:, None]
    ti = intensite**1.05
    blanc = couleur(BLANC, ti)
    teinte = np.where(t < 0, blanc * (1 + t) - couleur(ROUGE, ti) * t, blanc * (1 - t) + couleur(BLEU, ti) * t)
    return teinte * np.clip(intensite * 1.2, 0, 1.3)[:, None], alpha


def lancer():
    n = TAILLE * SURECH
    # Repère de la caméra.
    cam = DISTANCE * np.array([0.0, np.sin(ELEVATION), np.cos(ELEVATION)])
    avant = -cam / np.linalg.norm(cam)
    droite = np.cross(avant, [0.0, 1.0, 0.0])
    droite /= np.linalg.norm(droite)
    haut = np.cross(droite, avant)
    c, s = np.cos(INCLINAISON), np.sin(INCLINAISON)
    droite, haut = c * droite - s * haut, s * droite + c * haut

    u = (np.arange(n) + 0.5) / n * 2 - 1
    gx, gy = np.meshgrid(u, -u)
    t = np.tan(CHAMP)
    d = avant + (gx.ravel() * t)[:, None] * droite + (gy.ravel() * t)[:, None] * haut
    d /= np.linalg.norm(d, axis=1)[:, None]

    total = n * n
    pos = np.tile(cam, (total, 1))
    vit = d.copy()
    h2 = np.sum(np.cross(pos, vit) ** 2, axis=1)  # moment angulaire au carré, constant

    rgb = np.zeros((total, 3))
    opac = np.zeros(total)
    actifs = np.arange(total)

    def acc(x, h2a):
        r2 = np.sum(x * x, axis=1)
        return -1.5 * h2a[:, None] * x / (r2 ** 2.5)[:, None]

    for _ in range(3000):
        if actifs.size == 0:
            break
        x, v, h = pos[actifs], vit[actifs], h2[actifs]
        r = np.linalg.norm(x, axis=1)
        dt = np.clip(0.035 * r, 0.004, 0.8)[:, None]
        # Runge-Kutta 4 sur x'' = a(x)
        k1v = acc(x, h)
        k1x = v
        k2v = acc(x + 0.5 * dt * k1x, h)
        k2x = v + 0.5 * dt * k1v
        k3v = acc(x + 0.5 * dt * k2x, h)
        k3x = v + 0.5 * dt * k2v
        k4v = acc(x + dt * k3x, h)
        k4x = v + dt * k3v
        nx = x + dt / 6 * (k1x + 2 * k2x + 2 * k3x + k4x)
        nv = v + dt / 6 * (k1v + 2 * k2v + 2 * k3v + k4v)

        # Traversée du plan du disque : on y accumule la lumière, de l'avant vers l'arrière.
        croise = np.sign(x[:, 1]) != np.sign(nx[:, 1])
        if croise.any():
            i = np.nonzero(croise)[0]
            f = (x[i, 1] / (x[i, 1] - nx[i, 1]))[:, None]
            p = x[i] + f * (nx[i] - x[i])
            rp = np.hypot(p[:, 0], p[:, 2])
            dans = (rp > DISQUE_INT) & (rp < DISQUE_EXT)
            if dans.any():
                j = actifs[i[dans]]
                # Le photon voyage à l'inverse du rayon suivi.
                vd = v[i[dans]]
                col, a = emission(p[dans], -vd / np.linalg.norm(vd, axis=1)[:, None])
                reste = (1 - opac[j])
                rgb[j] += (reste * a)[:, None] * col
                opac[j] += reste * a

        pos[actifs], vit[actifs] = nx, nv
        rn = np.linalg.norm(nx, axis=1)
        avale = rn < 1.0
        opac[actifs[avale]] = 1.0  # horizon : noir absolu, opaque
        echappe = (rn > DISTANCE * 1.6) & (np.sum(nx * nv, axis=1) > 0)
        fini = avale | echappe | (opac[actifs] > 0.995)
        actifs = actifs[~fini]

    rgb = rgb.reshape(n, n, 3)
    opac = opac.reshape(n, n)
    return rgb, opac


def halo(rgb, opac):
    """Lueur autour des zones les plus chaudes (couleur prémultipliée)."""
    lum = rgb.max(axis=2)
    brillant = rgb * np.clip(lum - 0.35, 0, None)[..., None] * 1.6
    img = Image.fromarray((np.clip(brillant, 0, 1) * 255).astype(np.uint8))
    n = rgb.shape[0]
    lueur = np.zeros_like(rgb)
    for rayon, poids in ((n * 0.006, 0.9), (n * 0.02, 0.7), (n * 0.06, 0.55)):
        lueur += np.asarray(img.filter(ImageFilter.GaussianBlur(rayon)), dtype=np.float64) / 255 * poids
    # Lueur un peu atténuée, de la couleur du gaz qui l'émet.
    lueur *= np.array([0.85, 0.75, 0.9])
    return rgb + lueur * (1 - opac[..., None] * 0.6)


def bouclier(n, retrait=0.0):
    """Masque du bouclier (écu : haut droit aux coins arrondis, flancs droits puis courbes jusqu'à la pointe), en
    n × n ; `retrait` le rétrécit de ce nombre de pixels (intérieur du liseré)."""
    g, d, h, b = retrait, n - retrait, retrait, n - retrait
    r = n * 0.09
    points = [(g + r + r * np.cos(a), h + r + r * np.sin(a)) for a in np.linspace(np.pi, 1.5 * np.pi, 16)]
    points += [(d - r + r * np.cos(a), h + r + r * np.sin(a)) for a in np.linspace(1.5 * np.pi, 2 * np.pi, 16)]
    flanc = n * 0.44
    # Flanc droit jusqu'à la pointe (Bézier cubique), puis le gauche en miroir.
    t = np.linspace(0, 1, 60)[:, None]
    p0, p1 = np.array([d, flanc]), np.array([d, flanc + (b - flanc) * 0.5])
    p2, p3 = np.array([n / 2 + (d - n / 2) * 0.3, b - (b - flanc) * 0.2]), np.array([n / 2, b])
    courbe = (1 - t) ** 3 * p0 + 3 * (1 - t) ** 2 * t * p1 + 3 * (1 - t) * t**2 * p2 + t**3 * p3
    points += [tuple(p) for p in courbe]
    points += [(n - x, y) for x, y in courbe[::-1][1:]]
    masque = Image.new("L", (n, n), 0)
    ImageDraw.Draw(masque).polygon(points, fill=255)
    return np.asarray(masque, dtype=np.float64) / 255


def lineaire(c):
    """Valeurs d'écran (sRGB) → quantité de lumière."""
    return np.where(c <= 0.04045, c / 12.92, ((c + 0.055) / 1.055) ** 2.4)


def ecran(c):
    """Quantité de lumière → valeurs d'écran (sRGB)."""
    c = np.clip(c, 0, 1)
    return np.where(c <= 0.0031308, c * 12.92, 1.055 * c ** (1 / 2.4) - 0.055)


def reduire(lumiere, t):
    """Image de t px. La moyenne se fait sur la lumière, pas sur les valeurs d'écran : sinon un anneau fin et
    brillant, mêlé au noir qui l'entoure, s'assombrit et disparaît dans les petites tailles."""

    def plan(p):
        petit = Image.fromarray(p.astype(np.float32)).resize((t, t), Image.Resampling.LANCZOS)
        return np.asarray(petit, dtype=np.float64)

    rgb = np.dstack([plan(lumiere[..., c]) for c in range(3)])
    im = Image.fromarray((ecran(rgb) * 255 + 0.5).astype(np.uint8))
    if t <= 48:
        # Un peu de netteté en petit, sur la couleur seulement : le liseré, posé ensuite, reste tel quel.
        im = im.filter(ImageFilter.UnsharpMask(radius=0.7 if t <= 24 else 1.0, percent=90, threshold=0))
    rgb = lineaire(np.asarray(im, dtype=np.float64) / 255)
    # Bouclier et liseré dessinés à cette taille (4 fois plus grand, puis réduits) : un liseré réduit depuis 512 px
    # ne ferait plus qu'un demi-pixel flou en 16 px. Au moins un pixel, plus marqué en petit.
    sur = 4 * t
    epaisseur = max(4.0, 0.02 * sur)
    masque = plan_reduit(bouclier(sur), t)
    interieur = plan_reduit(bouclier(sur, retrait=epaisseur), t)
    bande = np.clip(masque - interieur, 0, 1)[..., None]
    x = np.linspace(0, 1, t)[None, :, None]
    lisere = lineaire(LISERE_GAUCHE) * (1 - x) + lineaire(LISERE_DROITE) * x
    force = 0.85 if t <= 48 else 0.6
    rgb = rgb * (1 - bande * force) + lisere * bande * force
    im = Image.fromarray((ecran(rgb) * 255 + 0.5).astype(np.uint8))
    im.putalpha(Image.fromarray((np.clip(masque, 0, 1) * 255 + 0.5).astype(np.uint8)))
    return im


def plan_reduit(p, t):
    petit = Image.fromarray(p.astype(np.float32)).resize((t, t), Image.Resampling.BOX)
    return np.asarray(petit, dtype=np.float64)


def main():
    rgb, opac = lancer()
    rgb = halo(rgb, opac)
    # Tonalité douce : les blancs ne saturent pas brutalement.
    rgb = 1 - np.exp(-1.15 * rgb)
    # Couleurs prémultipliées : posées sur le noir du bouclier, elles s'affichent telles quelles.
    lumiere = lineaire(np.clip(rgb, 0, 1))
    n = lumiere.shape[0]
    dy = round(n * REMONTEE)
    lumiere = np.concatenate([lumiere[dy:], np.zeros((dy, n, 3))])
    dossier = Path("assets/icones")
    dossier.mkdir(exist_ok=True)
    for t in TAILLES_LINUX:
        reduire(lumiere, t).save(dossier / f"gardien-{t}.png", optimize=True)
    windows = [reduire(lumiere, t) for t in TAILLES_WINDOWS]
    # Le fichier part de la plus grande ; les autres y sont mises telles quelles au lieu d'être recalculées.
    windows[-1].save("assets/gardien.ico", sizes=[im.size for im in windows], append_images=windows[:-1])
    print("assets/icones/ et assets/gardien.ico écrits.")


if __name__ == "__main__":
    main()
