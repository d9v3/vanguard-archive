#!/usr/bin/env python3
"""Icône de Sentinel : trou noir calculé par lancer de rayons dans la métrique de Schwarzschild.

Chaque pixel est un rayon de lumière suivi à rebours depuis la caméra, courbé par la gravité.
Le disque d'accrétion vu « par-dessus » et « par-dessous » l'ombre (effet Interstellar) n'est
pas dessiné : il sort tout seul du calcul.

Lancer depuis la racine du dépôt :
    uv run --no-project --with numpy --with pillow python outils/icone.py
Produit assets/sentinel.png (512 px) et assets/sentinel.ico (16 à 256 px).
"""

import numpy as np
from PIL import Image, ImageFilter

# Unités : rayon de Schwarzschild = 1 (sphère des photons à 1,5, dernière orbite stable à 3).
TAILLE = 512
SURECH = 3  # suréchantillonnage : 3 × 3 rayons par pixel final
DISTANCE = 26.0  # caméra
ELEVATION = np.radians(9.0)  # au-dessus du plan du disque : presque de profil, comme Gargantua
INCLINAISON = np.radians(16.0)  # roulis de l'image : le disque monte de gauche à droite
CHAMP = np.radians(16.5)  # demi-angle de vue
DISQUE_INT, DISQUE_EXT = 2.6, 8.6

# Palette du thème Rouge OLED, du plus froid au plus chaud.
PALETTE = np.array(
    [
        [0x3a, 0x05, 0x05],
        [0x7e, 0x0c, 0x0c],
        [0xd4, 0x20, 0x20],
        [0xff, 0x5a, 0x4f],
        [0xff, 0x9a, 0x70],
        [0xff, 0xf1, 0xe6],
    ],
    dtype=np.float64,
) / 255.0


def couleur(t):
    """Interpole la palette pour t entre 0 et 1."""
    t = np.clip(t, 0.0, 1.0) * (len(PALETTE) - 1)
    i = np.minimum(t.astype(int), len(PALETTE) - 2)
    f = (t - i)[:, None]
    return PALETTE[i] * (1 - f) + PALETTE[i + 1] * f


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


def emission(p):
    """Couleur et opacité du disque au point p (dans le plan y = 0)."""
    r = np.hypot(p[:, 0], p[:, 2])
    phi = np.arctan2(p[:, 2], p[:, 0])
    # Profil de température : maximum juste après le bord intérieur, puis décroissance.
    x = DISQUE_INT / r
    chaleur = (x**1.6) * (1.0 - 0.55 * np.sqrt(x)) * 5.6
    bords = np.clip((r - DISQUE_INT) / 0.4, 0, 1) * np.clip((DISQUE_EXT - r) / 3.5, 0, 1)
    tex = texture(r, phi)
    intensite = chaleur * tex * bords
    alpha = np.clip(intensite * 1.6, 0.0, 0.97)
    return couleur(intensite**1.05) * np.clip(intensite * 1.2, 0, 1.3)[:, None], alpha


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
                col, a = emission(p[dans])
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
    # La lueur rougit en s'éloignant.
    lueur *= np.array([1.0, 0.42, 0.34])
    total = rgb + lueur * (1 - opac[..., None] * 0.6)
    a = np.clip(opac + lueur.max(axis=2), 0, 1)
    return total, a


def main():
    rgb, opac = lancer()
    rgb, a = halo(rgb, opac)
    # Tonalité douce : les blancs ne saturent pas brutalement.
    rgb = 1 - np.exp(-1.15 * rgb)
    couleur_vraie = np.where(a[..., None] > 1e-4, rgb / np.maximum(a, 1e-4)[..., None], 0)
    rgba = np.dstack([np.clip(couleur_vraie, 0, 1), a])
    grande = Image.fromarray((rgba * 255 + 0.5).astype(np.uint8), "RGBA")
    finale = grande.resize((TAILLE, TAILLE), Image.Resampling.LANCZOS)
    finale.save("assets/sentinel.png", optimize=True)
    tailles = [16, 24, 32, 48, 64, 128, 256]
    finale.save("assets/sentinel.ico", sizes=[(t, t) for t in tailles])
    print("assets/sentinel.png et assets/sentinel.ico écrits.")


if __name__ == "__main__":
    main()
