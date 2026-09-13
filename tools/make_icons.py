# -*- coding: utf-8 -*-
"""
Генератор набора иконок MetroBox.

Сюжет — по мотивам NekoBox: изометрическая картонная коробка с четырьмя
отогнутыми наружу клапанами, но вместо кота из неё выглядывает наклонённый
смартфон Lumia со стартовым экраном Windows 10 Mobile.

Рисуется в условном пространстве 1024x1024 и рендерится с 4-кратным
суперсемплингом, поэтому края остаются чистыми на любом размере.
"""
import math
import os
from PIL import Image, ImageDraw, ImageFilter

# Каталог ассетов относительно этого файла: tools/ -> VlessApp/Assets
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'VlessApp', 'Assets')
SS = 4  # коэффициент суперсемплинга

# --- фон (согласован с тёмным UI приложения) ---
BG_TOP    = (20, 29, 52)
BG_BOT    = (8, 12, 24)
GLOW      = (56, 189, 248)
SPLASH_BG = (15, 21, 38)      # обязан совпадать с BackgroundColor в манифесте (#0F1526)

# --- картон ---
CARD_LEFT  = (214, 156, 96)   # передняя левая грань (освещена)
CARD_RIGHT = (176, 122, 66)   # передняя правая грань (в тени)
CARD_RIM   = (233, 181, 120)  # торец картона по краю выреза
CARD_FLAP  = (243, 200, 143)  # внутренняя сторона ближнего левого клапана (свет слева)
CARD_FLAP2 = (222, 176, 118)  # ближний правый — уже в полутени
CARD_FLAPB = (206, 148, 90)   # дальние клапаны — темнее, уходят вглубь
CARD_IN    = (92, 58, 30)     # темнота внутри коробки
CARD_INLIT = (124, 82, 44)    # подсвеченная задняя стенка внутри
EDGE       = (120, 76, 38)    # обводка

# --- телефон ---
BODY       = (0, 164, 239)    # поликарбонат Lumia
BODY_LO    = (0, 108, 162)
GLASS      = (11, 13, 18)
BEZEL_PART = (38, 44, 54)     # динамик, камера
PH_EDGE    = (6, 40, 60)

T_BLUE   = (0, 99, 177)
T_MAG    = (227, 0, 140)
T_GREEN  = (16, 124, 16)
T_ORANGE = (255, 140, 0)
T_TEAL   = (0, 183, 195)
T_PURPLE = (92, 45, 145)
T_RED    = (209, 52, 56)
T_JADE   = (1, 133, 116)
T_AZURE  = (0, 120, 215)
WHITE    = (255, 255, 255)

# --- изометрия коробки: ромб выреза N-E-S-W и высота стенок ---
# Вырез поднят высоко, а стенки сделаны глубокими: иначе коробка выглядит
# подносом, из которого телефон торчит целиком, вместо того чтобы стоять внутри.
N = (512, 392)
E = (806, 534)
S = (512, 676)
W = (218, 534)
BOX_H = 240
Ep = (E[0], E[1] + BOX_H)
Sp = (S[0], S[1] + BOX_H)
Wp = (W[0], W[1] + BOX_H)


def _flap(p1, p2, dx, dy):
    return [p1, p2, (p2[0] + dx, p2[1] + dy), (p1[0] + dx, p1[1] + dy)]


# Клапаны — параллелограммы, отогнутые от четырёх рёбер выреза наружу.
# Ближние нарочно короче дальних: так они не съедают передние стенки,
# и коробка читается коробкой, а не четырёхлучевой звездой.
FLAP_BL = _flap(N, W, -104, -126)
FLAP_BR = _flap(N, E,  104, -126)
FLAP_FL = _flap(W, S,  -96,     8)
FLAP_FR = _flap(E, S,   96,     8)

# --- телефон в собственной системе координат ---
PW, PH_ = 290, 650
PAD = 60
SCR = (21, 84, 269, 570)      # стекло экрана
TILT = -10                    # градусы, по часовой стрелке
PH_CX, PH_CY = 508, 492       # куда встаёт центр телефона в кадре 1024


def _s(v, k):
    return v * k


def _poly(d, pts, k, **kw):
    d.polygon([(_s(x, k), _s(y, k)) for x, y in pts], **kw)


def _background(k):
    n = 1024 * k
    img = Image.new("RGBA", (n, n))
    d = ImageDraw.Draw(img)
    for y in range(n):
        t = y / (n - 1)
        d.line([(0, y), (n, y)],
               fill=tuple(int(a + (b - a) * t) for a, b in zip(BG_TOP, BG_BOT)) + (255,))

    glow = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    ImageDraw.Draw(glow).ellipse([_s(250, k), _s(140, k), _s(774, k), _s(700, k)],
                                 fill=GLOW + (58,))
    return Image.alpha_composite(img, glow.filter(ImageFilter.GaussianBlur(_s(90, k))))


# ------------------------------------------------------------------ телефон

def _glyph_windows(d, k, cx, cy, size):
    """Флажок Windows — самая узнаваемая деталь на плитке."""
    g = size * 0.08
    h = (size - g) / 2
    for dx in (0, h + g):
        for dy in (0, h + g):
            x = cx - size / 2 + dx
            y = cy - size / 2 + dy
            d.rectangle([_s(x, k), _s(y, k), _s(x + h, k), _s(y + h, k)], fill=WHITE + (255,))


def _glyph_envelope(d, k, cx, cy, size):
    w, h = size, size * 0.68
    x0, y0 = cx - w / 2, cy - h / 2
    d.rectangle([_s(x0, k), _s(y0, k), _s(x0 + w, k), _s(y0 + h, k)], fill=WHITE + (255,))
    d.polygon([(_s(x0, k), _s(y0, k)),
               (_s(cx, k), _s(y0 + h * 0.62, k)),
               (_s(x0 + w, k), _s(y0, k))], fill=T_MAG + (255,))


def _glyph_dot(d, k, cx, cy, size):
    r = size / 2
    d.ellipse([_s(cx - r, k), _s(cy - r, k), _s(cx + r, k), _s(cy + r, k)], fill=WHITE + (255,))


def _phone_layer(k, detail):
    lay = Image.new("RGBA", ((PW + 2 * PAD) * k, (PH_ + 2 * PAD) * k), (0, 0, 0, 0))
    d = ImageDraw.Draw(lay)
    ox = oy = PAD

    def R(box, r, **kw):
        x0, y0, x1, y1 = box
        d.rounded_rectangle([_s(x0 + ox, k), _s(y0 + oy, k), _s(x1 + ox, k), _s(y1 + oy, k)],
                            radius=_s(r, k), **kw)

    # корпус: тёмный кант + цветной поликарбонат + стекло
    R((-4, -4, PW + 4, PH_ + 4), 46, fill=PH_EDGE + (255,))
    R((0, 0, PW, PH_), 42, fill=BODY + (255,))
    R((0, PH_ * 0.62, PW, PH_), 42, fill=BODY_LO + (60,))
    R((9, 9, PW - 9, PH_ - 9), 35, fill=GLASS + (255,))

    sx1 = SCR[2]
    if detail:
        # динамик и глазок фронтальной камеры
        R((109, 50, 181, 58), 4, fill=BEZEL_PART + (255,))
        d.ellipse([_s(201 + ox, k), _s(47 + oy, k), _s(215 + ox, k), _s(61 + oy, k)],
                  fill=BEZEL_PART + (255,))

        # строка состояния: шкала сигнала и батарея
        for i, hgt in enumerate((5, 8, 11, 14)):
            x = 29 + i * 7
            d.rectangle([_s(x + ox, k), _s(102 - hgt + oy, k), _s(x + 4 + ox, k), _s(102 + oy, k)],
                        fill=(150, 160, 175, 255))
        R((sx1 - 34, 90, sx1 - 12, 102), 2, fill=(150, 160, 175, 255))

    # стартовый экран: 4 колонки по 53 с зазором 6
    c = [29, 88, 147, 206]
    u, g = 53, 6
    m = 2 * u + g                                   # сторона плитки 2x2
    if detail:
        tiles = [
            ((c[0], 112, c[1] + u, 112 + m), T_BLUE,   "win"),
            ((c[2], 112, c[2] + u, 112 + u), T_MAG,    "env"),
            ((c[3], 112, c[3] + u, 112 + u), T_GREEN,  "dot"),
            ((c[2], 171, c[2] + u, 171 + u), T_ORANGE, None),
            ((c[3], 171, c[3] + u, 171 + u), T_TEAL,   None),
            ((c[0], 230, c[3] + u, 230 + m), T_PURPLE, None),
            ((c[0], 348, c[1] + u, 348 + m), T_RED,    "dot"),
            ((c[2], 348, c[3] + u, 348 + m), T_JADE,   None),
            ((c[0], 466, c[3] + u, 466 + u), T_AZURE,  None),
        ]
    else:
        # на мелких размерах сетка превращается в кашу — оставляем крупные блоки
        tiles = [
            ((c[0], 112, c[1] + u, 236), T_BLUE,   None),
            ((c[2], 112, c[3] + u, 236), T_MAG,    None),
            ((c[0], 248, c[3] + u, 372), T_PURPLE, None),
            ((c[0], 384, c[1] + u, 520), T_GREEN,  None),
            ((c[2], 384, c[3] + u, 520), T_ORANGE, None),
        ]

    for box, col, glyph in tiles:
        R(box, 2, fill=col + (255,))
        if not glyph:
            continue
        gx, gy = (box[0] + box[2]) / 2, (box[1] + box[3]) / 2
        gs = min(box[2] - box[0], box[3] - box[1]) * 0.34
        if glyph == "win":
            _glyph_windows(d, k, gx + ox, gy + oy, gs)
        elif glyph == "env":
            _glyph_envelope(d, k, gx + ox, gy + oy, gs)
        else:
            _glyph_dot(d, k, gx + ox, gy + oy, gs * 0.72)

    if detail:
        # узкий диагональный блик по стеклу, обрезанный по его форме
        gl = Image.new("RGBA", lay.size, (0, 0, 0, 0))
        _poly(ImageDraw.Draw(gl),
              [(ox - 10, oy + 210), (ox + 96, oy - 10), (ox + 142, oy - 10), (ox - 10, oy + 286)],
              k, fill=(255, 255, 255, 20))
        mask = Image.new("L", lay.size, 0)
        ImageDraw.Draw(mask).rounded_rectangle(
            [_s(9 + ox, k), _s(9 + oy, k), _s(PW - 9 + ox, k), _s(PH_ - 9 + oy, k)],
            radius=_s(35, k), fill=255)
        empty = Image.new("RGBA", lay.size, (0, 0, 0, 0))
        lay = Image.alpha_composite(lay, Image.composite(gl, empty, mask))

    return lay


# ------------------------------------------------------------------ коробка

def _box_back(d, k):
    """Всё, что находится ЗА телефоном: нутро коробки и дальние клапаны."""
    _poly(d, FLAP_BL, k, fill=CARD_FLAPB + (255,), outline=EDGE + (255,), width=max(1, _s(3, k)))
    _poly(d, FLAP_BR, k, fill=CARD_FLAPB + (255,), outline=EDGE + (255,), width=max(1, _s(3, k)))
    _poly(d, [N, E, S, W], k, fill=CARD_IN + (255,))
    # подсвеченная задняя стенка внутри — даёт ощущение глубины
    _poly(d, [N, E, (E[0], E[1] + 46), (N[0], N[1] + 46)], k, fill=CARD_INLIT + (255,))
    _poly(d, [N, W, (W[0], W[1] + 46), (N[0], N[1] + 46)], k, fill=CARD_INLIT + (255,))


def _box_front(d, k, detail):
    """Всё, что перед телефоном: передние грани, торец и ближние клапаны."""
    lw = max(1, _s(3, k))
    _poly(d, [W, S, Sp, Wp], k, fill=CARD_LEFT + (255,), outline=EDGE + (255,), width=lw)
    _poly(d, [S, E, Ep, Sp], k, fill=CARD_RIGHT + (255,), outline=EDGE + (255,), width=lw)

    # торец картона по переднему краю выреза
    t = 15
    _poly(d, [W, S, (S[0], S[1] + t), (W[0], W[1] + t)], k, fill=CARD_RIM + (255,))
    _poly(d, [S, E, (E[0], E[1] + t), (S[0], S[1] + t)], k, fill=CARD_RIM + (255,))

    _poly(d, FLAP_FL, k, fill=CARD_FLAP + (255,), outline=EDGE + (255,), width=lw)
    _poly(d, FLAP_FR, k, fill=CARD_FLAP2 + (255,), outline=EDGE + (255,), width=lw)


# ------------------------------------------------------------------ сборка

def scene(k, with_bg=True, detail=True):
    n = 1024 * k
    art = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    d = ImageDraw.Draw(art)

    _box_back(d, k)

    rot = _phone_layer(k, detail).rotate(TILT, resample=Image.BICUBIC, expand=True)
    art.alpha_composite(rot, (int(_s(PH_CX, k) - rot.width / 2),
                              int(_s(PH_CY, k) - rot.height / 2)))

    _box_front(d, k, detail)

    if not with_bg:
        return art

    base = _background(k)
    sh = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    ImageDraw.Draw(sh).ellipse([_s(200, k), _s(830, k), _s(824, k), _s(946, k)],
                               fill=(0, 0, 0, 140))
    base = Image.alpha_composite(base, sh.filter(ImageFilter.GaussianBlur(_s(20, k))))
    return Image.alpha_composite(base, art)


def square(size, with_bg=True):
    detail = size > 32
    img = scene(SS, with_bg=with_bg, detail=detail)
    if not detail:
        # оптическое укрупнение: на 16-32 px поля по углам — непозволительная роскошь,
        # подрезаем кадр по содержимому, чтобы рисунок занял больше пикселей
        n = img.size[0]
        cut = int(n * 0.075)
        img = img.crop((cut, cut, n - cut, n - cut))
    return img.resize((size, size), Image.LANCZOS)


def _centered(canvas, fraction):
    w, h = canvas.size
    px = int(h * fraction)
    art = scene(SS, with_bg=False, detail=px > 32).resize((px, px), Image.LANCZOS)
    canvas.alpha_composite(art, ((w - px) // 2, (h - px) // 2))
    return canvas


def wide(w, h):
    """Широкая плитка: изображение заполняет плитку целиком, градиент уместен."""
    return _centered(_background(SS).resize((w, h), Image.LANCZOS), 0.92)


def splash(w, h):
    """Заставка центрируется системой на поле BackgroundColor из манифеста,
    поэтому фон здесь строго однотонный — иначе на стыке видна граница."""
    canvas = Image.new("RGBA", (w, h), SPLASH_BG + (255,))
    glow = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    gx, gy, r = w // 2, h // 2, int(h * 0.44)
    ImageDraw.Draw(glow).ellipse([gx - r, gy - r, gx + r, gy + r], fill=GLOW + (55,))
    canvas = Image.alpha_composite(canvas, glow.filter(ImageFilter.GaussianBlur(h // 10)))
    return _centered(canvas, 0.86)


def _phone_mask(k, grow, hollow):
    """L-маска телефона: силуэт корпуса, при hollow — с вырезанным экраном."""
    lay = Image.new("L", ((PW + 2 * PAD) * k, (PH_ + 2 * PAD) * k), 0)
    d = ImageDraw.Draw(lay)
    d.rounded_rectangle([_s(PAD - grow, k), _s(PAD - grow, k),
                         _s(PAD + PW + grow, k), _s(PAD + PH_ + grow, k)],
                        radius=_s(42 + grow, k), fill=255)
    if hollow:
        d.rounded_rectangle([_s(PAD + 18, k), _s(PAD + 78, k),
                             _s(PAD + PW - 18, k), _s(PAD + PH_ - 62, k)],
                            radius=_s(12, k), fill=0)
    return lay.rotate(TILT, resample=Image.BICUBIC, expand=True)


def badge(size):
    """Монохромный значок экрана блокировки: белый силуэт с прорезями."""
    k = SS
    n = 1024 * k
    mask = Image.new("L", (n, n), 0)
    d = ImageDraw.Draw(mask)

    for p in (FLAP_BL, FLAP_BR, FLAP_FL, FLAP_FR):
        _poly(d, p, k, fill=255)
    _poly(d, [N, E, S, W], k, fill=255)
    _poly(d, [W, S, Sp, Wp], k, fill=255)
    _poly(d, [S, E, Ep, Sp], k, fill=255)

    # рёбра коробки прорезаем, иначе клапаны и стенки сливаются в одно пятно
    lw = _s(9, k)
    for a, b in ((N, W), (N, E), (W, S), (S, E), (S, Sp)):
        d.line([(_s(a[0], k), _s(a[1], k)), (_s(b[0], k), _s(b[1], k))], fill=0, width=lw)

    # телефон: сначала зазор по контуру, затем корпус с вырезанным экраном
    for grow, hollow in ((12, False), (0, True)):
        pm = _phone_mask(k, grow, hollow)
        pos = (int(_s(PH_CX, k) - pm.width / 2), int(_s(PH_CY, k) - pm.height / 2))
        mask.paste(0 if not hollow else pm, pos, _phone_mask(k, grow, False))

    out = Image.new("RGBA", (n, n), WHITE + (0,))
    out.putalpha(mask)
    return out.resize((size, size), Image.LANCZOS)


def px(base, f):
    """Windows округляет масштабированный размер ВВЕРХ: 71 при 150% — это 107, а не 106.
    Упаковщик пакета сверяет размеры точно и на 106 ругается."""
    return int(math.ceil(base * f - 1e-9))


def save(img, name):
    # Непрозрачные картинки кладём палитрой: плавный фон в truecolor раздувает PNG,
    # а на большую плитку и заставку у пакета лимит в 200 КБ.
    if img.mode == "RGBA" and img.getchannel("A").getextrema()[0] == 255:
        img = img.convert("RGB").quantize(colors=256, method=Image.MEDIANCUT,
                                          dither=Image.FLOYDSTEINBERG)
    img.save(os.path.join(OUT, name), "PNG", optimize=True)
    return name


def main():
    os.makedirs(OUT, exist_ok=True)
    written = []
    scales = [(100, 1.0), (125, 1.25), (150, 1.5), (200, 2.0), (400, 4.0)]

    for base, size in [("Square44x44Logo", 44), ("Square71x71Logo", 71),
                       ("Square150x150Logo", 150), ("Square310x310Logo", 310),
                       ("StoreLogo", 50)]:
        for pct, f in scales:
            written.append(save(square(px(size, f)), f"{base}.scale-{pct}.png"))

    for ts in (16, 24, 32, 48, 256):
        written.append(save(square(ts), f"Square44x44Logo.targetsize-{ts}.png"))
        written.append(save(square(ts, with_bg=False),
                            f"Square44x44Logo.targetsize-{ts}_altform-unplated.png"))

    # Иконка для врезки ВНУТРЬ плитки (живая плитка, большой и широкий размеры).
    # Фон прозрачный: своя подложка дала бы внутри плитки заметный чужой квадрат.
    for pct, f in scales:
        written.append(save(square(px(150, f), with_bg=False), f"TileIcon.scale-{pct}.png"))

    for pct, f in scales:
        written.append(save(wide(px(310, f), px(150, f)), f"Wide310x150Logo.scale-{pct}.png"))
        written.append(save(splash(px(620, f), px(300, f)), f"SplashScreen.scale-{pct}.png"))
        written.append(save(badge(px(24, f)), f"LockScreenLogo.scale-{pct}.png"))

    written.append(save(square(50), "StoreLogo.png"))

    print(f"записано файлов: {len(written)}")


if __name__ == "__main__":
    main()
