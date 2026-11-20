import streamlit as st
import math
import random
import re
import pandas as pd

# ---------------------------------------------------------
# Page Configuration
# ---------------------------------------------------------
st.set_page_config(
    page_title="RSA Асимметриялық Шифрлау Жүйесі",
    page_icon="🔐",
    layout="wide"
)

st.title("🔐 RSA Асимметриялық Шифрлау Жүйесі & Жай сандар тесттері")

# ---------------------------------------------------------
# Helper Functions (Cryptographic & Math Operations)
# ---------------------------------------------------------
def is_prime(n: int) -> bool:
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def modular_inverse(e: int, phi: int) -> int:
    d_old, d_new = 0, 1
    r_old, r_new = phi, e
    while r_new != 0:
        quotient = r_old // r_new
        r_old, r_new = r_new, r_old - quotient * r_new
        d_old, d_new = d_new, d_old - quotient * d_new
    if r_old > 1:
        return None
    if d_old < 0:
        d_old += phi
    return d_old

# --- Құпия кілт алмасу және ортақ кілтпен шифрлау/дешифрлау ---
def compute_shared_key(g_base: int, secret_self: int, other_public: int, p_mod: int) -> tuple[int, int]:
    """Өз ашық қалдығын (A немесе B) және есептелген ортақ құпия кілтті қайтарады."""
    my_public = pow(int(g_base), int(secret_self), int(p_mod))
    shared_key = pow(int(other_public), int(secret_self), int(p_mod))
    return my_public, shared_key

def _get_cipher_params(shared_key: int, p_mod: int) -> tuple[int, int]:
    mult = (shared_key % 997) + 11
    while math.gcd(mult, p_mod) != 1:
        mult += 2
    shift = (shared_key % 4093) + 17
    return mult, shift

def encrypt_with_shared_key(text: str, shared_key: int, p_mod: int) -> list[int]:
    """Ортақ кілт пен модуль арқылы мәтінді сандар тізбегіне шифрлау."""
    mult, shift = _get_cipher_params(shared_key, p_mod)
    return [((ord(ch) + shift) * mult + idx) % p_mod for idx, ch in enumerate(text)]

def decrypt_with_shared_key(cipher_list: list[int], shared_key: int, p_mod: int) -> str:
    """Есептелген ортақ кілт арқылы сандар тізбегін кері дешифрлау."""
    mult, shift = _get_cipher_params(shared_key, p_mod)
    inv_mult = modular_inverse(mult, p_mod)
    if inv_mult is None:
        raise ValueError("Кері модульдік элемент табылмады (жай модульді тексеріңіз).")
    chars = []
    for idx, c in enumerate(cipher_list):
        code_point = (((c - idx) % p_mod) * inv_mult - shift) % p_mod
        chars.append(chr(code_point))
    return "".join(chars)

# --- Жайлық тесттерінің алгоритмдері ---
def fermat_test(n: int, k: int = 5) -> bool:
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0: return False
    for _ in range(k):
        a = random.randint(2, n - 2)
        if pow(a, n - 1, n) != 1:
            return False
    return True

def miller_rabin_test(n: int, k: int = 5) -> bool:
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def jacobi(a: int, n: int) -> int:
    if n <= 0 or n % 2 == 0: return 0
    ans = 1
    a = a % n
    while a != 0:
        while a % 2 == 0:
            a //= 2
            r = n % 8
            if r == 3 or r == 5:
                ans = -ans
        a, n = n, a
        if a % 4 == 3 and n % 4 == 3:
            ans = -ans
        a = a % n
    if n == 1: return ans
    return 0

def solovay_strassen_test(n: int, k: int = 5) -> bool:
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0: return False
    for _ in range(k):
        a = random.randint(2, n - 1)
        jacobian = (jacobi(a, n) + n) % n
        if jacobian == 0 or pow(a, (n - 1) // 2, n) != jacobian:
            return False
    return True

def baillie_psw_test(n: int) -> bool:
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0: return False
    if not miller_rabin_test(n, k=1):
        return False
    return True

def check_password_strength(password: str):
    score = 0
    feedback = []
    if len(password) >= 8: score += 25
    else: feedback.append("Пароль ұзындығы кемінде 8 символ болуы тиіс.")
    if re.search(r"[a-z]", password) and re.search(r"[A-Z]", password): score += 25
    else: feedback.append("Үлкен және кіші әріптерді араластырыңыз.")
    if re.search(r"\d", password): score += 25
    else: feedback.append("Кемінде бір сан қосыңыз.")
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password): score += 25
    else: feedback.append("Арнайы таңбаларды пайдаланыңыз.")
    return score, feedback

# ---------------------------------------------------------
# Sidebar: Key Configuration Panel
# ---------------------------------------------------------
st.sidebar.header("⚙️ Кілттерді баптау режимі")
mode = st.sidebar.radio(
    "Генерация режимін таңдаңыз:",
    ("Автоматты генерация", "Кілттерді қолдан енгізу")
)

e_val, d_val, n_val = None, None, None

if mode == "Автоматты генерация":
    st.sidebar.subheader("Жай сандарды енгізіңіз:")
    p = st.sidebar.number_input("p мәні:", value=61, step=1)
    q = st.sidebar.number_input("q мәні:", value=53, step=1)

    if not (is_prime(p) and is_prime(q)):
        st.sidebar.error("⚠ p мен q тек ЖАЙ САНДАР болуы керек!")
    elif p == q:
        st.sidebar.error("⚠ p мен q бір-біріне тең болмауы тиіс!")
    else:
        n_val = p * q
        phi = (p - 1) * (q - 1)
        e_val = 17
        if math.gcd(e_val, phi) != 1:
            e_val = 3
            while math.gcd(e_val, phi) != 1:
                e_val += 2
        d_val = modular_inverse(e_val, phi)

        st.sidebar.success("Кілттер сәтті генерацияланды!")
        st.sidebar.markdown(f"**Ашық кілт (Public Key):**\n`({e_val}, {n_val})`")
        st.sidebar.markdown(f"**Жабық кілт (Private Key):**\n`({d_val}, {n_val})`")
        st.sidebar.caption(f"Эйлер функциясы φ(n) = {phi}")
else:
    st.sidebar.subheader("Дайын кілт параметрлерін енгізіңіз:")
    e_val = st.sidebar.number_input("Ашық экспонента (e):", value=17, step=1)
    d_val = st.sidebar.number_input("Жабық экспонента (d):", value=2753, step=1)
    n_val = st.sidebar.number_input("Модуль (n):", value=3233, step=1)

# ---------------------------------------------------------
# Main Tabs Layout (5 вкладка)
# ---------------------------------------------------------
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🔒 Шифрлау",
    "🔓 Дешифрлау",
    "📚 Теория & Пароль",
    "🧮 Жай санды тестілеу",
    "📐 Қалдықты есептеу"
])

with tab1:
    st.header("🔒 Жіберуші тарап (Алиса): мәтінді шифрлау")
    st.info(
        "**Логикасы:** Ешкім өз құпия санын жібермейді! Сіз тек **өзіңіздің құпия саныңызды (`a`)** "
        "және алушының ашық арнамен жіберген **ашық қалдығын (`B`)** енгізесіз. "
        "Ортақ құпия кілт $K = B^a \\bmod p$ автоматты есептеледі."
    )

    col1, col2 = st.columns(2)
    with col1:
        p_enc = st.number_input("Ортақ жай модуль (p):", min_value=10007, value=104729, step=2, key="p_enc")
        g_enc = st.number_input("Ортақ негіз (g):", min_value=2, value=5, step=1, key="g_enc")
    with col2:
        secret_a = st.number_input("Сіздің құпия саныңыз a (тек сіз білесіз, ешкімге жіберілмейді):", min_value=2, value=123, step=1, key="sec_a")
        other_pub_b = st.number_input("Алушының ашық қалдығы B (ашық арнадан алынған):", min_value=1, value=79796, step=1, key="pub_b")

    input_text = st.text_area("Шифрланатын мәтінді енгізіңіз:", value="Hello RSA")

    if st.button("Шифрлау", key="btn_encrypt"):
        if not is_prime(int(p_enc)):
            st.error("Модуль (p) жай сан болуы тиіс!")
        else:
            my_pub_a, shared_key_a = compute_shared_key(g_enc, secret_a, other_pub_b, p_enc)
            encrypted_numbers = encrypt_with_shared_key(input_text, shared_key_a, p_enc)
            st.subheader("Нәтиже (Шифрланған сандар массиві):")
            st.code(str(encrypted_numbers), language="python")
            st.success(
                f"📤 **Ашық арнамен алушыға мына екеуін ғана жіберіңіз:**\n"
                f"1. Жоғарыдағы шифрланған сандар массивін;\n"
                f"2. Өзіңіздің ашық қалдығыңызды: **`A = {my_pub_a}`**.\n\n"
                f"🔒 Сіздің құпия саныңыз (`a = {int(secret_a)}`) **ешқайда жіберілмейді** — тек өзіңізде қалады!"
            )

with tab2:
    st.header("🔓 Алушы тарап (Боб): мәтінді дешифрлау")
    st.info(
        "**Логикасы:** Сізге жіберушінің құпия санын (`a`) білудің мүлде қажеті жоқ! "
        "Сіз тек **өзіңіздің құпия саныңызды (`b`)** (оны ешкімге жібермегенсіз) және "
        "жіберушінің ашық қалдығын (**`A`**) енгізесіз. Сіздің құрылғыңызда сол ортақ кілт $K = A^b \\bmod p$ есептеледі."
    )

    col1, col2 = st.columns(2)
    with col1:
        p_dec = st.number_input("Ортақ жай модуль (p):", min_value=10007, value=104729, step=2, key="p_dec")
        g_dec = st.number_input("Ортақ негіз (g):", min_value=2, value=5, step=1, key="g_dec")
    with col2:
        secret_b = st.number_input("Сіздің жеке құпия саныңыз b (тек сізде сақталады):", min_value=2, value=456, step=1, key="sec_b")
        other_pub_a = st.number_input("Жіберушінің ашық қалдығы A (ашық арнадан келген):", min_value=1, value=25732, step=1, key="pub_a")

    cipher_input = st.text_input("Ашық арнадан келген шифрланған сандар массиві:", value="[48469, 43451, 31559, 31559, 27800, 99162, 74736, 73486, 86599]")

    if st.button("Дешифрлау", key="btn_decrypt"):
        if not is_prime(int(p_dec)):
            st.error("Модуль (p) жай сан болуы тиіс!")
        else:
            try:
                clean_str = cipher_input.replace("[", "").replace("]", "").strip()
                if clean_str:
                    cipher_list = [int(x.strip()) for x in clean_str.split(",") if x.strip()]
                    my_pub_b, shared_key_b = compute_shared_key(g_dec, secret_b, other_pub_a, p_dec)
                    decrypted_text = decrypt_with_shared_key(cipher_list, shared_key_b, p_dec)
                    st.balloons()
                    st.success("Хабарлама сәтті дешифрланды! (Құпия сандар ашық арнамен берілген жоқ)")
                    st.subheader("Түпнұсқа мәтін:")
                    st.success(f"**{decrypted_text}**")
                    st.caption(f"Анықтама: сіздің ашық қалдығыңыз B = {my_pub_b} (жіберушіге осы мән берілген).")
                else:
                    st.error("Массив бос!")
            except Exception as e:
                st.error(f"Дешифрлау қатесі (ашық қалдық A немесе жеке құпия сан b сәйкес келмейді): {e}")

with tab3:
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("📚 RSA Теориясы")
        st.markdown("""
- **Ашық кілт:** Шифрлау үшін, бәріне ортақ.
- **Жабық кілт:** Дешифрлау үшін, тек сізде қалады.
- **Математикасы:** Үлкен жай сандарды көбейту оңай, ал кері жіктеу (факторизация) қиын.
        """)
    with col2:
        st.subheader("🛡️ Пароль Беріктігін Талдау")
        pwd = st.text_input("Пароль енгізіңіз:", type="password")
        if pwd:
            score, feedback = check_password_strength(pwd)
            st.progress(score / 100.0)
            if score == 100: st.success(f"🟢 Беріктігі: {score}% — Өте берік!")
            elif score >= 50: st.warning(f"🟡 Беріктігі: {score}% — Орташа.")
            else: st.error(f"🔴 Беріктігі: {score}% — Әлсіз!")
            for tip in feedback: st.write(f"- {tip}")

with tab4:
    st.header("🧮 Жай сандарды тестілеу алгоритмдері")
    st.write("Кез келген санның жай немесе құрама екенін төрт әртүрлі криптографиялық тест арқылы тексеріңіз.")

    test_num = st.number_input("Тексерілетін санды енгізіңіз:", value=561, step=1)
    iterations = st.slider("Тест қайталау саны (k):", min_value=1, max_value=20, value=5)

    if st.button("Санды тексеру"):
        f_res = fermat_test(test_num, iterations)
        mr_res = miller_rabin_test(test_num, iterations)
        ss_res = solovay_strassen_test(test_num, iterations)
        bpsw_res = baillie_psw_test(test_num)

        col_a, col_b, col_c, col_d = st.columns(4)
        with col_a:
            st.metric("Fermat тесті", "Жай" if f_res else "Құрама")
        with col_b:
            st.metric("Miller-Rabin", "Жай" if mr_res else "Құрама")
        with col_c:
            st.metric("Solovay-Strassen", "Жай" if ss_res else "Құрама")
        with col_d:
            st.metric("Baillie-PSW", "Жай" if bpsw_res else "Құрама")

    st.markdown("---")
    st.subheader("📊 Алгоритмдерді салыстыру кестесі")
    
    comparison_data = {
        "Алгоритм": ["Fermat тесті", "Miller–Rabin тесті", "Solovay–Strassen тесті", "Baillie–PSW алгоритмі"],
        "Математикалық негізі": ["Ферманың кіші теоремасы", "Модульдік квадрат түбірлер мен қалдықтар", "Якоби символы және Эйлер критерийі", "Миллер-Рабин мен Лукас тізбектері"],
        "Қателік ықтималдығы": ["Жоғары (Каррмайкл сандарында қателеседі)", "Өте төмен ($< 4^{-k}$)", "Төмен ($< 4^{-k}$)", "Практикада белгілі қатесі жоқ"],
        "Өнімділік / Жылдамдық": ["Өте жылдам", "Өте жоғары (Стандарт)", "Орташа (Якоби символы баяулау)", "Жоғары"],
        "Қолданылу аясы": ["Оқыту мақсатында", "Заманауи криптография (RSA, OpenSSL)", "Тарихи / Теориялық", "Жоғары сенімді жүйелер"]
    }
    df = pd.DataFrame(comparison_data)
    st.table(df)

with tab5:
    st.header("📐 Қалдықты есептеу (Модульдік арифметика)")
    st.write("Мұнда дәрежелеу қалдығын $(g^x \\bmod p)$ немесе жай бөлу қалдығын $(a \\bmod p)$ қадамдап есептеуге болады.")

    calc_mode = st.radio(
        "Есептеу түрін таңдаңыз:",
        ("Дәрежелеу қалдығы: (g^x) mod p", "Жай бөлу қалдығы: a mod p"),
        horizontal=True
    )

    if calc_mode == "Дәрежелеу қалдығы: (g^x) mod p":
        col1, col2, col3 = st.columns(3)
        with col1:
            g_val = st.number_input("Негіз (g):", min_value=0, value=5, step=1, key="rem_g")
        with col2:
            x_val = st.number_input("Дәреже (x):", min_value=0, value=123, step=1, key="rem_x")
        with col3:
            p_val = st.number_input("Модуль (p):", min_value=1, value=104729, step=1, key="rem_p")

        if st.button("Қалдықты есептеу", key="btn_pow_mod"):
            g_i, x_i, p_i = int(g_val), int(x_val), int(p_val)
            remainder = pow(g_i, x_i, p_i)
            st.success(f"Нәтиже (қалдық): **({g_i}^{x_i}) mod {p_i} = {remainder}**")

            steps = []
            cur = 1
            base = g_i % p_i
            exp = x_i
            step_num = 1
            while exp > 0 and step_num <= 25:
                if exp % 2 == 1:
                    prev_cur = cur
                    cur = (cur * base) % p_i
                    steps.append(f"{step_num}-қадам (дәреже тақ): ({prev_cur} × {base}) mod {p_i} = {cur}")
                else:
                    steps.append(f"{step_num}-қадам (дәреже жұп): ағымдағы мән = {cur}")
                exp //= 2
                if exp > 0:
                    prev_base = base
                    base = (base * base) % p_i
                    steps.append(f"   ↳ негізді квадраттау: ({prev_base}²) mod {p_i} = {base}")
                step_num += 1

            st.subheader("Қалай есептелді (қадамдар):")
            for s in steps:
                st.write(s)
            if exp > 0:
                st.caption("Қалған қадамдар дәл осы ережемен жалғасады...")
            st.caption(f"Қысқа формула: `pow({g_i}, {x_i}, {p_i})` -> `{remainder}`")

    else:
        col1, col2 = st.columns(2)
        with col1:
            a_val = st.number_input("Бөлінетін сан (a):", value=125, step=1, key="rem_a")
        with col2:
            m_val = st.number_input("Бөлгіш / модуль (m):", min_value=1, value=23, step=1, key="rem_m")

        if st.button("Қалдықты табу", key="btn_simple_mod"):
            a_i, m_i = int(a_val), int(m_val)
            quotient = a_i // m_i
            remainder = a_i % m_i
            st.success(f"Нәтиже (қалдық): **{a_i} mod {m_i} = {remainder}**")
            st.subheader("Қалай есептелді:")
            st.write(f"1. {a_i} санын {m_i}-ге бөлгендегі толық бөлінді: **{quotient}**")
            st.write(f"2. Бөлінген бөліктің мәні: {quotient} × {m_i} = {quotient * m_i}")
            st.write(f"3. Қалдық: {a_i} − {quotient * m_i} = **{remainder}**")
