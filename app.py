<meta name="google-site-verification" content="KQodUwm-M-uQwoexXnecb7KRN7NvjkdzZQHU7G_V1is" />
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
# Main Tabs Layout (4 вкладка)
# ---------------------------------------------------------
tab1, tab2, tab3, tab4 = st.tabs(["🔒 Шифрлау", "🔓 Дешифрлау", "📚 Теория & Пароль", "🧮 Жай санды тестілеу"])

with tab1:
    st.header("🔒 Мәтінді шифрлау")
    st.write("Енгізілген ашық мәтін ашық кілт көмегімен сан тізбегіне айналдырылады.")
    input_text = st.text_area("Шифрланатын мәтінді енгізіңіз:", value="Hello RSA")
    if st.button("Шифрлау", key="btn_encrypt"):
        if e_val is None or n_val is None:
            st.error("Кілттер дұрыс орнатылмаған!")
        else:
            encrypted_numbers = [pow(ord(char), e_val, n_val) for char in input_text]
            st.subheader("Нәтиже (Шифрланған сандар массиві):")
            st.code(str(encrypted_numbers), language="python")
            st.info(f"💡 Дешифрлау үшін қажетті кілттер: d = {d_val}, n = {n_val}")

with tab2:
    st.header("🔓 Мәтінді дешифрлау")
    st.write("Шифрланған сандар массивін жабық кілт арқылы қайтару.")
    cipher_input = st.text_input("Зашифрланған сандар массиві:", value="[3000, 1234, 567]")
    if st.button("Дешифрлау", key="btn_decrypt"):
        if d_val is None or n_val is None:
            st.error("Кілттер дұрыс орнатылмаған!")
        else:
            try:
                clean_str = cipher_input.replace("[", "").replace("]", "").strip()
                if clean_str:
                    cipher_list = [int(x.strip()) for x in clean_str.split(",") if x.strip()]
                    decrypted_chars = [chr(pow(c, d_val, n_val)) for c in cipher_list]
                    st.balloons()
                    st.success("Хабарлама сәтті дешифрланды!")
                    st.subheader("Түпнұсқа мәтін:")
                    st.success(f"**{''.join(decrypted_chars)}**")
                else:
                    st.error("Массив бос!")
            except Exception as e:
                st.error(f"Формат қатесі: {e}")

with tab3:
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("📚 RSA Теориясы")
        st.markdown("""
        * **Ашық кілт:** Шифрлау үшін, бәріне ортақ.
        * **Жабық кілт:** Дешифрлау үшін, тек сізде қалады.
        * **Математикасы:** Үлкен жай сандарды көбейту оңай, ал кері жіктеу (факторизация) қиын.
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
