"""Login, first-run setup and the sidebar user panel."""

from __future__ import annotations

import time

import streamlit as st

from tia import auth
from tia.config import APP_VERSION
from tia.storage import Store
from tia.ui import theme
from tia.ui.common import secret_users

MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 30


def _hero(title: str, subtitle: str) -> None:
    st.markdown(
        f"<div class='ti-login-hero'><img src='{theme.logo_data_uri()}' width='68' height='68' alt=''/>"
        f"<h1>{theme.esc(title)}</h1><p>{theme.esc(subtitle)}</p></div>",
        unsafe_allow_html=True,
    )


def _footer() -> None:
    st.markdown(f"<div class='ti-foot'>Threat Intel Aggregator v{APP_VERSION}</div>", unsafe_allow_html=True)


def render_login(store: Store) -> None:
    theme.hide_sidebar()
    _, mid, _ = st.columns([1, 1.15, 1])
    with mid:
        _hero("Sign in to Threat Intel", "Use your workspace account to continue.")
        locked_for = st.session_state.get("lock_until", 0) - time.time()
        with st.form("login_form"):
            user = st.text_input("Username", placeholder="your.username")
            pw = st.text_input("Password", type="password", placeholder="••••••••")
            submitted = st.form_submit_button("Sign in", type="primary", use_container_width=True)
        if submitted:
            if locked_for > 0:
                st.error(f"Too many failed attempts. Try again in {int(locked_for) + 1} seconds.")
            else:
                result = auth.authenticate(store, user, pw, secret_users())
                if result:
                    st.session_state.pop("login_failures", None)
                    st.session_state["user"] = result
                    st.rerun()
                fails = st.session_state.get("login_failures", 0) + 1
                st.session_state["login_failures"] = fails
                if fails >= MAX_ATTEMPTS:
                    st.session_state["lock_until"] = time.time() + LOCKOUT_SECONDS
                    st.session_state["login_failures"] = 0
                    st.error(f"Too many failed attempts. Sign-in is paused for {LOCKOUT_SECONDS} seconds.")
                else:
                    st.error("Invalid username or password.")
        _footer()


def render_first_run(store: Store) -> None:
    theme.hide_sidebar()
    _, mid, _ = st.columns([1, 1.15, 1])
    with mid:
        _hero("Set up your workspace", "Create the administrator account to get started.")
        with st.form("setup_form"):
            user = st.text_input("Admin username", value="admin")
            pw = st.text_input("Password", type="password", help=f"At least {auth.MIN_PASSWORD_LENGTH} characters, letters and numbers.")
            pw2 = st.text_input("Confirm password", type="password")
            submitted = st.form_submit_button("Create account", type="primary", use_container_width=True)
        if submitted:
            problem = auth.validate_username(user) or auth.validate_password(pw)
            if not problem and pw != pw2:
                problem = "Passwords do not match."
            if problem:
                st.error(problem)
            elif store.user_count() > 0:
                st.error("An account already exists. Reload the page and sign in.")
            else:
                store.add_user(user.strip(), auth.hash_password(pw), "admin")
                st.session_state["user"] = {"username": user.strip(), "role": "admin", "source": "local", "insecure": False}
                st.rerun()
        _footer()


def render_sidebar_user() -> None:
    user = st.session_state["user"]
    with st.sidebar:
        st.markdown(
            "<div class='ti-user'>"
            f"<div class='ti-avatar'>{theme.esc(user['username'][:1].upper())}</div>"
            f"<div><div class='who'>{theme.esc(user['username'])}</div><div class='role'>{theme.esc(user['role'])}</div></div>"
            "</div>",
            unsafe_allow_html=True,
        )
        if user.get("insecure"):
            st.warning("This account uses a plain-text password in secrets. Replace it with a `password_hash`.", icon=":material/warning:")
        if st.button("Sign out", icon=":material/logout:", use_container_width=True, key="sign_out"):
            for k in list(st.session_state.keys()):
                del st.session_state[k]
            st.rerun()
