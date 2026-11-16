import pandas as pd
import streamlit as st

from tia import auth, sources
from tia.config import APP_VERSION, db_path
from tia.ui import theme
from tia.ui.common import KEY_FIELDS, current_user, get_store, is_admin, resolve_keys, username

store = get_store()
me = current_user()
theme.page_header("Account", "Settings", "API keys, users and your account.")

tab_names = ["API keys", "My account", "About"]
if is_admin():
    tab_names.insert(1, "Users")
tabs = dict(zip(tab_names, st.tabs(tab_names)))

# -- API keys -------------------------------------------------------------
with tabs["API keys"]:
    resolved = resolve_keys(store)
    if not is_admin():
        st.info("Only administrators can change API keys.", icon="🔒")
    with st.form("api_keys"):
        new_values = {}
        for key, (label, secret_name, env) in KEY_FIELDS.items():
            value, origin = resolved[key]
            managed = origin in ("secrets", "environment")
            help_text = (f"Set in Streamlit secrets as [apikeys] {secret_name}" if origin == "secrets"
                         else f"Set by the {env} environment variable" if origin == "environment"
                         else f"Stored in the app database. Can also be set via secrets ({secret_name}) or {env}.")
            new_values[key] = st.text_input(
                f"{label} API key", value="" if managed else value, type="password",
                disabled=managed or not is_admin(), help=help_text,
                placeholder=f"Managed by {origin}" if managed else "Paste key",
            )
            st.caption(f"Source: **{origin}**")
        saved = st.form_submit_button("Save keys", type="primary", disabled=not is_admin())
    if saved and is_admin():
        for key, value in new_values.items():
            if resolved[key][1] not in ("secrets", "environment"):
                store.set_setting(f"apikey.{key}", value.strip())
        st.toast("API keys saved", icon="✅")
        st.rerun()

    if st.button("Test connections", icon=":material/network_check:"):
        keys = {k: v for k, (v, _) in resolve_keys(store).items()}
        with st.spinner("Testing with 8.8.8.8…"):
            checks = {
                "VirusTotal": sources.query_virustotal("8.8.8.8", keys["vt"]),
                "AbuseIPDB": sources.query_abuseipdb("8.8.8.8", keys["abuseipdb"]),
                "Shodan": sources.query_shodan("8.8.8.8", keys["shodan"]),
            }
        for name, res in checks.items():
            if res.get("ok"):
                st.success(f"{name}: connected", icon="✅")
            elif res.get("skipped"):
                st.info(f"{name}: no key configured", icon="➖")
            else:
                st.error(f"{name}: {res.get('error')}", icon="❌")

# -- Users (admin) --------------------------------------------------------
if "Users" in tabs:
    with tabs["Users"]:
        users = store.list_users()
        if users:
            st.dataframe(pd.DataFrame(users).rename(columns={"username": "Username", "role": "Role", "created_at": "Created"}),
                         hide_index=True, use_container_width=True)
        left, right = st.columns(2)
        with left, st.form("add_user", clear_on_submit=True):
            st.markdown("**Add user**")
            nu = st.text_input("Username")
            nr = st.selectbox("Role", auth.ROLES, index=1)
            npw = st.text_input("Temporary password", type="password")
            if st.form_submit_button("Add user", type="primary"):
                problem = auth.validate_username(nu) or auth.validate_password(npw)
                if problem:
                    st.error(problem)
                else:
                    try:
                        store.add_user(nu.strip(), auth.hash_password(npw), nr)
                        st.toast(f"Added {nu}", icon="✅")
                        st.rerun()
                    except ValueError as exc:
                        st.error(str(exc))
        with right, st.container(border=True):
            st.markdown("**Manage user**")
            others = [u["username"] for u in users if u["username"].lower() != username().lower()]
            if not others:
                st.caption("No other users yet.")
            else:
                target = st.selectbox("User", others)
                role = next(u["role"] for u in users if u["username"] == target)
                new_role = st.selectbox("Role", auth.ROLES, index=auth.ROLES.index(role), key="manage_role")
                reset_pw = st.text_input("New password (optional)", type="password", key="manage_pw")
                b1, b2 = st.columns(2)
                if b1.button("Save changes", use_container_width=True):
                    problem = auth.validate_password(reset_pw) if reset_pw else None
                    if problem:
                        st.error(problem)
                    else:
                        store.set_role(target, new_role)
                        if reset_pw:
                            store.set_password_hash(target, auth.hash_password(reset_pw))
                        st.toast(f"Updated {target}", icon="✅")
                        st.rerun()
                if b2.button("Delete user", use_container_width=True, icon=":material/person_remove:"):
                    store.delete_user(target)
                    st.toast(f"Deleted {target}", icon="🗑️")
                    st.rerun()

# -- My account -----------------------------------------------------------
with tabs["My account"]:
    if me.get("source") != "local":
        st.info("Your account is defined in Streamlit secrets. Change its password there "
                "(generate a hash with `python -m tia.auth`).", icon="🔐")
    else:
        with st.form("change_password", clear_on_submit=True):
            st.markdown("**Change password**")
            cur = st.text_input("Current password", type="password")
            new = st.text_input("New password", type="password")
            new2 = st.text_input("Confirm new password", type="password")
            if st.form_submit_button("Update password", type="primary"):
                user = store.get_user(username())
                problem = None
                if not user or not auth.verify_password(cur, user["password_hash"]):
                    problem = "Current password is incorrect."
                elif new != new2:
                    problem = "New passwords do not match."
                else:
                    problem = auth.validate_password(new)
                if problem:
                    st.error(problem)
                else:
                    store.set_password_hash(username(), auth.hash_password(new))
                    st.success("Password updated.")

# -- About ----------------------------------------------------------------
with tabs["About"]:
    st.markdown(
        theme.card(
            "Threat Intel Aggregator",
            f"<div class='ti-sub' style='margin-bottom:10px'>Unified IOC lookups, risk scoring and reporting for security teams.</div>"
            + theme.stat("Version", APP_VERSION)
            + theme.stat("Data file", str(db_path()))
            + theme.stat("Sources", "VirusTotal v3 · AbuseIPDB v2 · Shodan")
            + theme.stat("Risk rule", "Most severe of VirusTotal and AbuseIPDB levels"),
        ),
        unsafe_allow_html=True,
    )
