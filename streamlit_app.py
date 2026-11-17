"""Threat Intel Aggregator - Streamlit entry point.

Run with:  streamlit run streamlit_app.py
"""

import streamlit as st

from tia.config import APP_NAME, ASSETS_DIR
from tia.ui import theme
from tia.ui.auth_views import render_first_run, render_login, render_sidebar_user
from tia.ui.common import current_user, get_store, secret_users

st.set_page_config(
    page_title=APP_NAME,
    page_icon=str(ASSETS_DIR / "logo.svg"),
    layout="wide",
    initial_sidebar_state="expanded",
)
theme.inject_css()
store = get_store()

if current_user() is None:
    if store.user_count() == 0 and not secret_users():
        render_first_run(store)
    else:
        render_login(store)
    st.stop()

st.logo(str(ASSETS_DIR / "logo_wide.svg"), icon_image=str(ASSETS_DIR / "logo.svg"), size="large")

pages = {
    "Overview": [
        st.Page("views/dashboard.py", title="Dashboard", icon=":material/space_dashboard:", default=True),
        st.Page("views/analytics.py", title="Analytics", icon=":material/insights:"),
    ],
    "Investigate": [
        st.Page("views/scan.py", title="Scan", icon=":material/radar:"),
        st.Page("views/investigations.py", title="Investigations", icon=":material/manage_search:"),
        st.Page("views/graph.py", title="Infrastructure graph", icon=":material/hub:"),
        st.Page("views/verdicts.py", title="Verdicts", icon=":material/gavel:"),
    ],
    "Output": [
        st.Page("views/reports.py", title="Reports", icon=":material/picture_as_pdf:"),
    ],
    "Account": [
        st.Page("views/settings.py", title="Settings", icon=":material/settings:"),
    ],
}

navigation = st.navigation(pages)
render_sidebar_user()
navigation.run()
