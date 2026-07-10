import streamlit as st

pg = st.navigation([
        st.Page('pages/home.py', title='🏠 Home'),
        st.Page('pages/details.py', title='📈 Details'),
        st.Page('pages/ipcountry.py', title='🗺️ IP Country'),
    ])
pg.run()