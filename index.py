import streamlit as st

pg = st.navigation([
        st.Page('webpages/pages/home.py', title='🏠 Home'),
        st.Page('webpages/pages/details.py', title='📈 Details'),
        st.Page('webpages/pages/ipcountry.py', title='🗺️ IP Country'),
    ])
pg.run()