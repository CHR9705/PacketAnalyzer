import streamlit as st

pg = st.navigation([
        st.Page('webpages/pages/home.py', title='🏠 Home'),
        st.Page('webpages/pages/ipcountry.py', title='🗺️ IP Country'),
        st.Page('webpages/pages/warning_list.py', title='⚠️ warnings'),
        st.Page('webpages/pages/settings.py', title='settings'),
        st.Page('webpages/pages/details.py', title='details'),        
    ])
pg.run()