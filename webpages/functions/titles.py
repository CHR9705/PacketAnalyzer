import streamlit as st

def get_h2(txt):
    return f"""
        <h2 style="
            font-size:20px;
            margin:0;
        ">
        {txt}
        </h2>
        """