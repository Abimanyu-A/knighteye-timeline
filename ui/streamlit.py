import streamlit as st
import requests
import os
from dotenv import load_dotenv
load_dotenv()

API_BASE = os.getenv("BASE_URL")

st.set_page_config(
    page_title="KnightEye Investigation Console",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
html, body, [class*="css"]  {
    font-family: "Inter", "Segoe UI", sans-serif;
}

section[data-testid="stSidebar"] {
    background-color: #0f1116;
}

.block-container {
    padding-top: 2rem;
}

.case-box {
    border: 1px solid #2a2f3a;
    border-radius: 10px;
    padding: 16px;
    margin-bottom: 14px;
    background-color: #0f1116;
}

.meta {
    color: #9aa4b2;
    font-size: 0.85rem;
}

.stage {
    font-weight: 700;
    color: #c7d1db;
}

.action {
    font-size: 1.05rem;
}

.sig-high {
    border-left: 4px solid #c0392b;
}

.sig-med {
    border-left: 4px solid #f39c12;
}

.sig-low {
    border-left: 4px solid #3498db;
}
</style>
""", unsafe_allow_html=True)

# Header
st.title("KnightEye Investigation Console")
st.caption("Digital crime-scene reconstruction & attack storyline engine")

# Fetch incidents
@st.cache_data(ttl=10)
def fetch_timeline():
    return requests.get(f"{API_BASE}/timeline").json()

data = fetch_timeline()

# Sidebar
st.sidebar.title("Case Console")

if st.sidebar.button("Collect Latest Telemetry"):
    with st.spinner("Collecting events from Wazuh..."):
        try:
            r = requests.get(f"{API_BASE}/collect/wazuh", timeout=120)
            result = r.json()
            st.sidebar.success(f"Ingestion complete — {result.get('stored', 0)} new events")
            st.cache_data.clear()
        except Exception as e:
            st.sidebar.error("Collection failed")
            st.sidebar.code(str(e))

st.sidebar.divider()

if not data:
    st.warning("No incidents available. Ingest telemetry first.")
    st.stop()

incident_ids = [i["incident_id"] for i in data]
selected_id = st.sidebar.selectbox("Active Incident", incident_ids)

incident = next(i for i in data if i["incident_id"] == selected_id)

# Incident overview
st.subheader("Incident Overview")

c1, c2, c3, c4 = st.columns(4)

c1.metric("Case ID", incident["incident_id"][:8] + "…")
c2.metric("Start Time", incident["start_time"])
c3.metric("End Time", incident["end_time"])
c4.metric("Systems Impacted", len(incident["systems"]))

st.markdown("**Systems involved:** " + ", ".join(incident["systems"]))

st.divider()

# Storylines
st.subheader("Identified Attack Storylines")

if not incident.get("storylines"):
    st.info("No strong multi-event attack chains were established for this incident.")
else:
    for s in incident["storylines"]:
        with st.expander(
            f"Storyline {s['storyline_id'][:6]} — {len(s['steps'])} linked actions — confidence: {s['confidence']}"
        ):
            st.markdown("**Systems involved:** " + ", ".join(s["systems"]))

            st.markdown("**Correlation basis:**")
            for r in s["reasoning"]:
                st.markdown(f"- {r}")

            st.markdown("**Reconstructed attack chain:**")
            for step in s["steps"]:
                st.markdown(
                    f"- **{step['stage']}** on `{step['system']}` → {step['action']} "
                    f"({step['count']} events)"
                )

st.divider()

# Threat phase overview
st.subheader("Threat Activity Breakdown")

phase_map = {}

for ev in incident["timeline"]:
    phase = ev["stage"]
    if phase not in phase_map:
        phase_map[phase] = {"count": 0, "systems": set()}
    phase_map[phase]["count"] += ev["count"]
    phase_map[phase]["systems"].add(ev["system"])

if not phase_map:
    st.info("No high-confidence threat phases were identified for this incident.")
else:
    cols = st.columns(len(phase_map))
    for idx, (phase, info) in enumerate(phase_map.items()):
        with cols[idx]:
            st.markdown(f"**{phase}**")
            st.markdown(
                f"<div class='meta'>Events: {info['count']}</div>",
                unsafe_allow_html=True
            )
            for s in info["systems"]:
                st.code(s)

st.divider()

# Forensic timeline
st.subheader("Forensic Timeline (High-Value Evidence Only)")

for ev in incident["timeline"]:
    sig_class = (
        "sig-high" if ev["significance"] >= 8 else
        "sig-med" if ev["significance"] >= 5 else
        "sig-low"
    )

    st.markdown(f"""
    <div class="case-box {sig_class}">
        <div class="stage">{ev['stage']}</div>
        <div class="meta">{ev['start_time']} → {ev['end_time']}</div>
        <div class="action">{ev['action']}</div>
        <div class="meta">
            System: {ev['system']} |
            Actor: {ev['actor']} |
            Target: {ev['target']} |
            Significance: {ev['significance']}
        </div>
        <div class="meta">Repetitions observed: {ev['count']}</div>
    </div>
    """, unsafe_allow_html=True)

st.divider()

# Investigation narrative
st.subheader("Investigator Narrative")
st.markdown(f"<div class='case-box'>{incident['narrative']}</div>", unsafe_allow_html=True)

st.divider()

# Evidence verification
st.subheader("Evidence Integrity")

if st.button("Verify Evidence Chain"):
    with st.spinner("Verifying forensic evidence..."):
        r = requests.get(f"{API_BASE}/evidence/verify/{incident['incident_id']}")
        result = r.json()["verification"]

    if result["valid"]:
        st.success("Evidence chain verified. No tampering detected.")
        st.json(result)
    else:
        st.error("Evidence integrity violation detected.")
        st.json(result)

st.caption("KnightEye · Investigation Console · Digital Evidence Correlation Engine")
