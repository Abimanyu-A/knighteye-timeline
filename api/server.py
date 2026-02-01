from fastapi import FastAPI
from pipelines.investigation import run_investigation, replay_investigation
from evidence.store import init_db

app = FastAPI()
init_db()

@app.get("/investigate")
def investigate():
    result = run_investigation()
    return {
        "run_id": result.run_id,
        "evidence_count": result.evidence_count,
        "incidents": result.incidents,
        "timelines": result.timelines,
        "storylines": result.storylines,
        "narratives": result.narratives,
        "verification": result.verification
    }
    
@app.get("/replay")
def replay():
    return replay_investigation()