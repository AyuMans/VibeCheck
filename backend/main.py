from fastapi import FastAPI

from backend.models import CodeReviewRequest, CodeReviewResponse
from backend.analysis_service import analyze_code


app = FastAPI(
    title="Private AI DevSecOps Platform",
    description="Local AI-powered code review platform",
    version="0.1.0"
)


@app.get("/")
def home():
    return {
        "message": "Private AI DevSecOps Platform backend is running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }

@app.post("/review-code", response_model=CodeReviewResponse)
def review_code_endpoint(request: CodeReviewRequest):
    analysis = analyze_code(
        code=request.code,
        language=request.language
    )

    return {
        "language": request.language,
        "summary": analysis["summary"],
        "findings": analysis["findings"],
        "policy": analysis["policy"]
    }