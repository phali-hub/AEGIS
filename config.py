import os
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

GROQ_MODEL = "llama-3.3-70b-versatile"
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
