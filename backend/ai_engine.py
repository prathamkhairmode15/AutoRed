import httpx
import json
import logging
import asyncio
import os

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
DEFAULT_MODEL = "llama3:8b"

async def fetch_cve_description(cve_id: str, client: httpx.AsyncClient) -> str:
    """Fetch official CVE description from MITRE API."""
    try:
        url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        res = await client.get(url, timeout=5.0)
        if res.status_code == 200:
            data = res.json()
            return data["containers"]["cna"]["descriptions"][0]["value"]
    except Exception as e:
        logging.warning(f"Could not fetch description for {cve_id}: {e}")
    return "Description not available."

async def generate_cve_explanation(cve_ids: list[str], model: str = DEFAULT_MODEL) -> str:
    """
    Sends a list of CVE IDs to a local Ollama instance to generate an explanation.
    """
    if not cve_ids:
        return "No CVEs provided."

    # Limit to top 5 CVEs to prevent overwhelming the local model and timing out
    if len(cve_ids) > 5:
        cve_ids = cve_ids[:5]
        notice = "\n\n*(Note: Showing explanations for the first 5 CVEs only to preserve system resources.)*"
    else:
        notice = ""

    # FETCH CVE DESCRIPTIONS CONCURRENTLY
    async with httpx.AsyncClient(timeout=120.0) as client:
        fetch_tasks = [fetch_cve_description(cve, client) for cve in cve_ids]
        descriptions = await asyncio.gather(*fetch_tasks)
        
    cve_contexts = []
    for cve, desc in zip(cve_ids, descriptions):
        cve_contexts.append(f"- {cve}: {desc}")
    context_str = "\n".join(cve_contexts)

    prompt = (
        f"You are a strict and factual cybersecurity expert. Your task is to explain the following Common Vulnerabilities and Exposures (CVEs).\n\n"
        f"OFFICIAL DESCRIPTIONS (RAG Context):\n{context_str}\n\n"
        f"RULES:\n"
        f"1. Rely ONLY on the official descriptions provided above. Do NOT invent or guess any information.\n"
        f"2. Do NOT invent release dates or version numbers that are not in the provided text.\n"
        f"3. For each CVE, briefly describe the factual mechanism, the potential impact, and standard remediation.\n"
        f"Keep the explanation professional, highly accurate, and concise."
    )

    GROQ_API_KEY = os.getenv("GROQ_API_KEY")
    if not GROQ_API_KEY:
        return "Error: GROQ_API_KEY is not set."

    payload = {
        "model": "llama-3.1-8b-instant",
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.0,
        "stream": False
    }

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post("https://api.groq.com/openai/v1/chat/completions", json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"] + notice
    except httpx.RequestError as exc:
        logging.error(f"An error occurred while requesting {exc.request.url!r}.")
        return f"Error communicating with AI API: {repr(exc)}"
    except httpx.HTTPStatusError as exc:
        logging.error(f"Error response {exc.response.status_code} while requesting {exc.request.url!r}.")
        return f"AI API returned an error: {exc.response.status_code}"
    except Exception as e:
        logging.error(f"Unexpected error in AI engine: {e}")
        return f"Unexpected error: {str(e)}"

async def stream_chat_response(prompt: str, model: str = DEFAULT_MODEL):
    """
    Streams a general chat response from the local Ollama instance.
    Yields text chunks as they arrive.
    """
    system_prompt = "You are AutoRed APT, a highly intelligent and helpful cybersecurity AI assistant. You answer questions directly and concisely."
    
    GROQ_API_KEY = os.getenv("GROQ_API_KEY")
    if not GROQ_API_KEY:
        yield "\n[Error: GROQ_API_KEY is not set. Please add it to your environment variables.]"
        return
        
    payload = {
        "model": "llama-3.1-8b-instant",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.4,
        "stream": True
    }

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            async with client.stream("POST", "https://api.groq.com/openai/v1/chat/completions", json=payload, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data_str = line[6:]
                        if data_str.strip() == "[DONE]":
                            break
                        try:
                            data = json.loads(data_str)
                            if "choices" in data and len(data["choices"]) > 0:
                                delta = data["choices"][0].get("delta", {})
                                if "content" in delta:
                                    yield delta["content"]
                        except json.JSONDecodeError:
                            pass
    except Exception as e:
        logging.error(f"Chat stream error: {e}")
        yield f"\n[Error: {str(e)}]"
