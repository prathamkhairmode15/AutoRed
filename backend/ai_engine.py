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

async def generate_scan_explanation(scan_data: dict, cve_ids: list[str], model: str = DEFAULT_MODEL) -> str:
    """
    Sends scan data and CVE IDs to an AI to generate a comprehensive explanation.
    """
    notice = ""
    # Limit to top 5 CVEs to prevent overwhelming
    if len(cve_ids) > 5:
        cve_ids = cve_ids[:5]
        notice = "\n\n*(Note: Showing explanations for the first 5 CVEs only to preserve system resources.)*"

    # FETCH CVE DESCRIPTIONS CONCURRENTLY
    cve_contexts = []
    if cve_ids:
        async with httpx.AsyncClient(timeout=120.0) as client:
            fetch_tasks = [fetch_cve_description(cve, client) for cve in cve_ids]
            descriptions = await asyncio.gather(*fetch_tasks)
            
        for cve, desc in zip(cve_ids, descriptions):
            cve_contexts.append(f"- {cve}: {desc}")
    
    context_str = "\n".join(cve_contexts)
    scan_json = json.dumps(scan_data, indent=2)

    prompt = (
        f"You are a strict and factual cybersecurity expert. Your task is to analyze and explain the results of a network scan.\n\n"
        f"SCAN DATA (JSON):\n{scan_json}\n\n"
    )
    if context_str:
        prompt += f"OFFICIAL CVE DESCRIPTIONS (RAG Context):\n{context_str}\n\n"

    prompt += (
        f"RULES:\n"
        f"1. Explain the WHOIS and NSLOOKUP findings briefly.\n"
        f"2. Explain the NMAP open ports: What is the standard use case for each open port, and why might it be open? What are the potential security risks?\n"
    )
    if context_str:
        prompt += f"3. Briefly describe the factual mechanism, potential impact, and standard remediation for each CVE found based ONLY on the official descriptions provided. Do NOT invent information.\n"
        
    prompt += f"Keep the explanation professional, highly accurate, and concise. Format using Markdown."

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
