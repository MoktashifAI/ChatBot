from dotenv import load_dotenv
from pathlib import Path
import os
import re
import json
import traceback

# Load .env at the very top!
# Try to load from multiple possible locations
load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env")
load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent / ".env")
load_dotenv()  # Also try default location

# Set OpenAI API key directly from API_KEY if OPENAI_API_KEY is not set
if not os.getenv("OPENAI_API_KEY") and os.getenv("API_KEY"):
    os.environ["OPENAI_API_KEY"] = os.getenv("API_KEY")

print("DEBUG: OPENAI_API_KEY =", os.getenv("OPENAI_API_KEY"))

from langchain_openai import ChatOpenAI
from langchain_community.tools.google_search.tool import GoogleSearchRun
from langchain_community.utilities.google_search import GoogleSearchAPIWrapper
from langchain.agents import initialize_agent, AgentType
from langchain_core.tools import Tool
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.exceptions import OutputParserException

print("DEBUG: Loading cybersec_agent.py")

# Set up the LLM with OpenRouter - using OPENAI_API_KEY directly from API_KEY
llm = ChatOpenAI(
    model="meta-llama/llama-4-scout-17b-16e-instruct",
    openai_api_base=os.getenv("BASE_URL", "https://api.groq.com/openai/v1"),
    openai_api_key=os.getenv("API_KEY"),  
    temperature=float(os.getenv("TEMPERATURE", "0.6")),# Directly use API_KEY
)
print("DEBUG: LLM initialized:", llm)

# Set up the Google Search API wrapper with keys from environment
google_api_wrapper = GoogleSearchAPIWrapper(
    google_api_key=os.getenv("GOOGLE_API_KEY"),
    google_cse_id=os.getenv("GOOGLE_CSE_ID"),
    k=10  # Increase number of results for better coverage
)

def enhance_search_query(query):
    """
    Enhance the search query based on the type of cybersecurity question.
    """
    # Check for CVE pattern
    cve_pattern = r"CVE-\d{4}-\d{4,7}"
    cve_match = re.search(cve_pattern, query, re.IGNORECASE)
    
    if cve_match:
        cve_id = cve_match.group(0)
        # Create a more specific query for CVE information
        return f"{cve_id} vulnerability details NIST NVD CVSS fortinet advisory"
    
    # Check for common web vulnerability keywords
    web_vuln_keywords = [
        "XSS", "CSRF", "SQL injection", "SQLI", "command injection", "file inclusion", 
        "LFI", "RFI", "SSRF", "XXE", "deserialization", "IDOR", "insecure direct object", 
        "authentication bypass", "CORS", "clickjacking", "OWASP"
    ]
    
    for keyword in web_vuln_keywords:
        if keyword.lower() in query.lower():
            return f"{query} vulnerability details exploitation impact mitigation OWASP"
    
    # General cybersecurity query enhancement
    if any(word in query.lower() for word in ["vulnerability", "exploit", "attack", "security", "hack"]):
        return f"{query} cybersecurity details impact mitigation techniques"
    
    # Default case - just return the original query
    return query

def direct_google_search(query, max_results=5):
    """
    Perform a direct Google search without going through the agent.
    This is useful when the agent fails to extract information correctly.
    """
    # Check if credentials are missing
    if not os.getenv("GOOGLE_API_KEY") or not os.getenv("GOOGLE_CSE_ID"):
        print("WARNING: Missing Google API credentials in direct_google_search. Using mock results.")
        
        # Generate mock results as text
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        cve_match = re.search(cve_pattern, query, re.IGNORECASE)
        
        if cve_match:
            cve_id = cve_match.group(0)
            return f"""
Title: {cve_id} - National Vulnerability Database
URL: https://nvd.nist.gov/vuln/detail/{cve_id}
Snippet: Vulnerability summary for {cve_id} - This vulnerability allows remote attackers to execute arbitrary code.

Title: MITRE CVE Program
URL: https://cve.mitre.org/
Snippet: The Common Vulnerabilities and Exposures (CVE) program identifies, defines, and catalogs publicly disclosed cybersecurity vulnerabilities.

Title: {cve_id} - CVE Details
URL: https://www.cvedetails.com/cve/{cve_id}
Snippet: Security vulnerability details for {cve_id}. CVSS score: 8.5. This vulnerability affects multiple versions and can be exploited remotely.
"""
        else:
            return f"""
Title: Cybersecurity Search Results for: {query}
URL: https://www.cisa.gov/topics/cybersecurity-best-practices
Snippet: Guidance and resources for implementing cybersecurity best practices related to {query}.

Title: Security Articles About {query}
URL: https://krebsonsecurity.com/
Snippet: In-depth security news and investigation related to {query} from security researcher Brian Krebs.

Title: Academic Research About {query}
URL: https://googleprojectzero.blogspot.com/
Snippet: Technical research about {query} from Google Project Zero, a team of security researchers.
"""
    
    enhanced_query = enhance_search_query(query)
    results = google_api_wrapper.results(enhanced_query, num_results=max_results * 2)  # Get more results to filter
    
    # Apply our strict filtering to get only the most relevant results
    if "cve-" in query.lower():
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        cve_match = re.search(cve_pattern, query, re.IGNORECASE)
        cve_id = cve_match.group(0).upper() if cve_match else None
        
        filtered_results = []
        for r in results:
            url = r["link"].lower()
            title = r["title"].lower()
            snippet = r.get("snippet", "").lower()
            
            # Skip if this doesn't mention our specific CVE
            if not (cve_id.lower() in url or cve_id.lower() in title or cve_id.lower() in snippet):
                continue
                
            # Skip if URL mentions a different CVE
            other_cves = re.findall(r"cve-\d{4}-\d{4,7}", url.lower())
            if other_cves and not any(cve_id.lower() == other_cve for other_cve in other_cves):
                continue
                
            filtered_results.append(r)
            
            if len(filtered_results) >= max_results:
                break
                
        results = filtered_results
    
    full_text = ""
    for r in results:
        full_text += f"Title: {r['title']}\nURL: {r['link']}\nSnippet: {r.get('snippet', '')}\n\n"
    
    return full_text

def filter_relevant_links(query, links, max_links=5):
    """
    Filter search results to keep only the most relevant links.
    For CVE queries, prioritize official sources and specific CVE information.
    """
    if not links:
        return []
        
    # Extract CVE ID if present
    cve_pattern = r"CVE-\d{4}-\d{4,7}"
    cve_match = re.search(cve_pattern, query, re.IGNORECASE)
    cve_id = cve_match.group(0).upper() if cve_match else None
    
    if cve_id:
        # Prioritize specific sources for CVEs
        priority_domains = [
            "nvd.nist.gov", 
            "cve.org",
            "cve.mitre.org",
            "fortinet.com",
            "fortiguard.com",
            "cisa.gov",
            "cvedetails.com",
            "rapid7.com",
            "tenable.com",
            "qualys.com",
            "securityfocus.com",
            "letsdefend.io"
        ]
        
        # Score each link based on relevance
        scored_links = []
        for link in links:
            score = 0
            url = link["url"].lower()
            title = link["title"].lower()
            snippet = link.get("snippet", "").lower()
            
            # Fix URL formatting issues (sometimes the URL has no space after it)
            if '[' in url:
                url = url.split('[')[0]
            
            # Explicitly reject certain patterns
            reject_patterns = [
                # General listing pages
                "/catalog",
                "list",
                # URLs for different CVEs
                r"CVE-\d{4}-\d{4,7}",
                # Social media and non-authoritative sources
                "twitter.com",
                "reddit.com",
                "github.io",
                "crowd",
                "feeds"
            ]
            
            # Check for reject patterns
            should_reject = False
            for pattern in reject_patterns:
                if pattern.startswith('r"'):
                    # It's a regex pattern
                    regex = pattern[2:-1]  # Remove the r" and trailing "
                    matches = re.findall(regex, url + " " + title)
                    if matches and not any(cve_id.lower() == match.lower() for match in matches):
                        should_reject = True
                        break
                elif pattern in url:
                    # For CISA catalog or other general listing pages, only accept if URL contains the specific CVE
                    if pattern == "/catalog" and cve_id.lower() in url:
                        continue
                    should_reject = True
                    break
            
            if should_reject:
                continue
                
            # Make sure the specific CVE ID is in the URL, title, or snippet for all links
            if not (cve_id.lower() in url or cve_id.lower() in title or cve_id.lower() in snippet):
                continue
                
            # Now continue with scoring if the link passes the strict filters
            if cve_id.lower() in url:
                score += 10
            if cve_id.lower() in title:
                score += 5
            if cve_id.lower() in snippet:
                score += 3
                
            # Boost score for priority domains
            for domain in priority_domains:
                if domain in url:
                    score += 8
                    break
                    
            # Check for advisory or specific vulnerability information
            if any(term in title.lower() or term in snippet.lower() for term in ["advisory", "vulnerability", "exploit", "affected", "impact", "mitigate", "bypass", "authentication"]):
                score += 2
                
            # Check if URL contains the exact CVE path
            cve_path_pattern = f"{cve_id.lower().replace('-', '/')}"
            cve_path_pattern2 = f"{cve_id.lower().replace('-', '-')}"
            if cve_path_pattern in url or cve_path_pattern2 in url:
                score += 5
                
            scored_links.append((score, link))
            
        # Sort by score and take the top results
        sorted_links = [link for score, link in sorted(scored_links, key=lambda x: x[0], reverse=True)]
        
        # Final verification pass to make sure we don't have any bad links
        verified_links = []
        for link in sorted_links:
            url = link["url"].lower()
            
            # Clean up the URL
            if '[' in url:
                link["url"] = url.split('[')[0]
                
            # Ensure it's a specific page for the CVE
            if cve_id.lower() not in link["url"].lower() and cve_id.lower() not in link["title"].lower():
                continue
                
            # Reject catalog pages unless they have the specific CVE in the URL
            if "/catalog" in url and cve_id.lower() not in url:
                continue
                
            # Reject if URL contains another CVE ID that's not our target
            other_cves = re.findall(r"cve-\d{4}-\d{4,7}", url.lower())
            if other_cves and not any(cve_id.lower() == other_cve for other_cve in other_cves):
                continue
                
            verified_links.append(link)
            
            # Stop after we have max_links
            if len(verified_links) >= max_links:
                break
        
        return verified_links
    else:
        # For non-CVE queries, do basic filtering
        filtered_links = []
        query_terms = query.lower().split()
        
        for link in links:
            url = link["url"].lower()
            title = link["title"].lower()
            snippet = link.get("snippet", "").lower()
            
            # Skip obviously irrelevant results
            if all(term not in title and term not in snippet for term in query_terms):
                continue
                
            filtered_links.append(link)
            
        return filtered_links[:max_links]

def search_cybersec_links(query, num_results=10):
    """
    Enhanced search for cybersecurity links with more results and better filtering.
    """
    if not os.getenv("GOOGLE_API_KEY") or not os.getenv("GOOGLE_CSE_ID"):
        print("WARNING: Missing Google API credentials. GOOGLE_API_KEY and GOOGLE_CSE_ID environment variables must be set for web search.")
        
        # Use mock results instead of returning empty list
        print("USING MOCK SEARCH RESULTS FOR DEMO")
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        cve_match = re.search(cve_pattern, query, re.IGNORECASE)
        
        if cve_match:
            cve_id = cve_match.group(0)
            return [
                {"title": f"{cve_id} - National Vulnerability Database", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}", 
                 "snippet": f"Vulnerability summary for {cve_id} - This vulnerability allows remote attackers to execute arbitrary code."},
                {"title": "MITRE CVE Program", "url": "https://cve.mitre.org/", 
                 "snippet": "The Common Vulnerabilities and Exposures (CVE) program identifies, defines, and catalogs publicly disclosed cybersecurity vulnerabilities."},
                {"title": f"{cve_id} - CVE Details", "url": f"https://www.cvedetails.com/cve/{cve_id}", 
                 "snippet": f"Security vulnerability details for {cve_id}. CVSS score: 8.5. This vulnerability affects multiple versions."}
            ]
        
        elif "vulnerability" in query.lower() or "exploit" in query.lower():
            return [
                {"title": "OWASP Top 10 Web Application Security Risks", "url": "https://owasp.org/www-project-top-ten/", 
                 "snippet": "The OWASP Top 10 is a standard awareness document for developers and web application security."},
                {"title": "Common Types of Cybersecurity Vulnerabilities", "url": "https://www.cisa.gov/topics/cyber-threats-and-vulnerabilities", 
                 "snippet": "Comprehensive overview of common cybersecurity vulnerabilities and mitigation strategies."},
                {"title": "Exploit Database - Offensive Security", "url": "https://www.exploit-db.com/", 
                 "snippet": "The Exploit Database is a CVE compliant archive of public exploits and corresponding vulnerable software."}
            ]
        
        else:
            return [
                {"title": "Cybersecurity Best Practices - CISA", "url": "https://www.cisa.gov/topics/cybersecurity-best-practices", 
                 "snippet": "Guidance and resources for implementing cybersecurity best practices."},
                {"title": "Latest Cybersecurity Threats - Krebs on Security", "url": "https://krebsonsecurity.com/", 
                 "snippet": "In-depth security news and investigation from security researcher Brian Krebs."},
                {"title": "Security Research - Google Project Zero", "url": "https://googleprojectzero.blogspot.com/", 
                 "snippet": "Google Project Zero is a team of security researchers who study zero-day vulnerabilities in hardware and software systems."}
            ]
        
    try:
        enhanced_query = enhance_search_query(query)
        print(f"DEBUG: Enhanced search query: {enhanced_query}")
        
        results = google_api_wrapper.results(enhanced_query, num_results=num_results)
        print(f"DEBUG: Found {len(results)} search results")
        
        # Each result is a dict with 'title', 'link', 'snippet'
        all_links = [{"title": r["title"], "url": r["link"], "snippet": r.get("snippet", "")} for r in results]
        
        # Filter results to include only the most relevant ones
        filtered_links = filter_relevant_links(query, all_links, max_links=5)
        print(f"DEBUG: Filtered to {len(filtered_links)} relevant links")
        
        # Make sure we always have some links, even if filtering removed them all
        if not filtered_links and all_links:
            print("DEBUG: Using unfiltered links as fallback")
            return all_links[:5]  # Return at least some results
            
        return filtered_links
    except Exception as e:
        print(f"ERROR in search_cybersec_links: {str(e)}")
        print(traceback.format_exc())
        
        # Try a simpler direct search as backup
        try:
            # Simple direct search without complex filtering
            print("DEBUG: Attempting backup search method")
            enhanced_query = enhance_search_query(query)
            results = google_api_wrapper.results(enhanced_query, num_results=5)
            return [{"title": r["title"], "url": r["link"], "snippet": r.get("snippet", "")} for r in results]
        except Exception as backup_error:
            print(f"ERROR in backup search: {str(backup_error)}")
            # Return hardcoded links for common sources if this is a CVE query
            cve_pattern = r"CVE-\d{4}-\d{4,7}"
            cve_match = re.search(cve_pattern, query, re.IGNORECASE)
            if cve_match:
                cve_id = cve_match.group(0)
                return [
                    {"title": "National Vulnerability Database (NVD)", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"},
                    {"title": "MITRE CVE Program", "url": "https://cve.mitre.org/"},
                    {"title": "CVE Details Database", "url": f"https://www.cvedetails.com/cve/{cve_id}"}
                ]
            return []  # Empty list if all else fails

# Set up the Google Search tool for cybersecurity with enhanced description
google_cybersec_search = GoogleSearchRun(
    api_wrapper=google_api_wrapper,
    description=(
        "A specialized Google Search tool for cybersecurity. Use this tool to find detailed information about: "
        "1. CVEs and vulnerability details (including CVSS scores, affected systems, and mitigations) "
        "2. Security advisories and bulletins from vendors and security organizations "
        "3. Detailed explanations of attack techniques, exploits, and web vulnerabilities "
        "4. Best practices and mitigation strategies "
        "Only use this tool for cybersecurity-related queries."
    )
)

def extract_cvss_from_search_results(query, search_results):
    """
    Extract CVSS score information from search results directly.
    """
    cve_pattern = r"CVE-\d{4}-\d{4,7}"
    if not re.search(cve_pattern, query, re.IGNORECASE):
        return None  # Not a CVE query
    
    # Look for CVSS score patterns in the search results
    cvss_patterns = [
        r"CVSS[\s:]+(\d+\.\d+)",
        r"severity[\s:]+(\d+\.\d+)",
        r"base score[\s:]+(\d+\.\d+)",
        r"score[\s:]+(\d+\.\d+)[\s,]+(CRITICAL|HIGH|MEDIUM|LOW)",
        r"(\d+\.\d+)[\s,]+(CRITICAL|HIGH|MEDIUM|LOW)",
        r"CVSS[\s:v\d\.]+(\d+\.\d+)",
        r"CVSS:(\d+\.\d+)"
    ]
    
    for result in search_results:
        snippet = result.get("snippet", "")
        title = result.get("title", "")
        
        for pattern in cvss_patterns:
            # Check in snippet
            match = re.search(pattern, snippet, re.IGNORECASE)
            if match:
                score = match.group(1)
                severity = match.group(2) if len(match.groups()) > 1 else "HIGH"  # Default to HIGH if not specified
                return {"score": score, "severity": severity}
            
            # Check in title
            match = re.search(pattern, title, re.IGNORECASE)
            if match:
                score = match.group(1)
                severity = match.group(2) if len(match.groups()) > 1 else "HIGH"
                return {"score": score, "severity": severity}
    
    return None

def format_final_answer(answer, query, links):
    """
    Format the final answer by cleaning up the agent's response and structuring it better.
    - Remove thinking/reasoning steps
    - Enhance the formatting of vulnerability information
    - Add source links
    - Handle multiple CVSS scores from different sources properly
    """
    # Check if this is likely a Final Answer format from the agent
    final_answer_pattern = r"(?:Final Answer:|Final Response:|Final:)(.*)"
    match = re.search(final_answer_pattern, answer, re.DOTALL | re.IGNORECASE)
    
    if match:
        # Extract just the answer part
        clean_answer = match.group(1).strip()
    else:
        # If not in expected format, use the whole answer but try to clean it
        clean_answer = answer.strip()
        # Remove any "Thought:", "Action:", etc. text
        action_patterns = [
            r"Thought:.*?((?=Action:)|$)",
            r"Action:.*?((?=Action Input:)|$)",
            r"Action Input:.*?((?=Observation:)|$)",
            r"Observation:.*?((?=Thought:)|$)"
        ]
        for pattern in action_patterns:
            clean_answer = re.sub(pattern, "", clean_answer, flags=re.DOTALL)

    # Check for CVE pattern in the query
    cve_pattern = r"CVE-\d{4}-\d{4,7}"
    cve_match = re.search(cve_pattern, query, re.IGNORECASE)

    # Enhanced CVSS handling - look for multiple scores and their sources
    if cve_match:
        # Look for different CVSS score patterns that might indicate multiple sources
        cvss_patterns = [
            r"NIST.*?(?:CVSS|base score|score)[\s:]+(\d+\.\d+)[\s,]*(CRITICAL|HIGH|MEDIUM|LOW)?",
            r"(?:CNA|vendor|ivanti|fortinet).*?(?:CVSS|base score|score)[\s:]+(\d+\.\d+)[\s,]*(CRITICAL|HIGH|MEDIUM|LOW)?",
            r"(?:CVSS|base score|score)[\s:]+(\d+\.\d+)[\s,]*(CRITICAL|HIGH|MEDIUM|LOW)?.*?NIST",
            r"(?:CVSS|base score|score)[\s:]+(\d+\.\d+)[\s,]*(CRITICAL|HIGH|MEDIUM|LOW)?.*?(?:CNA|vendor|ivanti|fortinet)",
            r"(?:CVSS|base score|severity)[\s:]+(\d+\.\d+)[\s,]+(CRITICAL|HIGH|MEDIUM|LOW)"
        ]
        
        found_scores = []
        for pattern in cvss_patterns:
            matches = re.finditer(pattern, clean_answer, re.IGNORECASE)
            for match in matches:
                score = match.group(1)
                severity = match.group(2).upper() if match.group(2) else "HIGH"  # Default severity
                source_text = match.group(0)
                
                # Determine source based on context
                source = "Unknown"
                if "nist" in source_text.lower():
                    source = "NIST"
                elif any(vendor in source_text.lower() for vendor in ["cna", "vendor", "ivanti", "fortinet"]):
                    source = "Vendor"
                
                found_scores.append({"score": score, "severity": severity, "source": source, "full_match": source_text})
        
        # If we found multiple different scores, format them clearly
        if len(found_scores) > 1:
            unique_scores = []
            seen_scores = set()
            for score_info in found_scores:
                score_key = f"{score_info['score']}_{score_info['severity']}"
                if score_key not in seen_scores:
                    unique_scores.append(score_info)
                    seen_scores.add(score_key)
            
            if len(unique_scores) > 1:
                # Multiple different scores found - create a clear summary
                score_summary = "**CVSS Scores (Multiple Assessments):**\n"
                for score_info in unique_scores:
                    score_summary += f"- {score_info['source']}: {score_info['score']} {score_info['severity']}\n"
                score_summary += "\n*Note: Different organizations may assign different CVSS scores based on their assessment criteria.*\n\n"
                
                # Remove the original scattered CVSS mentions and add our summary at the top
                for pattern in cvss_patterns:
                    clean_answer = re.sub(pattern, "", clean_answer, flags=re.IGNORECASE)
                
                # Remove any remaining CVSS score mentions that might be scattered
                clean_answer = re.sub(r"(?:CVSS|base score|severity)[\s:]+\d+\.\d+[\s,]*(?:CRITICAL|HIGH|MEDIUM|LOW)?", "", clean_answer, flags=re.IGNORECASE)
                
                # Clean up extra whitespace and add our summary
                clean_answer = re.sub(r'\n\s*\n\s*\n', '\n\n', clean_answer)  # Remove excessive newlines
                clean_answer = score_summary + clean_answer.lstrip()
            else:
                # Only one unique score, use the original logic
                cvss_score = unique_scores[0]['score']
                cvss_severity = unique_scores[0]['severity']
                
                # Replace all CVSS mentions in the answer with the consistent value
                def cvss_replacer(match):
                    return f"CVSS Score: {cvss_score} {cvss_severity}"
                
                for pattern in cvss_patterns:
                    clean_answer = re.sub(pattern, cvss_replacer, clean_answer, flags=re.IGNORECASE)
                
                # Prepend the bolded value
                score_text = f"**CVSS Score: {cvss_score} {cvss_severity}**\n\n"
                # Remove any duplicate bolded lines
                clean_answer = re.sub(r"\*\*CVSS Score:.*?\*\*\s*", "", clean_answer, flags=re.IGNORECASE)
                clean_answer = score_text + clean_answer.lstrip()
        elif len(found_scores) == 1:
            # Single score found, use original logic
            cvss_score = found_scores[0]['score']
            cvss_severity = found_scores[0]['severity']
            
            # Replace all CVSS mentions in the answer with the consistent value
            def cvss_replacer(match):
                return f"CVSS Score: {cvss_score} {cvss_severity}"
            
            for pattern in cvss_patterns:
                clean_answer = re.sub(pattern, cvss_replacer, clean_answer, flags=re.IGNORECASE)
            
            # Prepend the bolded value
            score_text = f"**CVSS Score: {cvss_score} {cvss_severity}**\n\n"
            # Remove any duplicate bolded lines
            clean_answer = re.sub(r"\*\*CVSS Score:.*?\*\*\s*", "", clean_answer, flags=re.IGNORECASE)
            clean_answer = score_text + clean_answer.lstrip()
        else:
            # No scores found in answer, try to extract from search results
            cvss_info = extract_cvss_from_search_results(query, links)
            if cvss_info:
                cvss_score = cvss_info['score']
                cvss_severity = cvss_info['severity'].upper()
                
                # Prepend the bolded value
                score_text = f"**CVSS Score: {cvss_score} {cvss_severity}**\n\n"
                clean_answer = score_text + clean_answer.lstrip()

    # Add source links at the end if not already included
    if links and not any(f"[{i+1}]" for i in range(len(links)) if f"[{i+1}]" in clean_answer):
        source_text = "\n\n**Sources:**\n"
        for i, link in enumerate(links):
            # Format each source as a Markdown link
            source_text += f"[{i+1}] [{link['title']}]({link['url']})\n\n"
        clean_answer += source_text

    return clean_answer

def answer_cybersec_query(user_query, force_web_search=False):
    """
    Enhanced version that answers a cybersecurity query with better formatting and web search control.
    
    Args:
        user_query: The user's cybersecurity question
        force_web_search: If True, always use web search. If False, use heuristics to decide.
    
    Returns:
        Dict containing the answer and links
    """
    # Log that the function is being called with force_web_search
    if force_web_search:
        print(f"DEBUG: Forcing web search for query: {user_query}")
    
    # Heuristic: If the query contains certain keywords or force_web_search is True, use the agent (web search)
    search_keywords = [
        "cve", "CVE", "exploit", "vulnerability", "zero-day", "advisory", "patch", "mitre", "nvd", "breach", "attack", "malware",
        "latest", "recent", "news", "security update", "threat", "incident", "report", "google", "source", "reference", "link",
        "xss", "csrf", "sqli", "sql injection", "rce", "owasp", "pentest", "penetration test", "cyber", "hack"
    ]
    
    use_search = force_web_search or any(word.lower() in user_query.lower() for word in search_keywords)

    # Always force web search if explicitly requested
    if force_web_search:
        use_search = True

    if use_search:
        # Get search links first to ensure we have them even if agent fails
        links = search_cybersec_links(user_query)
        print(f"DEBUG: Got {len(links)} search links for query: {user_query}")
        
        # Add default sources for CVE queries even if search fails
        if not links:
            cve_pattern = r"CVE-\d{4}-\d{4,7}"
            cve_match = re.search(cve_pattern, user_query, re.IGNORECASE)
            if cve_match:
                cve_id = cve_match.group(0)
                print(f"DEBUG: Adding default CVE sources for {cve_id}")
                links = [
                    {"title": "National Vulnerability Database (NVD)", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"},
                    {"title": "MITRE CVE Program", "url": "https://cve.mitre.org/"},
                    {"title": "CVE Details Database", "url": f"https://www.cvedetails.com/cve/{cve_id}"}
                ]
        
        # Check if this is a CVE query that needs direct handling
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        is_cve_query = re.search(cve_pattern, user_query, re.IGNORECASE)
        
        try:
            # Use the agent with search - enhanced prompt
            cybersec_agent_prompt = (
                "You are a cybersecurity assistant specialized in providing accurate, detailed information about security vulnerabilities, exploits, and best practices. "
                "For CVE queries, include comprehensive information about: "
                "- Detailed vulnerability description including the vulnerable component and the exploit method "
                "- CVSS score and severity rating with vector string if available. If multiple CVSS scores exist from different sources (e.g., NIST vs. vendor), clearly identify each source and score "
                "- Complete list of affected systems/versions with specific version numbers "
                "- Technical explanation of attack vectors and exploitation methods "
                "- Detailed mitigation steps and patch information "
                "- Known exploitation status (is it being exploited in the wild?) "
                "- Discovery timeline and attribution if available "
                
                "For web vulnerability queries, provide in-depth analysis including: "
                "- Detailed technical explanation of the vulnerability "
                "- Impact assessment with real-world implications "
                "- Step-by-step attack methodology "
                "- Detection techniques with specific indicators "
                "- Comprehensive prevention strategies "
                
                "Organize information in a clear, structured way using headings and bullet points. Aim for technical depth while maintaining readability. "
                "If using information from the search tool, verify information across multiple sources and note any discrepancies, especially in CVSS scores. "
                "When different organizations provide different CVSS scores for the same vulnerability, present both scores with their sources clearly identified. "
                "Prefer official sources like NIST NVD, MITRE, CISA, and vendor advisories. "
                "Present a comprehensive answer without any agent thinking steps or reasoning processes. "
                "Remove any 'Final Answer:' prefixes from your response. "
                "If a query is not related to cybersecurity, politely decline to answer."
            )
            
            agent = initialize_agent(
                tools=[google_cybersec_search],
                llm=llm,
                agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
                verbose=True,
                handle_parsing_errors=True
            )
            
            # Use the agent
            try:
                answer = agent.run(user_query)
            except Exception as agent_error:
                # If agent fails, use direct LLM
                print(f"Agent failed, using direct LLM approach: {str(agent_error)}")
                
                # Get links as we already have them
                link_list = "\n".join([f"- [{link['title']}]({link['url']})" for link in links])
                
                # Create direct prompt for LLM
                if not os.getenv("GOOGLE_API_KEY") or not os.getenv("GOOGLE_CSE_ID"):
                    mock_note = "[Using simulated web search data for demonstration purposes]"
                else:
                    mock_note = ""
                    
                system_prompt = f"""
                You are a cybersecurity assistant specialized in providing accurate information.
                {mock_note}
                
                For the query: "{user_query}"
                
                I have found the following web search results:
                {link_list}
                
                Please provide a helpful, detailed answer based on these search results.
                Present information in a structured way with clear sections and bullet points where appropriate.
                Include relevant technical details about vulnerabilities, exploits, or security practices.
                If you're not sure about something, acknowledge the limitations of the information available.
                """
                
                messages = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_query}
                ]
                
                response = llm.invoke(messages)
                answer = response.content
            
            # Format the final answer
            formatted_answer = format_final_answer(answer, user_query, links)
            
            return {"answer": formatted_answer, "links": links, "used_web_search": True}
        
        except Exception as e:
            print(f"Agent error: {str(e)}")
            print(traceback.format_exc())
            
            # If the agent fails, try a direct approach with the LLM
            if is_cve_query:
                try:
                    # Get direct search results specifically for this CVE
                    cve_id = is_cve_query.group(0)
                    direct_query = f"{cve_id} vulnerability details advisory CVSS score fortinet affected versions mitigations exploitation status detailed"
                    search_text = direct_google_search(direct_query, max_results=5)
                    
                    # Create a direct prompt for the LLM
                    system_prompt = (
                        "You are a cybersecurity expert specializing in vulnerability analysis. Given the search results about a CVE, "
                        "create a comprehensive and detailed analysis including: "
                        "- Vulnerability description: Explain in technical detail what the vulnerability is and how it works "
                        "- CVSS Score and severity rating: Include the numeric score, severity level, and vector string if available "
                        "- Affected systems: List all vulnerable software/hardware versions with precise version numbers "
                        "- Technical details: Explain the attack vectors, exploitation methods, and potential impact "
                        "- Mitigation: Provide detailed remediation steps including patch information, workarounds, and best practices "
                        "- Exploitation status: Note if this is being actively exploited in the wild "
                        "- Discovery timeline: When it was discovered and by whom if available "
                        
                        "Format your response with clear headings and bullet points. Provide specific technical details wherever possible. "
                        "If information is missing or contradictory across sources, note this explicitly. "
                    )
                    
                    prompt = f"""
                    Query: {user_query}
                    
                    Search Results:
                    {search_text}
                    
                    Please provide a comprehensive analysis of {cve_id} based on the search results.
                    Include as much technical detail as possible while maintaining accuracy.
                    """
                    
                    messages = [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt}
                    ]
                    
                    response = llm.invoke(messages)
                    fallback_answer = response.content
                    
                    # Format this answer as well
                    formatted_fallback = format_final_answer(fallback_answer, user_query, links)
                    
                    return {"answer": formatted_fallback, "links": links, "used_web_search": True}
                except Exception as fallback_error:
                    print(f"Fallback error: {str(fallback_error)}")
                    
                    # Provide a generic response about the CVE with links
                    cve_id = is_cve_query.group(0)
                    generic_response = f"I couldn't retrieve detailed information about {cve_id} at this time. This may be a very recent vulnerability or there might be connectivity issues. Please check the provided links for the most up-to-date information on this vulnerability."
                    
                    # Make sure links are included
                    formatted_response = generic_response
                    if links:
                        source_text = "\n\n**Sources:**\n"
                        for i, link in enumerate(links):
                            source_text += f"[{i+1}] [{link['title']}]({link['url']})\n\n"
                        formatted_response += source_text
                    
                    return {
                        "answer": formatted_response,
                        "links": links,
                        "used_web_search": True
                    }
            else:
                # For non-CVE queries, return a simpler error message with any sources we found
                error_msg = f"I encountered an error while searching for information about your query. Please try again with a different query or check the provided sources for information."
                
                # Add sources if we have them
                if links:
                    source_text = "\n\n**Sources:**\n"
                    for i, link in enumerate(links):
                        source_text += f"[{i+1}] [{link['title']}]({link['url']})\n\n"
                    error_msg += source_text
                
                return {
                    "answer": error_msg,
                    "links": links,
                    "used_web_search": True
                }
    else:
        # Just use the LLM for general knowledge
        system_prompt = (
            "You are a cybersecurity expert. Provide accurate information about cybersecurity topics "
            "based on your training data. If the user is asking about something that would require "
            "real-time or recent information that might not be in your knowledge base, let them know "
            "they should enable web search for the most up-to-date information."
        )
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_query}
        ]
        
        response = llm.invoke(messages)
        
        # Even without web search, provide reference links for CVE queries
        links = []
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        cve_match = re.search(cve_pattern, user_query, re.IGNORECASE)
        if cve_match:
            cve_id = cve_match.group(0)
            links = [
                {"title": "National Vulnerability Database (NVD)", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"},
                {"title": "MITRE CVE Program", "url": "https://cve.mitre.org/"},
                {"title": "CVE Details Database", "url": f"https://www.cvedetails.com/cve/{cve_id}"}
            ]
            
            # Add source references to the response
            answer_content = response.content
            if not "**Sources:**" in answer_content:
                source_text = "\n\n**Sources:**\n"
                for i, link in enumerate(links):
                    source_text += f"[{i+1}] [{link['title']}]({link['url']})\n\n"
                answer_content += source_text
            
            return {
                "answer": answer_content, 
                "links": links, 
                "used_web_search": False
            }
        
        return {
            "answer": response.content, 
            "links": links, 
            "used_web_search": False
        }

def is_cybersecurity_query(query):
    """
    Uses the LLM to classify if a query is cybersecurity-related.
    Returns True if the LLM says yes, False otherwise.
    """
    system_prompt = (
        "You are an expert classifier. "
        "Decide if the following user question is about cybersecurity, hacking, penetration testing, malware, vulnerabilities, or digital security. "
        "If yes, answer only with 'yes'. If not, answer only with 'no'."
    )
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": query}
    ]
    try:
        response = llm.invoke(messages)
        answer = response.content.strip().lower()
        return answer.startswith("yes")
    except Exception as e:
        print(f"[is_cybersecurity_query] LLM error: {e}")
        return False
def should_use_web_search(message):
    """
    Analyzes the user message to determine if a web search is needed.
    Uses LLM-based classification for cybersecurity topic detection.
    Args:
        message: The user's query
    Returns:
        bool: True if web search is recommended, False otherwise
    """
    # Check for explicit web search requests
    explicit_search_phrases = [
        "search for", "find information", "look up", "latest", "recent", 
        "news about", "update on", "current status", "did you know",
        "what happened with", "tell me about", "have you heard"
    ]
    if any(phrase in message.lower() for phrase in explicit_search_phrases):
        return True

    # Check for questions about current events/specific details
    current_event_patterns = [
        r"what is the (latest|current|recent)",
        r"what happened (with|to|in)",
        r"how (many|much|often)",
        r"when (was|did|will)",
        r"where (is|was|will)",
        r"who (is|was|discovered)",
        r"(in|on|during) [0-9]{4}",
        r"CVE-\d{4}-\d{4,7}"
    ]
    for pattern in current_event_patterns:
        if re.search(pattern, message, re.IGNORECASE):
            return True

    # Use LLM-based classification for cybersecurity topic detection
    return is_cybersecurity_query(message)

