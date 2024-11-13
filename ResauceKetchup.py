import xml.etree.ElementTree as ET
import base64
import pandas as pd
import re
import sys
import os

def parse_burp_xml(file_path):
    # Check if the file exists
    if not os.path.isfile(file_path):
        print(f"Error: The file '{file_path}' does not exist.")
        return
    
    tree = ET.parse(file_path)
    root = tree.getroot()
    
    data = []

    for issue in root.findall("issue"):
        host = issue.find("host").text if issue.find("host") is not None else None
        path = issue.find("path").text if issue.find("path") is not None else None
        request_responses = issue.findall("requestresponse")
        
        for rr in request_responses:
            # Extract the request URL
            request_elem = rr.find("request")
            endpoint = None
            if request_elem is not None:
                if request_elem.get("base64") == "true":
                    try:
                        request_text = base64.b64decode(request_elem.text).decode("utf-8")
                    except Exception:
                        request_text = None  # Skip if decoding fails
                else:
                    request_text = request_elem.text
                
                # Parse the endpoint from the request text for any HTTP method
                if request_text:
                    for line in request_text.splitlines():
                        if line.split()[0] in {"GET", "POST", "PUT", "DELETE", "OPTIONS"}:
                            endpoint = line.split()[1]
                            break

            # Process the response to find all cross-domain scripts
            response_elem = rr.find("response")
            if response_elem is not None and response_elem.get("base64") == "true":
                try:
                    decoded_response = base64.b64decode(response_elem.text).decode("utf-8")
                except Exception:
                    continue  # Skip if decoding fails
                
                # Enhanced regex pattern to capture src in <script> tags across multiple lines
                script_tags = re.finditer(r'<script[^>]*src=["\'](https?://[^"\']+)["\'][^>]*>(.*?)</script>', decoded_response, re.DOTALL | re.IGNORECASE)
                for tag in script_tags:
                    script_src = tag.group(1)
                    script_content = tag.group(2)
                    sri_enabled = 'Yes' if 'integrity=' in script_content else 'No'
                    
                    # Add the data with line number info
                    data.append({
                        "Resource": script_src,
                        "SRI Enabled": sri_enabled,
                        "Line Number": decoded_response[:tag.start()].count('\n') + 1,
                        "Endpoint": endpoint or f"{host}{path}"
                    })
    
    # Convert collected data to DataFrame for output
    df = pd.DataFrame(data)
    output_file = "cross_domain_scripts.tsv"
    df.to_csv(output_file, index=False, sep='\t')
    print(f"Output saved to {output_file}")
    return df

# Check for command-line arguments
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script_name.py <path_to_burp_xml_file>")
        print("Example: python script_name.py /path/to/Cross-domain-script-include.xml")
    else:
        file_path = sys.argv[1]
        parse_burp_xml(file_path)
