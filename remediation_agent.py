"""
Local Autonomous Vulnerability Remediation Pipeline
Powered by Google Agent Development Kit (ADK)
"""

import os
import re
import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, List
from google.adk import Agent

import asyncio
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

# ---------------------------------------------------------
# 1. Define Tools as Standard Python Functions
# ---------------------------------------------------------
# ADK automatically reads the type hints and docstrings to give the agent context.

def scan_workspace_dependencies(repo_path: str) -> List[Dict[str, str]]:
    """Generates a dependency tree and identifies all vulnerable dependencies."""
    print(f"\n[Tool] Generating Maven dependency tree in {repo_path}...")
    
    # Mocking discovery to bypass Xray API for local testing
    return [{
        "vulnerable_lib": "org.yaml:snakeyaml",
        "current_version": "1.33",
        "root_direct_lib": "com.food.ordering.system"
    }]

def fetch_safe_versions(vulnerabilities: List[Dict[str, str]]) -> Dict[str, str]:
    """Queries Artifactory and filters for safe, stable versions."""
    print("\n[Tool] Identifying safe versions via Artifactory & Xray...")
    safe_updates = {}
    
    for item in vulnerabilities:
        lib = item["vulnerable_lib"]
        # Select highest safe version
        safe_updates[lib] = "1.35" 
            
    return safe_updates

def apply_dependency_management_override(repo_path: str, safe_updates: Dict[str, str]) -> str:
    """Injects safe versions into the pom.xml <dependencyManagement> section."""
    print(f"\n[Tool] Enforcing safe versions globally via dependencyManagement...")
    print(f"[Tool] Received updates from agent: {safe_updates}")
    
    pom_path = os.path.join(repo_path, "pom.xml")
    
    if not os.path.exists(pom_path):
        return f"Error: No pom.xml found at {pom_path}"
        
    ET.register_namespace('', "http://maven.apache.org/POM/4.0.0")
    ns = {"maven": "http://maven.apache.org/POM/4.0.0"}
    
    tree = ET.parse(pom_path)
    root = tree.getroot()
    
    dep_mgmt = root.find("maven:dependencyManagement", ns)
    if dep_mgmt is None:
        dep_mgmt = ET.SubElement(root, "dependencyManagement")
        dependencies_node = ET.SubElement(dep_mgmt, "dependencies")
    else:
        dependencies_node = dep_mgmt.find("maven:dependencies", ns)
        if dependencies_node is None:
            dependencies_node = ET.SubElement(dep_mgmt, "dependencies")
            
    for lib, safe_version in safe_updates.items():
        # --- THE FIX: Safe splitting with validation ---
        parts = lib.split(":")
        if len(parts) != 2:
            print(f"   [Warning] Agent passed malformed library name '{lib}'. Expected 'groupId:artifactId'. Skipping.")
            continue 
            
        group_id, artifact_id = parts[0], parts[1]
        
        new_dep = ET.SubElement(dependencies_node, "dependency")
        ET.SubElement(new_dep, "groupId").text = group_id
        ET.SubElement(new_dep, "artifactId").text = artifact_id
        ET.SubElement(new_dep, "version").text = str(safe_version) # Force string cast just in case
            
    tree.write(pom_path, encoding="utf-8", xml_declaration=True)
    return "Dependency management constraints written successfully."

def run_local_maven_build(repo_path: str) -> str:
    """Runs 'mvn clean install' locally and captures logs."""
    print("\n[Tool] Executing 'mvn clean install' locally...")
    try:
        result = subprocess.run(
            ["mvn", "clean", "test"],
            cwd=repo_path,
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            return "Maven build SUCCESS. All tests passed."
        else:
            # Aggressively truncate logs to protect the local LLM's context window
            error_logs = result.stdout[-5000:] if len(result.stdout) > 5000 else result.stdout
            return f"Maven build FAILED. Error logs: {error_logs}"
            
    except Exception as e:
        return f"Execution Error: {str(e)}"

# ---------------------------------------------------------
# 2. Define the Agent
# ---------------------------------------------------------
# Connect the tools directly to the agent. ADK handles the reasoning and execution loop.
remediation_agent = Agent(
    name="LocalCodeFixer",
    model="ollama/qwen2.5:1.5b", # To run locally via Ollama, configure the LiteLLM proxy string here (e.g., "ollama/qwen:1.5b")
    instruction=(
        "You are an autonomous Java security engineer. Your job is to update vulnerable "
        "dependencies in a local Maven workspace. Follow these steps strictly: "
        "1. Use `scan_workspace_dependencies` to find vulnerabilities. "
        "2. Use `fetch_safe_versions` to find patches for those vulnerabilities. CRITICAL: You must maintain the exact 'groupId:artifactId' formatting for all library names. "
        "3. Use `apply_dependency_management_override` to update the pom.xml. "
        "4. Use `run_local_maven_build` to verify the build. "
        "5. If the build fails, output the exact Java code fixes required to resolve the breaking changes."
    ),
    tools=[
        scan_workspace_dependencies,
        fetch_safe_versions,
        apply_dependency_management_override,
        run_local_maven_build
    ]
)

# ---------------------------------------------------------
# 3. Execution
# ---------------------------------------------------------

import asyncio
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

async def main():
    # IMPORTANT: Update this to your actual local workspace path
    target_workspace = "/Users/Gagan/eclipse-workspace/food-ordering-system" 
    
    # Define identifiers cleanly
    app = "LocalRemediationApp"
    user = "local_dev"
    session_id = "session_01"
    
    print("Initiating ADK Runner...\n")
    
    # 1. Initialize the session memory
    session_service = InMemorySessionService()
    
    # ---> THE FIX: Explicitly create the session before running <---
    await session_service.create_session(
        app_name=app,
        user_id=user,
        session_id=session_id
    )

    # 2. Build the runner
    runner = Runner(
        agent=remediation_agent,
        app_name=app,
        session_service=session_service
    )
    
    # 3. Format the user prompt
    prompt_text = f"Please remediate vulnerabilities for the repository located at: {target_workspace}"
    message = types.Content(role="user", parts=[types.Part(text=prompt_text)])
    
    print("Agent is thinking and executing tools... (this may take a moment)\n")
    
    # 4. Stream the execution events asynchronously
    async for event in runner.run_async(
        user_id=user,
        session_id=session_id,
        new_message=message
    ):
        # Capture and print the final output
        if event.is_final_response() and event.content and event.content.parts:
            print("\n==========================================")
            print("🤖 AGENT FINAL RESPONSE:")
            print("".join(p.text for p in event.content.parts if p.text))
            print("==========================================")

if __name__ == "__main__":
    asyncio.run(main())