#!/usr/bin/env python3
"""
Legal Research Powerhouse - FastMCP 2.0 Enhanced Server
Maximum Control Point (MCP) Integration

Features:
- FastMCP 2.0 with server composition and proxying
- Intelligent tool selection (max 40 tools per context)
- Progressive scoping with enterprise authentication
- Forensic-grade logging and audit trails
- Federal compliance with chain-of-custody
- Hawaii timezone optimization for Case 1FDV-23-0001009
"""

import asyncio
import os
import json
import hashlib
from typing import List, Dict, Optional, Any, Union
from datetime import datetime, timezone
from pathlib import Path
import logging
from dataclasses import dataclass, asdict
from enum import Enum

# FastMCP 2.0 imports
try:
    from fastmcp import FastMCP, compose_servers
    from fastmcp.auth import GoogleAuth, GitHubAuth
    from fastmcp.tools import tool, Tool
    from fastmcp.resources import resource
    from fastmcp.prompts import prompt
except ImportError:
    # Fallback to standard MCP if FastMCP not available
    from mcp.server.fastmcp import FastMCP
    from mcp.server.models import TextContent, Tool
    from mcp.server import Server

# Import our enhanced connectors
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from connectors.perplexity_search_v2 import PerplexitySearchV2, SearchRecency, SearchDomain, SearchPriority

# Setup forensic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler('logs/legal_research_powerhouse.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ToolCategory(Enum):
    """Tool categories for intelligent selection"""
    LEGAL_RESEARCH = "legal_research"
    EVIDENCE_COLLECTION = "evidence_collection"
    CASE_MANAGEMENT = "case_management"
    DOCUMENT_PROCESSING = "document_processing"
    MEMORY_MANAGEMENT = "memory_management"
    COMPLIANCE = "compliance"
    COMMUNICATION = "communication"
    ANALYSIS = "analysis"

class AccessScope(Enum):
    """Progressive access scopes"""
    READ_ONLY = "read_only"
    SEARCH_BASIC = "search_basic"
    SEARCH_ADVANCED = "search_advanced"
    EVIDENCE_READ = "evidence_read"
    EVIDENCE_WRITE = "evidence_write"
    CASE_ADMIN = "case_admin"
    FORENSIC_ADMIN = "forensic_admin"

@dataclass
class ToolMetadata:
    """Enhanced tool metadata for intelligent selection"""
    name: str
    description: str
    category: ToolCategory
    required_scopes: List[AccessScope]
    complexity_score: int  # 1-10
    risk_level: str  # low, medium, high
    use_cases: List[str]
    forensic_logging: bool = True
    hawaii_optimized: bool = False

class IntelligentToolSelector:
    """Intelligent tool selection with context awareness"""
    
    def __init__(self, max_tools: int = 40):
        self.max_tools = max_tools
        self.tool_registry = {}
        self.usage_patterns = {}
        
    def register_tool(self, tool_meta: ToolMetadata):
        """Register tool with metadata"""
        self.tool_registry[tool_meta.name] = tool_meta
        logger.debug(f"Registered tool: {tool_meta.name} ({tool_meta.category.value})")
    
    def select_tools_for_context(
        self,
        query: str,
        case_type: str = "family_court",
        user_scopes: List[AccessScope] = None,
        required_tools: List[str] = None
    ) -> List[str]:
        """Select optimal tools for given context"""
        if user_scopes is None:
            user_scopes = [AccessScope.READ_ONLY, AccessScope.SEARCH_BASIC]
        
        available_tools = []
        
        # Filter tools by scope permissions
        for tool_name, tool_meta in self.tool_registry.items():
            if any(scope in user_scopes for scope in tool_meta.required_scopes):
                available_tools.append(tool_meta)
        
        # Score tools based on context
        scored_tools = []
        for tool in available_tools:
            score = self._calculate_tool_score(tool, query, case_type)
            scored_tools.append((tool.name, score))
        
        # Sort by score and select top tools
        scored_tools.sort(key=lambda x: x[1], reverse=True)
        selected = [tool[0] for tool in scored_tools[:self.max_tools]]
        
        # Ensure required tools are included
        if required_tools:
            for req_tool in required_tools:
                if req_tool not in selected and req_tool in self.tool_registry:
                    # Replace lowest scored tool if at limit
                    if len(selected) >= self.max_tools:
                        selected.pop()
                    selected.append(req_tool)
        
        logger.info(f"Selected {len(selected)} tools for context: {query[:50]}...")
        return selected
    
    def _calculate_tool_score(self, tool: ToolMetadata, query: str, case_type: str) -> float:
        """Calculate relevance score for tool selection"""
        score = 0.0
        
        # Base relevance from description and use cases
        text_to_check = f"{tool.description} {' '.join(tool.use_cases)}".lower()
        query_words = query.lower().split()
        
        for word in query_words:
            if word in text_to_check:
                score += 1.0
        
        # Category bonuses
        if "research" in query.lower() and tool.category == ToolCategory.LEGAL_RESEARCH:
            score += 3.0
        if "evidence" in query.lower() and tool.category == ToolCategory.EVIDENCE_COLLECTION:
            score += 3.0
        if "case" in query.lower() and tool.category == ToolCategory.CASE_MANAGEMENT:
            score += 2.0
        
        # Case type relevance
        if case_type in tool.use_cases:
            score += 2.0
        
        # Hawaii optimization bonus
        if tool.hawaii_optimized:
            score += 1.0
        
        # Complexity penalty for simple queries
        if len(query.split()) < 5 and tool.complexity_score > 7:
            score -= 1.0
        
        # Risk penalty
        if tool.risk_level == "high":
            score -= 0.5
        
        return score

class LegalResearchPowerhouse:
    """Main legal research server with FastMCP 2.0"""
    
    def __init__(self):
        self.mcp = FastMCP("Legal-Research-Powerhouse")
        self.tool_selector = IntelligentToolSelector()
        self.audit_log = []
        self.case_context = {}
        
        # Setup authentication
        self._setup_authentication()
        
        # Register tools
        self._register_tools()
        
        # Setup progressive scoping
        self._setup_progressive_scoping()
        
        logger.info("Legal Research Powerhouse initialized")
    
    def _setup_authentication(self):
        """Setup enterprise authentication"""
        try:
            # Google authentication for legal organization
            google_auth = GoogleAuth(
                client_id=os.getenv("GOOGLE_CLIENT_ID"),
                client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
                allowed_domains=["glacier-legal.com", "hawaii.gov"]
            )
            self.mcp.add_auth(google_auth)
            
            # GitHub authentication for technical repositories
            github_auth = GitHubAuth(
                client_id=os.getenv("GITHUB_CLIENT_ID"),
                client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
                organization="GlacierEQ"
            )
            self.mcp.add_auth(github_auth)
            
            logger.info("Enterprise authentication configured")
            
        except Exception as e:
            logger.warning(f"Authentication setup failed: {e}")
    
    def _setup_progressive_scoping(self):
        """Setup progressive access scoping"""
        self.scope_escalation_rules = {
            AccessScope.SEARCH_ADVANCED: {
                "requires": [AccessScope.SEARCH_BASIC],
                "approval_required": False
            },
            AccessScope.EVIDENCE_READ: {
                "requires": [AccessScope.SEARCH_BASIC],
                "approval_required": True,
                "justification_required": True
            },
            AccessScope.EVIDENCE_WRITE: {
                "requires": [AccessScope.EVIDENCE_READ],
                "approval_required": True,
                "multi_factor_required": True
            },
            AccessScope.FORENSIC_ADMIN: {
                "requires": [AccessScope.CASE_ADMIN],
                "approval_required": True,
                "multi_factor_required": True,
                "admin_approval_required": True
            }
        }
    
    def _register_tools(self):
        """Register all available tools with metadata"""
        
        # Legal Research Tools
        self.tool_selector.register_tool(ToolMetadata(
            name="search_legal_precedent",
            description="Search for legal precedents using enhanced Perplexity Search API",
            category=ToolCategory.LEGAL_RESEARCH,
            required_scopes=[AccessScope.SEARCH_BASIC],
            complexity_score=6,
            risk_level="low",
            use_cases=["precedent research", "case law", "court decisions", "family_court"],
            hawaii_optimized=True
        ))
        
        self.tool_selector.register_tool(ToolMetadata(
            name="deep_legal_analysis",
            description="Perform comprehensive legal analysis with reasoning models",
            category=ToolCategory.ANALYSIS,
            required_scopes=[AccessScope.SEARCH_ADVANCED],
            complexity_score=8,
            risk_level="medium",
            use_cases=["legal analysis", "case strategy", "precedent analysis"],
            hawaii_optimized=True
        ))
        
        # Evidence Collection Tools
        self.tool_selector.register_tool(ToolMetadata(
            name="collect_email_evidence",
            description="Search and collect email evidence with forensic integrity",
            category=ToolCategory.EVIDENCE_COLLECTION,
            required_scopes=[AccessScope.EVIDENCE_READ],
            complexity_score=7,
            risk_level="high",
            use_cases=["email discovery", "communication records", "evidence gathering"]
        ))
        
        # Case Management Tools
        self.tool_selector.register_tool(ToolMetadata(
            name="create_case_record",
            description="Create comprehensive case record with federal compliance",
            category=ToolCategory.CASE_MANAGEMENT,
            required_scopes=[AccessScope.CASE_ADMIN],
            complexity_score=5,
            risk_level="medium",
            use_cases=["case creation", "file organization", "workflow setup"],
            hawaii_optimized=True
        ))
        
        logger.info(f"Registered {len(self.tool_selector.tool_registry)} tools")

    @tool()
    async def search_legal_precedent(
        self,
        query: str,
        jurisdiction: str = "hawaii",
        case_type: str = "family_court",
        recency: str = "year",
        max_results: int = 20
    ) -> str:
        """
        Search for legal precedents using enhanced Perplexity Search API v2
        
        Args:
            query: Legal research query
            jurisdiction: Court jurisdiction (default: hawaii)
            case_type: Type of case (family_court, civil, criminal)
            recency: Time filter (day, week, month, year)
            max_results: Maximum results (1-50)
        """
        try:
            # Log tool usage for audit
            await self._log_tool_usage(
                "search_legal_precedent", 
                {"query": query, "jurisdiction": jurisdiction, "case_type": case_type}
            )
            
            # Get API key from environment
            api_key = os.getenv("PERPLEXITY_API_KEY")
            if not api_key:
                return "Error: PERPLEXITY_API_KEY not configured"
            
            # Use enhanced search with forensic logging
            async with PerplexitySearchV2(
                api_key=api_key,
                case_number=self.case_context.get("current_case", "general_research"),
                jurisdiction=jurisdiction
            ) as search:
                
                results = await search.search(
                    query=query,
                    recency=SearchRecency(recency),
                    domain_filter=SearchDomain.COURTS_GOV,
                    max_results=min(max_results, 50),
                    priority=SearchPriority.HIGH,
                    legal_context=f"{case_type} {jurisdiction} court"
                )
                
                if not results:
                    return f"No legal precedents found for: {query}"
                
                # Format results for legal analysis
                response = f"Found {len(results)} legal precedents for '{query}' in {jurisdiction}:\n\n"
                
                for i, result in enumerate(results[:10], 1):
                    response += f"**{i}. {result.title}**\n"
                    response += f"   Source: {result.url}\n"
                    response += f"   Relevance: {result.score:.2f}\n"
                    response += f"   Summary: {result.snippet[:300]}...\n"
                    response += f"   Integrity Hash: {result.content_hash[:16]}...\n\n"
                
                # Add forensic metadata
                response += f"\n---\n**Forensic Metadata:**\n"
                response += f"Search executed: {datetime.now(timezone.utc).isoformat()}\n"
                response += f"Total results: {len(results)}\n"
                response += f"Jurisdiction: {jurisdiction}\n"
                response += f"Case reference: {self.case_context.get('current_case', 'N/A')}\n"
                
                return response
                
        except Exception as e:
            error_msg = f"Legal precedent search failed: {str(e)}"
            logger.error(error_msg)
            return error_msg
    
    @tool()
    async def deep_legal_analysis(
        self,
        topic: str,
        case_context: str = "",
        analysis_depth: str = "comprehensive"
    ) -> str:
        """
        Perform deep legal analysis using advanced reasoning models
        
        Args:
            topic: Legal topic for analysis
            case_context: Specific case context
            analysis_depth: Analysis depth (basic, standard, comprehensive)
        """
        try:
            await self._log_tool_usage(
                "deep_legal_analysis",
                {"topic": topic, "analysis_depth": analysis_depth}
            )
            
            api_key = os.getenv("PERPLEXITY_API_KEY")
            if not api_key:
                return "Error: PERPLEXITY_API_KEY not configured"
            
            # Construct analysis prompt
            analysis_prompt = f"""
            Conduct a comprehensive legal analysis of: {topic}
            
            Case Context: {case_context or 'Hawaii family court proceedings'}
            
            Please provide:
            1. Relevant legal principles and precedents
            2. Applicable Hawaii state law and federal law
            3. Key factors for consideration
            4. Potential arguments and counterarguments
            5. Strategic recommendations
            
            Focus on Hawaii jurisdiction and family court procedures.
            """
            
            # Use reasoning model for deep analysis
            reasoning_effort = {
                "basic": "low",
                "standard": "medium", 
                "comprehensive": "high"
            }.get(analysis_depth, "high")
            
            import aiohttp
            
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": "sonar-reasoning-pro",
                "messages": [
                    {
                        "role": "user",
                        "content": analysis_prompt
                    }
                ],
                "reasoning_effort": reasoning_effort,
                "max_tokens": 4000,
                "temperature": 0.1  # Lower temperature for legal analysis
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://api.perplexity.ai/v1/chat/completions",
                    json=payload,
                    headers=headers
                ) as response:
                    
                    if response.status == 200:
                        data = await response.json()
                        analysis = data["choices"][0]["message"]["content"]
                        
                        # Add forensic metadata
                        analysis += f"\n\n---\n**Analysis Metadata:**\n"
                        analysis += f"Generated: {datetime.now(timezone.utc).isoformat()}\n"
                        analysis += f"Model: sonar-reasoning-pro\n"
                        analysis += f"Reasoning effort: {reasoning_effort}\n"
                        analysis += f"Case reference: {self.case_context.get('current_case', 'N/A')}\n"
                        
                        return analysis
                    else:
                        return f"Analysis failed: HTTP {response.status}"
                        
        except Exception as e:
            error_msg = f"Deep legal analysis failed: {str(e)}"
            logger.error(error_msg)
            return error_msg
    
    @tool()
    async def set_case_context(
        self,
        case_number: str,
        case_type: str = "family_court",
        jurisdiction: str = "hawaii"
    ) -> str:
        """
        Set current case context for all subsequent operations
        
        Args:
            case_number: Legal case number (e.g., 1FDV-23-0001009)
            case_type: Type of case
            jurisdiction: Court jurisdiction
        """
        try:
            self.case_context = {
                "current_case": case_number,
                "case_type": case_type,
                "jurisdiction": jurisdiction,
                "set_at": datetime.now(timezone.utc).isoformat()
            }
            
            await self._log_tool_usage(
                "set_case_context",
                self.case_context
            )
            
            logger.info(f"Case context set: {case_number} ({case_type}, {jurisdiction})")
            
            return f"Case context set successfully:\n" \
                   f"Case Number: {case_number}\n" \
                   f"Case Type: {case_type}\n" \
                   f"Jurisdiction: {jurisdiction}\n" \
                   f"Set at: {self.case_context['set_at']}"
                   
        except Exception as e:
            error_msg = f"Failed to set case context: {str(e)}"
            logger.error(error_msg)
            return error_msg
    
    @tool()
    async def get_optimal_tools(
        self,
        query: str,
        user_role: str = "legal_researcher"
    ) -> str:
        """
        Get optimal tool selection for current query and context
        
        Args:
            query: User query or task description
            user_role: User role (legal_researcher, attorney, admin)
        """
        try:
            # Map user roles to scopes
            role_scopes = {
                "legal_researcher": [AccessScope.READ_ONLY, AccessScope.SEARCH_BASIC, AccessScope.SEARCH_ADVANCED],
                "attorney": [AccessScope.READ_ONLY, AccessScope.SEARCH_BASIC, AccessScope.SEARCH_ADVANCED, AccessScope.EVIDENCE_READ],
                "admin": [scope for scope in AccessScope],
                "paralegal": [AccessScope.READ_ONLY, AccessScope.SEARCH_BASIC, AccessScope.CASE_ADMIN]
            }
            
            user_scopes = role_scopes.get(user_role, [AccessScope.READ_ONLY])
            case_type = self.case_context.get("case_type", "general")
            
            selected_tools = self.tool_selector.select_tools_for_context(
                query=query,
                case_type=case_type,
                user_scopes=user_scopes
            )
            
            # Format response
            response = f"Optimal tools for query: '{query[:50]}...'\n\n"
            response += f"User Role: {user_role}\n"
            response += f"Available Scopes: {[scope.value for scope in user_scopes]}\n"
            response += f"Case Context: {case_type}\n\n"
            response += f"Selected Tools ({len(selected_tools)}/{self.tool_selector.max_tools}):"\n"
            
            for i, tool_name in enumerate(selected_tools[:10], 1):
                tool_meta = self.tool_selector.tool_registry.get(tool_name)
                if tool_meta:
                    response += f"{i}. {tool_name} - {tool_meta.description[:60]}...\n"
            
            if len(selected_tools) > 10:
                response += f"... and {len(selected_tools) - 10} more tools\n"
            
            return response
            
        except Exception as e:
            error_msg = f"Tool selection failed: {str(e)}"
            logger.error(error_msg)
            return error_msg
    
    async def _log_tool_usage(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        user_id: str = "system"
    ):
        """
        Log tool usage for forensic audit trail
        """
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool_name": tool_name,
            "parameters": parameters,
            "user_id": user_id,
            "case_context": self.case_context,
            "session_id": id(self),
            "integrity_hash": hashlib.sha256(
                f"{tool_name}{json.dumps(parameters, sort_keys=True)}{user_id}".encode()
            ).hexdigest()
        }
        
        self.audit_log.append(log_entry)
        
        # Write to forensic log file
        try:
            log_file = Path("logs/tool_usage_audit.jsonl")
            log_file.parent.mkdir(exist_ok=True)
            
            with open(log_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
                
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")
    
    def get_server(self) -> FastMCP:
        """Get the configured MCP server"""
        return self.mcp

# Initialize the legal research powerhouse
legal_server = LegalResearchPowerhouse()
mcp = legal_server.get_server()

# Example initialization for Case 1FDV-23-0001009
async def initialize_case_context():
    """Initialize with current case context"""
    await legal_server.set_case_context(
        case_number="1FDV-23-0001009",
        case_type="family_court",
        jurisdiction="hawaii"
    )
    logger.info("Case context initialized for 1FDV-23-0001009")

if __name__ == "__main__":
    # Run the MCP server
    import asyncio
    from mcp.server.stdio import stdio_server
    
    async def main():
        # Initialize case context
        await initialize_case_context()
        
        # Run the server
        async with stdio_server() as (read_stream, write_stream):
            await mcp.run(
                read_stream,
                write_stream,
                mcp.create_initialization_options()
            )
    
    asyncio.run(main())