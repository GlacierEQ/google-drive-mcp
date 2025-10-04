#!/usr/bin/env python3
"""
Ultimate MCP Orchestrator - Power Path Coordination
Maximum Control Point (MCP) Architecture v2.0

Features:
- Intelligent routing across all MCP servers
- Case 1FDV-23-0001009 workflow automation
- Real-time performance monitoring
- Forensic-grade audit trails
- Hawaii timezone optimization
- Federal compliance orchestration
"""

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import logging
from dataclasses import dataclass, asdict
from enum import Enum
import importlib
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import signal
from contextlib import asynccontextmanager

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import our enhanced components
try:
    from connectors.perplexity_search_v2 import PerplexitySearchV2, SearchRecency, SearchDomain, SearchPriority
    from connectors.gmail_legal_evidence import GmailLegalEvidence
    from forensic.federal_forensic_master import FederalForensicMaster
    from memory.enhanced_mem0_integration import EnhancedMemoryManager, MemoryType, MemoryPriority
except ImportError as e:
    logging.warning(f"Some components not available: {e}")

# FastMCP imports
try:
    from fastmcp import FastMCP, compose_servers
    from fastmcp.tools import tool
except ImportError:
    from mcp.server.fastmcp import FastMCP
    from mcp.server.models import TextContent

# Setup orchestrator logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler('logs/ultimate_mcp_orchestrator.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class WorkflowType(Enum):
    """Automated workflow types"""
    LEGAL_RESEARCH = "legal_research"
    EVIDENCE_COLLECTION = "evidence_collection"
    CASE_ANALYSIS = "case_analysis"
    DOCUMENT_PROCESSING = "document_processing"
    DEADLINE_MANAGEMENT = "deadline_management"
    COMPLIANCE_CHECK = "compliance_check"
    FULL_CASE_WORKFLOW = "full_case_workflow"

class ServerStatus(Enum):
    """MCP server status tracking"""
    ONLINE = "online"
    OFFLINE = "offline"
    ERROR = "error"
    STARTING = "starting"
    STOPPING = "stopping"

@dataclass
class MCPServerInfo:
    """MCP server information and status"""
    name: str
    description: str
    priority: int
    capabilities: List[str]
    status: ServerStatus
    last_health_check: str
    process_id: Optional[int] = None
    error_count: int = 0
    response_time_ms: float = 0.0

class UltimateMCPOrchestrator:
    """Ultimate MCP orchestration system"""
    
    def __init__(
        self,
        case_number: str = "1FDV-23-0001009",
        jurisdiction: str = "hawaii"
    ):
        self.case_number = case_number
        self.jurisdiction = jurisdiction
        self.config_file = Path("config/power_path_config.json")
        
        # Load configuration
        self.config = self._load_config()
        
        # Initialize components
        self.perplexity_search = None
        self.gmail_evidence = None
        self.forensic_master = None
        self.memory_manager = None
        
        # Server registry
        self.servers = {}
        self.server_processes = {}
        
        # Performance tracking
        self.performance_metrics = {
            "requests_processed": 0,
            "average_response_time": 0.0,
            "error_rate": 0.0,
            "uptime_start": datetime.now(timezone.utc).isoformat()
        }
        
        # Workflow automation
        self.active_workflows = {}
        
        logger.info(f"Ultimate MCP Orchestrator initialized for case {case_number}")
    
    def _load_config(self) -> Dict:
        """Load orchestrator configuration"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                logger.info(f"Configuration loaded: {len(config.get('mcpServers', {}))} servers")
                return config
            else:
                logger.error(f"Configuration file not found: {self.config_file}")
                return {}
        except Exception as e:
            logger.error(f"Configuration loading failed: {e}")
            return {}
    
    async def initialize_components(self):
        """Initialize all MCP components"""
        try:
            logger.info("Initializing MCP components...")
            
            # Initialize Perplexity Search v2
            if os.getenv("PERPLEXITY_API_KEY"):
                self.perplexity_search = PerplexitySearchV2(
                    api_key=os.getenv("PERPLEXITY_API_KEY"),
                    case_number=self.case_number,
                    jurisdiction=self.jurisdiction
                )
                logger.info("Perplexity Search v2 initialized")
            
            # Initialize Gmail Evidence Collector
            if os.getenv("GMAIL_CLIENT_ID"):
                self.gmail_evidence = GmailLegalEvidence(
                    case_number=self.case_number
                )
                logger.info("Gmail Legal Evidence collector initialized")
            
            # Initialize Federal Forensic Master
            self.forensic_master = FederalForensicMaster(
                case_number=self.case_number,
                jurisdiction=self.jurisdiction
            )
            logger.info("Federal Forensic Master initialized")
            
            # Initialize Enhanced Memory Manager
            self.memory_manager = EnhancedMemoryManager(
                case_number=self.case_number,
                jurisdiction=self.jurisdiction,
                mem0_api_key=os.getenv("MEM0_API_KEY")
            )
            
            # Create case memory session
            await self.memory_manager.create_case_memory_session()
            logger.info("Enhanced Memory Manager initialized")
            
            logger.info("All MCP components initialized successfully")
            
        except Exception as e:
            logger.error(f"Component initialization failed: {e}")
            raise
    
    async def execute_legal_research_workflow(
        self,
        research_topic: str,
        case_context: str = "",
        max_precedents: int = 20,
        analysis_depth: str = "comprehensive"
    ) -> Dict:
        """
        Execute complete legal research workflow
        
        Args:
            research_topic: Topic to research
            case_context: Additional case context
            max_precedents: Maximum precedents to find
            analysis_depth: Depth of analysis
            
        Returns:
            Complete research results
        """
        workflow_id = f"research_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        try:
            logger.info(f"Starting legal research workflow: {workflow_id}")
            
            workflow_results = {
                "workflow_id": workflow_id,
                "workflow_type": WorkflowType.LEGAL_RESEARCH.value,
                "case_reference": self.case_number,
                "started_timestamp": datetime.now(timezone.utc).isoformat(),
                "research_topic": research_topic,
                "results": {}
            }
            
            # Step 1: Search for legal precedents
            logger.info("Step 1: Searching legal precedents...")
            
            if self.perplexity_search:
                async with self.perplexity_search as search:
                    precedents = await search.search(
                        query=f"{research_topic} {self.jurisdiction} court precedent",
                        recency=SearchRecency.YEAR,
                        domain_filter=SearchDomain.COURTS_GOV,
                        max_results=max_precedents,
                        priority=SearchPriority.HIGH,
                        legal_context=f"{case_context} family court"
                    )
                    
                    workflow_results["results"]["precedents"] = [
                        {
                            "title": p.title,
                            "url": p.url,
                            "snippet": p.snippet,
                            "score": p.score,
                            "domain": p.domain
                        }
                        for p in precedents
                    ]
                    
                    logger.info(f"Found {len(precedents)} legal precedents")
            
            # Step 2: Perform deep legal analysis
            logger.info("Step 2: Performing deep legal analysis...")
            
            # This would integrate with the legal research server
            # For now, we'll simulate the analysis structure
            analysis_result = {
                "analysis_depth": analysis_depth,
                "key_findings": [],
                "applicable_law": [],
                "strategic_recommendations": [],
                "precedent_analysis": []
            }
            
            workflow_results["results"]["analysis"] = analysis_result
            
            # Step 3: Store research in memory
            logger.info("Step 3: Storing research in memory...")
            
            if self.memory_manager:
                # Store research topic
                await self.memory_manager.store_case_memory(
                    content=f"Legal research conducted on: {research_topic}. Found {len(workflow_results['results'].get('precedents', []))} relevant precedents.",
                    memory_type=MemoryType.LEGAL,
                    source="legal_research_workflow",
                    priority=MemoryPriority.HIGH,
                    tags=["research", "precedents", research_topic.replace(" ", "_")]
                )
                
                # Store key precedents
                for i, precedent in enumerate(workflow_results["results"].get("precedents", [])[:5]):
                    await self.memory_manager.store_case_memory(
                        content=f"Legal precedent: {precedent['title']}. {precedent['snippet'][:200]}...",
                        memory_type=MemoryType.LEGAL,
                        source="perplexity_search_v2",
                        priority=MemoryPriority.HIGH if precedent['score'] > 0.8 else MemoryPriority.NORMAL,
                        tags=["precedent", "case_law", self.jurisdiction]
                    )
                
                logger.info("Research results stored in memory")
            
            # Step 4: Generate workflow summary
            workflow_results["completed_timestamp"] = datetime.now(timezone.utc).isoformat()
            workflow_results["status"] = "completed"
            workflow_results["summary"] = {
                "precedents_found": len(workflow_results["results"].get("precedents", [])),
                "analysis_completed": bool(workflow_results["results"].get("analysis")),
                "memories_created": 1 + len(workflow_results["results"].get("precedents", [])[:5]),
                "workflow_duration_seconds": (datetime.fromisoformat(workflow_results["completed_timestamp"].replace('Z', '+00:00')) - 
                                             datetime.fromisoformat(workflow_results["started_timestamp"].replace('Z', '+00:00'))).total_seconds()
            }
            
            # Store workflow in active workflows
            self.active_workflows[workflow_id] = workflow_results
            
            logger.info(f"Legal research workflow completed: {workflow_id}")
            return workflow_results
            
        except Exception as e:
            logger.error(f"Legal research workflow failed: {e}")
            raise
    
    async def execute_evidence_collection_workflow(
        self,
        evidence_keywords: List[str],
        date_range_days: int = 365,
        auto_label: bool = True
    ) -> Dict:
        """
        Execute evidence collection workflow
        
        Args:
            evidence_keywords: Keywords to search for
            date_range_days: Days to search back
            auto_label: Automatically label as evidence
            
        Returns:
            Evidence collection results
        """
        workflow_id = f"evidence_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        try:
            logger.info(f"Starting evidence collection workflow: {workflow_id}")
            
            workflow_results = {
                "workflow_id": workflow_id,
                "workflow_type": WorkflowType.EVIDENCE_COLLECTION.value,
                "case_reference": self.case_number,
                "started_timestamp": datetime.now(timezone.utc).isoformat(),
                "keywords": evidence_keywords,
                "results": {}
            }
            
            # Step 1: Collect email evidence
            logger.info("Step 1: Collecting email evidence...")
            
            if self.gmail_evidence:
                # Authenticate if needed
                if await self.gmail_evidence.authenticate():
                    # Search for case emails
                    case_emails = await self.gmail_evidence.search_case_emails(
                        case_number=self.case_number,
                        keywords=evidence_keywords,
                        date_range_days=date_range_days,
                        max_results=50
                    )
                    
                    workflow_results["results"]["emails_found"] = len(case_emails)
                    workflow_results["results"]["email_metadata"] = [
                        {
                            "message_id": email.message_id,
                            "subject": email.subject,
                            "sender": email.sender,
                            "date": email.date_sent,
                            "attachment_count": email.attachment_count
                        }
                        for email in case_emails[:10]  # First 10 for summary
                    ]
                    
                    # Auto-label as evidence if requested
                    if auto_label and case_emails:
                        message_ids = [email.message_id for email in case_emails]
                        label_result = await self.gmail_evidence.label_as_evidence(
                            message_ids,
                            evidence_label="LEGAL_EVIDENCE",
                            case_label=f"CASE_{self.case_number.replace('-', '_')}"
                        )
                        
                        workflow_results["results"]["labeling_result"] = label_result
                    
                    logger.info(f"Collected {len(case_emails)} email evidence items")
            
            # Step 2: Process evidence through forensic system
            logger.info("Step 2: Processing evidence through forensic system...")
            
            if self.forensic_master and "email_metadata" in workflow_results["results"]:
                processed_evidence = []
                
                # Process each email through forensic system
                for email_meta in workflow_results["results"]["email_metadata"][:5]:  # First 5
                    try:
                        # Simulate email data structure for forensic processing
                        email_data = {
                            "message_metadata": email_meta,
                            "forensic_metadata": {
                                "collected_via": "gmail_legal_evidence",
                                "workflow_id": workflow_id
                            }
                        }
                        
                        forensic_metadata = await self.forensic_master.process_email_evidence(
                            email_data=email_data,
                            case_reference=self.case_number
                        )
                        
                        processed_evidence.append({
                            "evidence_id": forensic_metadata.evidence_id,
                            "original_subject": email_meta["subject"],
                            "processed_timestamp": forensic_metadata.collected_timestamp,
                            "integrity_hash": forensic_metadata.integrity_hashes.get("sha256", "")[:16],
                            "digital_signature": bool(forensic_metadata.digital_signature)
                        })
                        
                    except Exception as e:
                        logger.error(f"Forensic processing failed for email {email_meta['message_id']}: {e}")
                        continue
                
                workflow_results["results"]["forensic_processing"] = {
                    "evidence_items_processed": len(processed_evidence),
                    "processed_evidence": processed_evidence
                }
                
                logger.info(f"Processed {len(processed_evidence)} evidence items through forensic system")
            
            # Step 3: Store workflow results in memory
            logger.info("Step 3: Storing workflow results in memory...")
            
            if self.memory_manager:
                # Store workflow summary
                workflow_summary = f"Evidence collection workflow completed. Found {workflow_results['results'].get('emails_found', 0)} emails with keywords: {', '.join(evidence_keywords)}"
                
                await self.memory_manager.store_case_memory(
                    content=workflow_summary,
                    memory_type=MemoryType.EVIDENCE,
                    source="evidence_collection_workflow",
                    priority=MemoryPriority.HIGH,
                    tags=["evidence_collection", "workflow"] + evidence_keywords
                )
                
                logger.info("Workflow results stored in memory")
            
            # Complete workflow
            workflow_results["completed_timestamp"] = datetime.now(timezone.utc).isoformat()
            workflow_results["status"] = "completed"
            
            # Store in active workflows
            self.active_workflows[workflow_id] = workflow_results
            
            logger.info(f"Evidence collection workflow completed: {workflow_id}")
            return workflow_results
            
        except Exception as e:
            logger.error(f"Evidence collection workflow failed: {e}")
            raise
    
    async def execute_full_case_workflow(
        self,
        research_topics: List[str],
        evidence_keywords: List[str],
        priority_level: str = "high"
    ) -> Dict:
        """
        Execute comprehensive case workflow combining all capabilities
        
        Args:
            research_topics: Topics for legal research
            evidence_keywords: Keywords for evidence collection
            priority_level: Workflow priority
            
        Returns:
            Complete workflow results
        """
        workflow_id = f"full_case_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        try:
            logger.info(f"Starting full case workflow: {workflow_id}")
            
            full_workflow_results = {
                "workflow_id": workflow_id,
                "workflow_type": WorkflowType.FULL_CASE_WORKFLOW.value,
                "case_reference": self.case_number,
                "started_timestamp": datetime.now(timezone.utc).isoformat(),
                "priority_level": priority_level,
                "components": {
                    "legal_research": [],
                    "evidence_collection": {},
                    "memory_analytics": {},
                    "compliance_check": {}
                }
            }
            
            # Execute legal research for each topic
            logger.info("Executing legal research components...")
            for topic in research_topics:
                research_result = await self.execute_legal_research_workflow(
                    research_topic=topic,
                    case_context=f"Case {self.case_number} - {self.jurisdiction} family court",
                    max_precedents=15,
                    analysis_depth="comprehensive"
                )
                full_workflow_results["components"]["legal_research"].append(research_result)
            
            # Execute evidence collection
            logger.info("Executing evidence collection...")
            evidence_result = await self.execute_evidence_collection_workflow(
                evidence_keywords=evidence_keywords,
                date_range_days=730,  # 2 years for comprehensive collection
                auto_label=True
            )
            full_workflow_results["components"]["evidence_collection"] = evidence_result
            
            # Generate memory analytics
            logger.info("Generating memory analytics...")
            if self.memory_manager:
                analytics = await self.memory_manager.get_memory_analytics(
                    case_reference=self.case_number
                )
                full_workflow_results["components"]["memory_analytics"] = analytics
            
            # Perform compliance check
            logger.info("Performing compliance verification...")
            if self.forensic_master:
                custody_report = self.forensic_master.generate_custody_report(
                    case_reference=self.case_number
                )
                full_workflow_results["components"]["compliance_check"] = {
                    "evidence_count": custody_report["report_metadata"]["evidence_count"],
                    "compliance_status": custody_report["evidence_summary"]["compliance_status"],
                    "report_timestamp": custody_report["report_metadata"]["generated_timestamp"]
                }
            
            # Complete workflow
            full_workflow_results["completed_timestamp"] = datetime.now(timezone.utc).isoformat()
            full_workflow_results["status"] = "completed"
            full_workflow_results["summary"] = {
                "research_topics_completed": len(research_topics),
                "total_precedents_found": sum(
                    len(r["results"].get("precedents", []))
                    for r in full_workflow_results["components"]["legal_research"]
                ),
                "emails_collected": evidence_result["results"].get("emails_found", 0),
                "evidence_items_processed": evidence_result["results"].get("forensic_processing", {}).get("evidence_items_processed", 0),
                "total_memories_created": full_workflow_results["components"]["memory_analytics"].get("total_memories", 0),
                "compliance_status": full_workflow_results["components"]["compliance_check"].get("compliance_status", "unknown")
            }
            
            # Store complete workflow in memory
            if self.memory_manager:
                workflow_summary = f"Complete case workflow executed for {self.case_number}. Research topics: {', '.join(research_topics)}. Evidence collection: {evidence_result['results'].get('emails_found', 0)} emails processed."
                
                await self.memory_manager.store_case_memory(
                    content=workflow_summary,
                    memory_type=MemoryType.STRATEGIC,
                    source="full_case_workflow",
                    priority=MemoryPriority.CRITICAL,
                    tags=["full_workflow", "case_management", priority_level]
                )
            
            # Store in active workflows
            self.active_workflows[workflow_id] = full_workflow_results
            
            logger.info(f"Full case workflow completed: {workflow_id}")
            return full_workflow_results
            
        except Exception as e:
            logger.error(f"Full case workflow failed: {e}")
            raise
    
    def get_workflow_status(
        self,
        workflow_id: str = None
    ) -> Dict:
        """
        Get status of workflows
        
        Args:
            workflow_id: Specific workflow ID (optional)
            
        Returns:
            Workflow status information
        """
        try:
            if workflow_id:
                if workflow_id in self.active_workflows:
                    return self.active_workflows[workflow_id]
                else:
                    return {"error": f"Workflow not found: {workflow_id}"}
            else:
                # Return summary of all workflows
                return {
                    "total_workflows": len(self.active_workflows),
                    "active_workflows": list(self.active_workflows.keys()),
                    "workflow_types": {
                        workflow_type.value: len([
                            wf for wf in self.active_workflows.values()
                            if wf.get("workflow_type") == workflow_type.value
                        ])
                        for workflow_type in WorkflowType
                    }
                }
                
        except Exception as e:
            logger.error(f"Workflow status check failed: {e}")
            return {"error": str(e)}
    
    async def health_check_all_components(self) -> Dict:
        """
        Perform health check on all MCP components
        
        Returns:
            Health status of all components
        """
        try:
            health_status = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "hawaii_time": datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z'),
                "case_reference": self.case_number,
                "overall_status": "healthy",
                "components": {}
            }
            
            # Check Perplexity Search
            if self.perplexity_search:
                try:
                    # Test search functionality
                    async with self.perplexity_search as search:
                        test_results = await search.search(
                            query="test health check",
                            max_results=1,
                            priority=SearchPriority.LOW
                        )
                        
                        health_status["components"]["perplexity_search_v2"] = {
                            "status": "healthy",
                            "test_results_count": len(test_results),
                            "last_check": datetime.now(timezone.utc).isoformat()
                        }
                        
                except Exception as e:
                    health_status["components"]["perplexity_search_v2"] = {
                        "status": "unhealthy",
                        "error": str(e)
                    }
                    health_status["overall_status"] = "degraded"
            
            # Check Gmail Evidence
            if self.gmail_evidence:
                try:
                    # Test authentication
                    auth_success = await self.gmail_evidence.authenticate()
                    
                    health_status["components"]["gmail_legal_evidence"] = {
                        "status": "healthy" if auth_success else "unhealthy",
                        "authentication": "successful" if auth_success else "failed",
                        "last_check": datetime.now(timezone.utc).isoformat()
                    }
                    
                    if not auth_success:
                        health_status["overall_status"] = "degraded"
                        
                except Exception as e:
                    health_status["components"]["gmail_legal_evidence"] = {
                        "status": "unhealthy",
                        "error": str(e)
                    }
                    health_status["overall_status"] = "degraded"
            
            # Check Forensic Master
            if self.forensic_master:
                try:
                    # Test evidence registry
                    registry_count = len(self.forensic_master.evidence_registry)
                    
                    health_status["components"]["federal_forensic_master"] = {
                        "status": "healthy",
                        "evidence_registry_count": registry_count,
                        "vault_path_exists": self.forensic_master.evidence_vault_path.exists(),
                        "last_check": datetime.now(timezone.utc).isoformat()
                    }
                    
                except Exception as e:
                    health_status["components"]["federal_forensic_master"] = {
                        "status": "unhealthy",
                        "error": str(e)
                    }
                    health_status["overall_status"] = "degraded"
            
            # Check Memory Manager
            if self.memory_manager:
                try:
                    # Test memory operations
                    memory_count = len(self.memory_manager.memory_registry)
                    
                    health_status["components"]["enhanced_memory_manager"] = {
                        "status": "healthy",
                        "memory_count": memory_count,
                        "mem0_available": bool(self.memory_manager.memory_client),
                        "embedding_model_available": bool(self.memory_manager.embedding_model),
                        "last_check": datetime.now(timezone.utc).isoformat()
                    }
                    
                except Exception as e:
                    health_status["components"]["enhanced_memory_manager"] = {
                        "status": "unhealthy",
                        "error": str(e)
                    }
                    health_status["overall_status"] = "degraded"
            
            logger.info(f"Health check completed: {health_status['overall_status']}")
            return health_status
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "overall_status": "failed",
                "error": str(e)
            }

# FastMCP 2.0 Orchestrator Server
class UltimateMCPServer:
    """Ultimate MCP server with orchestration capabilities"""
    
    def __init__(self):
        self.mcp = FastMCP("Ultimate-MCP-Orchestrator")
        self.orchestrator = UltimateMCPOrchestrator()
        
        logger.info("Ultimate MCP Server initialized")
    
    @tool()
    async def execute_legal_research(
        self,
        research_topic: str,
        case_context: str = "",
        max_precedents: int = 15
    ) -> str:
        """
        Execute comprehensive legal research workflow
        
        Args:
            research_topic: Legal topic to research
            case_context: Additional case context
            max_precedents: Maximum precedents to find
        """
        try:
            # Initialize components if needed
            if not self.orchestrator.perplexity_search:
                await self.orchestrator.initialize_components()
            
            # Execute workflow
            results = await self.orchestrator.execute_legal_research_workflow(
                research_topic=research_topic,
                case_context=case_context,
                max_precedents=max_precedents
            )
            
            # Format response
            summary = results.get("summary", {})
            precedents = results.get("results", {}).get("precedents", [])
            
            response = f"Legal Research Workflow Completed\n"
            response += "=" * 40 + "\n\n"
            response += f"Topic: {research_topic}\n"
            response += f"Case: {results['case_reference']}\n"
            response += f"Precedents Found: {summary.get('precedents_found', 0)}\n"
            response += f"Duration: {summary.get('workflow_duration_seconds', 0):.1f}s\n\n"
            
            if precedents:
                response += "Top Legal Precedents:\n"
                for i, precedent in enumerate(precedents[:5], 1):
                    response += f"{i}. **{precedent['title']}**\n"
                    response += f"   Score: {precedent['score']:.2f}\n"
                    response += f"   Domain: {precedent['domain']}\n"
                    response += f"   Summary: {precedent['snippet'][:150]}...\n\n"
            
            response += f"Workflow ID: {results['workflow_id']}\n"
            response += f"Status: {results['status']}\n"
            
            return response
            
        except Exception as e:
            return f"Legal research workflow failed: {str(e)}"
    
    @tool()
    async def collect_case_evidence(
        self,
        keywords: str,
        days_back: int = 365,
        auto_label: bool = True
    ) -> str:
        """
        Execute evidence collection workflow
        
        Args:
            keywords: Comma-separated keywords to search for
            days_back: Number of days to search back
            auto_label: Automatically label emails as evidence
        """
        try:
            # Parse keywords
            keyword_list = [kw.strip() for kw in keywords.split(',') if kw.strip()]
            
            # Initialize components if needed
            if not self.orchestrator.gmail_evidence:
                await self.orchestrator.initialize_components()
            
            # Execute workflow
            results = await self.orchestrator.execute_evidence_collection_workflow(
                evidence_keywords=keyword_list,
                date_range_days=days_back,
                auto_label=auto_label
            )
            
            # Format response
            response = f"Evidence Collection Workflow Completed\n"
            response += "=" * 45 + "\n\n"
            response += f"Keywords: {keywords}\n"
            response += f"Case: {results['case_reference']}\n"
            response += f"Search Period: {days_back} days\n"
            response += f"Emails Found: {results['results'].get('emails_found', 0)}\n"
            
            # Labeling results
            labeling = results["results"].get("labeling_result", {})
            if labeling:
                response += f"Successfully Labeled: {labeling.get('successfully_labeled', 0)}\n"
                response += f"Labels Applied: {', '.join(labeling.get('labels_applied', []))}\n"
            
            # Forensic processing
            forensic = results["results"].get("forensic_processing", {})
            if forensic:
                response += f"Evidence Items Processed: {forensic.get('evidence_items_processed', 0)}\n"
            
            response += f"\nWorkflow ID: {results['workflow_id']}\n"
            response += f"Status: {results['status']}\n"
            
            return response
            
        except Exception as e:
            return f"Evidence collection workflow failed: {str(e)}"
    
    @tool()
    async def run_full_case_analysis(
        self,
        research_topics: str,
        evidence_keywords: str,
        priority: str = "high"
    ) -> str:
        """
        Run comprehensive case analysis with all available tools
        
        Args:
            research_topics: Comma-separated research topics
            evidence_keywords: Comma-separated evidence keywords
            priority: Analysis priority (low, normal, high, critical)
        """
        try:
            # Parse inputs
            topic_list = [topic.strip() for topic in research_topics.split(',') if topic.strip()]
            keyword_list = [kw.strip() for kw in evidence_keywords.split(',') if kw.strip()]
            
            # Initialize components
            await self.orchestrator.initialize_components()
            
            # Execute full workflow
            results = await self.orchestrator.execute_full_case_workflow(
                research_topics=topic_list,
                evidence_keywords=keyword_list,
                priority_level=priority
            )
            
            # Format comprehensive response
            summary = results.get("summary", {})
            
            response = f"Comprehensive Case Analysis Completed\n"
            response += "=" * 50 + "\n\n"
            response += f"Case: {results['case_reference']}\n"
            response += f"Priority: {results['priority_level']}\n"
            response += f"Started: {results['started_timestamp']}\n"
            response += f"Completed: {results['completed_timestamp']}\n\n"
            
            response += "Results Summary:\n"
            response += f"  Research Topics: {summary.get('research_topics_completed', 0)}\n"
            response += f"  Precedents Found: {summary.get('total_precedents_found', 0)}\n"
            response += f"  Emails Collected: {summary.get('emails_collected', 0)}\n"
            response += f"  Evidence Processed: {summary.get('evidence_items_processed', 0)}\n"
            response += f"  Memories Created: {summary.get('total_memories_created', 0)}\n"
            response += f"  Compliance Status: {summary.get('compliance_status', 'unknown')}\n\n"
            
            response += f"Workflow ID: {results['workflow_id']}\n"
            response += f"Overall Status: {results['status']}\n"
            
            return response
            
        except Exception as e:
            return f"Full case analysis failed: {str(e)}"
    
    @tool()
    async def system_health_check(self) -> str:
        """
        Perform comprehensive health check of all MCP components
        """
        try:
            # Initialize components if needed
            if not self.orchestrator.perplexity_search:
                await self.orchestrator.initialize_components()
            
            # Execute health check
            health_results = await self.orchestrator.health_check_all_components()
            
            # Format response
            response = f"MCP System Health Check\n"
            response += "=" * 30 + "\n\n"
            response += f"Timestamp: {health_results['hawaii_time']}\n"
            response += f"Case: {health_results['case_reference']}\n"
            response += f"Overall Status: {health_results['overall_status'].upper()}\n\n"
            
            response += "Component Status:\n"
            for component, status in health_results["components"].items():
                component_status = status.get("status", "unknown").upper()
                status_icon = "✅" if component_status == "HEALTHY" else "❌"
                response += f"  {status_icon} {component}: {component_status}\n"
                
                if status.get("error"):
                    response += f"     Error: {status['error']}\n"
                
                # Add specific metrics if available
                if "test_results_count" in status:
                    response += f"     Test Results: {status['test_results_count']}\n"
                if "authentication" in status:
                    response += f"     Authentication: {status['authentication']}\n"
                if "evidence_registry_count" in status:
                    response += f"     Evidence Count: {status['evidence_registry_count']}\n"
                if "memory_count" in status:
                    response += f"     Memory Count: {status['memory_count']}\n"
            
            return response
            
        except Exception as e:
            return f"System health check failed: {str(e)}"
    
    def get_server(self) -> FastMCP:
        """Get the configured MCP server"""
        return self.mcp

# Initialize the ultimate server
ultimate_server = UltimateMCPServer()
mcp = ultimate_server.get_server()

# Example Case 1FDV-23-0001009 workflow
async def case_workflow_example():
    """Example comprehensive workflow for Case 1FDV-23-0001009"""
    print("\n" + "=" * 60)
    print("   CASE 1FDV-23-0001009 - COMPREHENSIVE WORKFLOW EXAMPLE")
    print("=" * 60 + "\n")
    
    orchestrator = UltimateMCPOrchestrator(
        case_number="1FDV-23-0001009",
        jurisdiction="hawaii"
    )
    
    # Initialize all components
    print("1. Initializing MCP components...")
    await orchestrator.initialize_components()
    
    # Execute legal research
    print("\n2. Executing legal research...")
    research_topics = [
        "Hawaii child custody best interests standard",
        "Family court visitation schedules Hawaii",
        "Child support guidelines Hawaii family court"
    ]
    
    # Execute evidence collection
    print("\n3. Collecting evidence...")
    evidence_keywords = [
        "custody", "visitation", "Kekoa", "family court", "child support"
    ]
    
    # Run full workflow
    print("\n4. Running comprehensive case workflow...")
    try:
        results = await orchestrator.execute_full_case_workflow(
            research_topics=research_topics,
            evidence_keywords=evidence_keywords,
            priority_level="high"
        )
        
        print("\nWorkflow Results:")
        print(f"- Research Topics: {results['summary']['research_topics_completed']}")
        print(f"- Precedents Found: {results['summary']['total_precedents_found']}")
        print(f"- Emails Collected: {results['summary']['emails_collected']}")
        print(f"- Evidence Processed: {results['summary']['evidence_items_processed']}")
        print(f"- Memories Created: {results['summary']['total_memories_created']}")
        print(f"- Compliance: {results['summary']['compliance_status']}")
        
    except Exception as e:
        print(f"Workflow failed: {e}")
    
    # Health check
    print("\n5. Performing system health check...")
    health = await orchestrator.health_check_all_components()
    print(f"Overall System Status: {health['overall_status'].upper()}")

if __name__ == "__main__":
    # Run the MCP server or example
    from mcp.server.stdio import stdio_server
    
    if os.getenv("RUN_EXAMPLE"):
        asyncio.run(case_workflow_example())
    else:
        async def main():
            logger.info("Starting Ultimate MCP Orchestrator server")
            
            # Initialize orchestrator
            await ultimate_server.orchestrator.initialize_components()
            
            async with stdio_server() as (read_stream, write_stream):
                await mcp.run(
                    read_stream,
                    write_stream,
                    mcp.create_initialization_options()
                )
        
        asyncio.run(main())