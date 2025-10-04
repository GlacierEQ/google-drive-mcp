#!/usr/bin/env python3
"""
Enhanced Mem0 Integration - Cross-Session Legal Memory System
Maximum Control Point (MCP) Architecture v2.0

Features:
- Mem0 Powerhouse integration with forensic compliance
- Cross-session memory continuity (7-year retention)
- Case-specific memory isolation and context management
- Hawaii jurisdiction optimization
- Federal compliance with audit trails
- Case 1FDV-23-0001009 specialized memory workflows
"""

import asyncio
import json
import hashlib
import os
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import logging
from dataclasses import dataclass, asdict, field
from enum import Enum

# Memory system imports
try:
    from mem0 import MemoryClient, MemoryConfig
    from sentence_transformers import SentenceTransformer
    import chromadb
    from chromadb.config import Settings
except ImportError:
    logging.warning("Memory dependencies not fully available. Install with: pip install mem0ai sentence-transformers chromadb")

# FastMCP imports
try:
    from fastmcp import FastMCP
    from fastmcp.tools import tool
except ImportError:
    from mcp.server.fastmcp import FastMCP
    from mcp.server.models import TextContent

# Setup forensic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler('logs/enhanced_mem0_integration.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class MemoryType(Enum):
    """Legal memory categorization types"""
    PROCEDURAL = "procedural"  # Court procedures, deadlines, processes
    FACTUAL = "factual"        # Case facts, events, evidence
    LEGAL = "legal"            # Legal precedents, arguments, analysis  
    PERSONAL = "personal"      # Client preferences, context, history
    STRATEGIC = "strategic"    # Case strategy, tactics, planning
    TIMELINE = "timeline"      # Chronological events and milestones
    EVIDENCE = "evidence"      # Evidence-specific information
    COMMUNICATION = "communication"  # Communications and correspondence

class MemoryPriority(Enum):
    """Memory priority levels for legal context"""
    CRITICAL = 10    # Court orders, deadlines, emergency
    HIGH = 8         # Key facts, important precedents
    NORMAL = 5       # General case information
    LOW = 3          # Background information
    ARCHIVE = 1      # Historical/reference data

@dataclass
class LegalMemoryEntry:
    """Enhanced memory entry for legal contexts"""
    memory_id: str
    content: str
    memory_type: MemoryType
    priority: MemoryPriority
    case_reference: str
    jurisdiction: str
    source: str
    created_timestamp: str
    created_by: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    relationships: List[str] = field(default_factory=list)
    retention_policy: str = "7_years_legal"
    access_log: List[Dict] = field(default_factory=list)
    integrity_hash: str = ""
    
    def __post_init__(self):
        if not self.memory_id:
            self.memory_id = str(uuid.uuid4())
        if not self.created_timestamp:
            self.created_timestamp = datetime.now(timezone.utc).isoformat()
        if not self.integrity_hash:
            data_to_hash = f"{self.content}{self.memory_type.value}{self.case_reference}"
            self.integrity_hash = hashlib.sha256(data_to_hash.encode()).hexdigest()

class EnhancedMemoryManager:
    """Enhanced memory management with Mem0 and forensic compliance"""
    
    def __init__(
        self,
        case_number: str = "1FDV-23-0001009",
        jurisdiction: str = "hawaii",
        mem0_api_key: str = None
    ):
        self.case_number = case_number
        self.jurisdiction = jurisdiction
        self.memory_vault_path = Path("memory_vault")
        self.memory_vault_path.mkdir(exist_ok=True)
        
        # Initialize Mem0 client
        self.mem0_config = MemoryConfig(
            vector_store={
                "provider": "chroma",
                "config": {
                    "collection_name": f"legal_case_{case_number.replace('-', '_')}",
                    "path": str(self.memory_vault_path / "chroma_db")
                }
            },
            embedding_model={
                "provider": "sentence_transformers",
                "config": {
                    "model": "all-MiniLM-L6-v2"
                }
            },
            llm={
                "provider": "openai",
                "config": {
                    "model": "gpt-4o",
                    "temperature": 0.1
                }
            }
        )
        
        # Initialize memory client
        try:
            self.memory_client = MemoryClient(api_key=mem0_api_key, config=self.mem0_config)
            logger.info("Mem0 client initialized successfully")
        except Exception as e:
            logger.warning(f"Mem0 client initialization failed: {e}")
            self.memory_client = None
        
        # Case-specific sessions
        self.case_sessions = {}
        
        # Local memory registry for forensic compliance
        self.memory_registry = {}
        self._load_memory_registry()
        
        # Initialize embedding model for local processing
        try:
            self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
            logger.info("Local embedding model loaded")
        except Exception as e:
            logger.warning(f"Local embedding model loading failed: {e}")
            self.embedding_model = None
        
        logger.info(f"Enhanced Memory Manager initialized for case {case_number}")
    
    def _load_memory_registry(self):
        """Load memory registry from file"""
        registry_file = self.memory_vault_path / "memory_registry.json"
        
        if registry_file.exists():
            try:
                with open(registry_file, 'r') as f:
                    data = json.load(f)
                
                # Convert to LegalMemoryEntry objects
                for memory_id, entry_dict in data.items():
                    # Convert enums back from strings
                    entry_dict['memory_type'] = MemoryType(entry_dict['memory_type'])
                    entry_dict['priority'] = MemoryPriority(entry_dict['priority'])
                    
                    self.memory_registry[memory_id] = LegalMemoryEntry(**entry_dict)
                
                logger.info(f"Loaded {len(self.memory_registry)} memory entries")
                
            except Exception as e:
                logger.error(f"Failed to load memory registry: {e}")
                self.memory_registry = {}
        else:
            logger.info("No existing memory registry found")
    
    def _save_memory_registry(self):
        """Save memory registry to file"""
        registry_file = self.memory_vault_path / "memory_registry.json"
        
        try:
            # Convert to serializable format
            serializable_registry = {}
            for memory_id, entry in self.memory_registry.items():
                entry_dict = asdict(entry)
                # Convert enums to strings
                entry_dict['memory_type'] = entry.memory_type.value
                entry_dict['priority'] = entry.priority.value
                serializable_registry[memory_id] = entry_dict
            
            with open(registry_file, 'w') as f:
                json.dump(serializable_registry, f, indent=2)
            
            logger.info(f"Saved memory registry: {len(self.memory_registry)} entries")
            
        except Exception as e:
            logger.error(f"Failed to save memory registry: {e}")
    
    async def create_case_memory_session(
        self,
        case_number: str = None,
        case_type: str = "family_court",
        jurisdiction: str = None
    ) -> str:
        """
        Create specialized memory session for legal case
        
        Args:
            case_number: Case number (defaults to instance case)
            case_type: Type of legal case
            jurisdiction: Court jurisdiction
            
        Returns:
            Session ID
        """
        case_num = case_number or self.case_number
        jurisdict = jurisdiction or self.jurisdiction
        
        session_id = f"case_{case_num.replace('-', '_')}"
        
        try:
            session_config = {
                "session_id": session_id,
                "metadata": {
                    "case_number": case_num,
                    "case_type": case_type,
                    "jurisdiction": jurisdict,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "compliance_level": "federal",
                    "retention_policy": "7_years_legal",
                    "legal_hold_status": "active"
                },
                "memory_types": [
                    memory_type.value for memory_type in MemoryType
                ]
            }
            
            # Create session with Mem0 if available
            if self.memory_client:
                session = await self.memory_client.create_session(**session_config)
                self.case_sessions[case_num] = session
                logger.info(f"Mem0 session created: {session_id}")
            else:
                # Create local session tracking
                self.case_sessions[case_num] = session_config
                logger.info(f"Local session created: {session_id}")
            
            return session_id
            
        except Exception as e:
            logger.error(f"Session creation failed: {e}")
            raise
    
    async def store_case_memory(
        self,
        content: str,
        memory_type: MemoryType,
        case_reference: str = None,
        source: str = "manual_entry",
        priority: MemoryPriority = MemoryPriority.NORMAL,
        tags: List[str] = None,
        created_by: str = "system"
    ) -> LegalMemoryEntry:
        """
        Store memory with legal case context and forensic compliance
        
        Args:
            content: Memory content to store
            memory_type: Type of memory
            case_reference: Case number reference
            source: Source of the memory
            priority: Memory priority level
            tags: Optional tags for categorization
            created_by: Who created this memory
            
        Returns:
            LegalMemoryEntry object
        """
        try:
            case_ref = case_reference or self.case_number
            
            # Create memory entry
            memory_entry = LegalMemoryEntry(
                memory_id=str(uuid.uuid4()),
                content=content,
                memory_type=memory_type,
                priority=priority,
                case_reference=case_ref,
                jurisdiction=self.jurisdiction,
                source=source,
                created_timestamp=datetime.now(timezone.utc).isoformat(),
                created_by=created_by,
                tags=tags or [],
                metadata={
                    "storage_method": "enhanced_mem0",
                    "compliance_verified": True,
                    "hawaii_timezone": datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')
                }
            )
            
            # Store in Mem0 if available
            if self.memory_client and case_ref in self.case_sessions:
                try:
                    session = self.case_sessions[case_ref]
                    
                    mem0_metadata = {
                        "memory_type": memory_type.value,
                        "priority": priority.value,
                        "source": source,
                        "tags": tags or [],
                        "case_reference": case_ref,
                        "jurisdiction": self.jurisdiction,
                        "created_by": created_by
                    }
                    
                    # Add to Mem0
                    result = await session.add_memory(
                        content=content,
                        metadata=mem0_metadata
                    )
                    
                    memory_entry.metadata["mem0_id"] = result.memory_id
                    logger.debug(f"Memory stored in Mem0: {result.memory_id}")
                    
                except Exception as e:
                    logger.warning(f"Mem0 storage failed: {e}")
            
            # Store locally for forensic compliance
            self.memory_registry[memory_entry.memory_id] = memory_entry
            
            # Log access
            await self._log_memory_access(
                memory_entry.memory_id,
                "memory_creation",
                created_by,
                f"Created {memory_type.value} memory"
            )
            
            # Save registry
            self._save_memory_registry()
            
            logger.info(
                f"Memory stored: {memory_entry.memory_id[:8]}... "
                f"({memory_type.value}, priority={priority.value})"
            )
            
            return memory_entry
            
        except Exception as e:
            logger.error(f"Memory storage failed: {e}")
            raise
    
    async def query_case_memories(
        self,
        query: str,
        case_reference: str = None,
        memory_type: MemoryType = None,
        limit: int = 10,
        min_relevance_score: float = 0.3
    ) -> List[Dict]:
        """
        Query memories for specific case with semantic search
        
        Args:
            query: Search query
            case_reference: Case to search within
            memory_type: Filter by memory type
            limit: Maximum results
            min_relevance_score: Minimum relevance threshold
            
        Returns:
            List of matching memories with relevance scores
        """
        try:
            case_ref = case_reference or self.case_number
            results = []
            
            # Query Mem0 if available
            if self.memory_client and case_ref in self.case_sessions:
                try:
                    session = self.case_sessions[case_ref]
                    
                    filters = {"case_reference": case_ref}
                    if memory_type:
                        filters["memory_type"] = memory_type.value
                    
                    mem0_results = await session.query_memories(
                        query=query,
                        filters=filters,
                        limit=limit
                    )
                    
                    for result in mem0_results:
                        if result.score >= min_relevance_score:
                            results.append({
                                "memory_id": result.memory_id,
                                "content": result.content,
                                "relevance_score": result.score,
                                "memory_type": result.metadata.get("memory_type"),
                                "source": result.metadata.get("source"),
                                "created_timestamp": result.metadata.get("timestamp"),
                                "priority": result.metadata.get("priority"),
                                "tags": result.metadata.get("tags", []),
                                "source_system": "mem0"
                            })
                    
                    logger.debug(f"Mem0 query returned {len(results)} results")
                    
                except Exception as e:
                    logger.warning(f"Mem0 query failed: {e}")
            
            # Fallback to local semantic search
            if not results or len(results) < limit:
                local_results = await self._local_semantic_search(
                    query, case_ref, memory_type, limit - len(results), min_relevance_score
                )
                results.extend(local_results)
            
            # Sort by relevance score
            results.sort(key=lambda x: x['relevance_score'], reverse=True)
            
            # Log query access
            for result in results:
                await self._log_memory_access(
                    result['memory_id'],
                    "memory_query",
                    "system",
                    f"Query: {query[:50]}..."
                )
            
            logger.info(f"Memory query completed: {len(results)} results for '{query[:30]}...'")
            return results[:limit]
            
        except Exception as e:
            logger.error(f"Memory query failed: {e}")
            raise
    
    async def _local_semantic_search(
        self,
        query: str,
        case_reference: str,
        memory_type: MemoryType = None,
        limit: int = 10,
        min_relevance_score: float = 0.3
    ) -> List[Dict]:
        """
        Local semantic search fallback
        """
        if not self.embedding_model:
            return []
        
        try:
            # Filter memories by case and type
            candidate_memories = []
            for memory_id, memory_entry in self.memory_registry.items():
                if memory_entry.case_reference != case_reference:
                    continue
                if memory_type and memory_entry.memory_type != memory_type:
                    continue
                
                candidate_memories.append(memory_entry)
            
            if not candidate_memories:
                return []
            
            # Generate query embedding
            query_embedding = self.embedding_model.encode([query])
            
            # Generate content embeddings
            content_texts = [mem.content for mem in candidate_memories]
            content_embeddings = self.embedding_model.encode(content_texts)
            
            # Calculate similarity scores
            import numpy as np
            similarities = np.dot(query_embedding, content_embeddings.T).flatten()
            
            # Create results
            results = []
            for i, (memory_entry, score) in enumerate(zip(candidate_memories, similarities)):
                if score >= min_relevance_score:
                    results.append({
                        "memory_id": memory_entry.memory_id,
                        "content": memory_entry.content,
                        "relevance_score": float(score),
                        "memory_type": memory_entry.memory_type.value,
                        "source": memory_entry.source,
                        "created_timestamp": memory_entry.created_timestamp,
                        "priority": memory_entry.priority.value,
                        "tags": memory_entry.tags,
                        "source_system": "local"
                    })
            
            # Sort by relevance
            results.sort(key=lambda x: x['relevance_score'], reverse=True)
            
            logger.debug(f"Local search returned {len(results)} results")
            return results[:limit]
            
        except Exception as e:
            logger.error(f"Local semantic search failed: {e}")
            return []
    
    async def get_case_timeline(
        self,
        case_reference: str = None,
        start_date: str = None,
        end_date: str = None
    ) -> List[Dict]:
        """
        Generate chronological timeline of case memories
        
        Args:
            case_reference: Case to generate timeline for
            start_date: Start date filter (ISO format)
            end_date: End date filter (ISO format)
            
        Returns:
            Chronological list of case memories
        """
        try:
            case_ref = case_reference or self.case_number
            
            # Get all timeline and factual memories
            timeline_memories = await self.query_case_memories(
                query="timeline events dates milestones",
                case_reference=case_ref,
                memory_type=MemoryType.TIMELINE,
                limit=100
            )
            
            factual_memories = await self.query_case_memories(
                query="facts events occurrences",
                case_reference=case_ref,
                memory_type=MemoryType.FACTUAL,
                limit=100
            )
            
            # Combine and deduplicate
            all_memories = timeline_memories + factual_memories
            unique_memories = {mem['memory_id']: mem for mem in all_memories}.values()
            
            # Sort chronologically
            sorted_memories = sorted(
                unique_memories,
                key=lambda x: x.get('created_timestamp', ''),
                reverse=False
            )
            
            # Apply date filters if specified
            if start_date or end_date:
                filtered_memories = []
                for memory in sorted_memories:
                    mem_date = memory.get('created_timestamp', '')
                    
                    if start_date and mem_date < start_date:
                        continue
                    if end_date and mem_date > end_date:
                        continue
                    
                    filtered_memories.append(memory)
                
                sorted_memories = filtered_memories
            
            logger.info(
                f"Generated timeline: {len(sorted_memories)} entries for case {case_ref}"
            )
            
            return sorted_memories
            
        except Exception as e:
            logger.error(f"Timeline generation failed: {e}")
            raise
    
    async def get_memory_analytics(
        self,
        case_reference: str = None
    ) -> Dict:
        """
        Get analytics and insights about case memories
        
        Args:
            case_reference: Case to analyze
            
        Returns:
            Memory analytics and insights
        """
        try:
            case_ref = case_reference or self.case_number
            
            # Filter memories for case
            case_memories = [
                memory for memory in self.memory_registry.values()
                if memory.case_reference == case_ref
            ]
            
            if not case_memories:
                return {
                    "case_reference": case_ref,
                    "total_memories": 0,
                    "message": "No memories found for case"
                }
            
            # Calculate analytics
            analytics = {
                "case_reference": case_ref,
                "generated_timestamp": datetime.now(timezone.utc).isoformat(),
                "total_memories": len(case_memories),
                "memory_types": {},
                "priority_distribution": {},
                "source_breakdown": {},
                "timeline_analysis": {},
                "recent_activity": [],
                "top_tags": {}
            }
            
            # Analyze memory types
            for memory in case_memories:
                # Memory types
                mem_type = memory.memory_type.value
                analytics["memory_types"][mem_type] = \
                    analytics["memory_types"].get(mem_type, 0) + 1
                
                # Priority distribution
                priority = memory.priority.value
                analytics["priority_distribution"][str(priority)] = \
                    analytics["priority_distribution"].get(str(priority), 0) + 1
                
                # Source breakdown
                source = memory.source
                analytics["source_breakdown"][source] = \
                    analytics["source_breakdown"].get(source, 0) + 1
                
                # Collect tags
                for tag in memory.tags:
                    analytics["top_tags"][tag] = \
                        analytics["top_tags"].get(tag, 0) + 1
            
            # Recent activity (last 7 days)
            seven_days_ago = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
            recent_memories = [
                memory for memory in case_memories
                if memory.created_timestamp > seven_days_ago
            ]
            
            analytics["recent_activity"] = [
                {
                    "memory_id": mem.memory_id[:8] + "...",
                    "type": mem.memory_type.value,
                    "created": mem.created_timestamp,
                    "source": mem.source
                }
                for mem in sorted(recent_memories, key=lambda x: x.created_timestamp, reverse=True)[:10]
            ]
            
            # Sort top tags
            analytics["top_tags"] = dict(
                sorted(analytics["top_tags"].items(), key=lambda x: x[1], reverse=True)[:10]
            )
            
            logger.info(f"Memory analytics generated for case {case_ref}")
            return analytics
            
        except Exception as e:
            logger.error(f"Memory analytics generation failed: {e}")
            raise
    
    async def _log_memory_access(
        self,
        memory_id: str,
        action: str,
        user: str,
        notes: str = ""
    ):
        """Log memory access for audit trail"""
        access_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "memory_id": memory_id,
            "action": action,
            "user": user,
            "notes": notes,
            "case_reference": self.case_number,
            "integrity_hash": hashlib.sha256(
                f"{memory_id}{action}{user}{self.case_number}".encode()
            ).hexdigest()
        }
        
        # Add to memory entry if exists
        if memory_id in self.memory_registry:
            self.memory_registry[memory_id].access_log.append(access_entry)
        
        # Write to access log file
        access_log_file = self.memory_vault_path / "memory_access_log.jsonl"
        
        try:
            with open(access_log_file, "a") as f:
                f.write(json.dumps(access_entry) + "\n")
        except Exception as e:
            logger.error(f"Failed to write memory access log: {e}")

# FastMCP 2.0 Server Integration
class EnhancedMemoryMCPServer:
    """MCP server for enhanced memory management"""
    
    def __init__(self):
        self.mcp = FastMCP("Enhanced-Memory-Manager")
        self.memory_manager = EnhancedMemoryManager()
        
        logger.info("Enhanced Memory MCP Server initialized")
    
    @tool()
    async def store_case_memory(
        self,
        content: str,
        memory_type: str,
        case_reference: str = None,
        source: str = "manual_entry",
        priority: int = 5,
        tags: str = "",
        created_by: str = "system"
    ) -> str:
        """
        Store information in case-specific memory system
        
        Args:
            content: Information to store
            memory_type: Type of memory (procedural, factual, legal, personal, strategic, timeline, evidence, communication)
            case_reference: Case number (optional)
            source: Source of information
            priority: Priority level (1-10, 10 being highest)
            tags: Comma-separated tags
            created_by: Who created this memory
        """
        try:
            # Parse inputs
            memory_type_enum = MemoryType(memory_type.lower())
            priority_enum = MemoryPriority(priority)
            tag_list = [tag.strip() for tag in tags.split(',') if tag.strip()] if tags else []
            
            # Ensure case session exists
            case_ref = case_reference or self.memory_manager.case_number
            if case_ref not in self.memory_manager.case_sessions:
                await self.memory_manager.create_case_memory_session(
                    case_number=case_ref
                )
            
            # Store memory
            memory_entry = await self.memory_manager.store_case_memory(
                content=content,
                memory_type=memory_type_enum,
                case_reference=case_ref,
                source=source,
                priority=priority_enum,
                tags=tag_list,
                created_by=created_by
            )
            
            return f"Memory stored successfully:\n" \
                   f"Memory ID: {memory_entry.memory_id}\n" \
                   f"Case: {memory_entry.case_reference}\n" \
                   f"Type: {memory_entry.memory_type.value}\n" \
                   f"Priority: {memory_entry.priority.value}\n" \
                   f"Source: {memory_entry.source}\n" \
                   f"Created: {memory_entry.created_timestamp}\n" \
                   f"Tags: {', '.join(memory_entry.tags) if memory_entry.tags else 'None'}\n" \
                   f"Integrity Hash: {memory_entry.integrity_hash[:16]}..."
                   
        except Exception as e:
            return f"Failed to store memory: {str(e)}"
    
    @tool()
    async def recall_case_information(
        self,
        query: str,
        case_reference: str = None,
        memory_type: str = None,
        limit: int = 5
    ) -> str:
        """
        Recall information from case memory system
        
        Args:
            query: What information to recall
            case_reference: Case number (optional)
            memory_type: Filter by memory type (optional)
            limit: Maximum number of results
        """
        try:
            # Parse memory type if provided
            memory_type_enum = None
            if memory_type:
                memory_type_enum = MemoryType(memory_type.lower())
            
            # Query memories
            memories = await self.memory_manager.query_case_memories(
                query=query,
                case_reference=case_reference,
                memory_type=memory_type_enum,
                limit=limit
            )
            
            if not memories:
                return f"No relevant memories found for query: {query}"
            
            # Format response
            response = f"Found {len(memories)} relevant memories:\n\n"
            
            for i, memory in enumerate(memories, 1):
                response += f"**{i}. Memory {memory['memory_id'][:8]}...**\n"
                response += f"   Type: {memory['memory_type']}\n"
                response += f"   Source: {memory['source']}\n"
                response += f"   Relevance: {memory['relevance_score']:.2f}\n"
                response += f"   Created: {memory['created_timestamp']}\n"
                response += f"   Content: {memory['content'][:200]}...\n"
                if memory.get('tags'):
                    response += f"   Tags: {', '.join(memory['tags'])}\n"
                response += "\n"
            
            return response
            
        except Exception as e:
            return f"Failed to recall information: {str(e)}"
    
    @tool()
    async def get_case_timeline(
        self,
        case_reference: str = None,
        days_back: int = 365
    ) -> str:
        """
        Get chronological timeline of case events and memories
        
        Args:
            case_reference: Case number (optional)
            days_back: Number of days to look back
        """
        try:
            case_ref = case_reference or self.memory_manager.case_number
            
            # Calculate date range
            start_date = (datetime.now(timezone.utc) - timedelta(days=days_back)).isoformat()
            
            timeline = await self.memory_manager.get_case_timeline(
                case_reference=case_ref,
                start_date=start_date
            )
            
            if not timeline:
                return f"No timeline entries found for case {case_ref}"
            
            # Format timeline
            response = f"Case Timeline for {case_ref}\n"
            response += "=" * 40 + "\n\n"
            
            for i, entry in enumerate(timeline[:20], 1):
                # Parse timestamp for display
                try:
                    timestamp = datetime.fromisoformat(entry['created_timestamp'].replace('Z', '+00:00'))
                    display_time = timestamp.strftime('%Y-%m-%d %H:%M UTC')
                except:
                    display_time = entry['created_timestamp']
                
                response += f"{i}. **{display_time}**\n"
                response += f"   Type: {entry['memory_type']}\n"
                response += f"   Source: {entry['source']}\n"
                response += f"   Content: {entry['content'][:150]}...\n\n"
            
            if len(timeline) > 20:
                response += f"... and {len(timeline) - 20} more entries\n"
            
            return response
            
        except Exception as e:
            return f"Timeline generation failed: {str(e)}"
    
    @tool()
    async def get_memory_analytics(
        self,
        case_reference: str = None
    ) -> str:
        """
        Get analytics and insights about case memories
        
        Args:
            case_reference: Case number (optional)
        """
        try:
            analytics = await self.memory_manager.get_memory_analytics(
                case_reference=case_reference
            )
            
            response = f"Memory Analytics for Case {analytics['case_reference']}\n"
            response += "=" * 50 + "\n\n"
            
            response += f"Total Memories: {analytics['total_memories']}\n\n"
            
            # Memory types breakdown
            response += "Memory Types:\n"
            for mem_type, count in analytics['memory_types'].items():
                response += f"  {mem_type}: {count}\n"
            
            response += "\nPriority Distribution:\n"
            for priority, count in analytics['priority_distribution'].items():
                response += f"  Priority {priority}: {count}\n"
            
            response += "\nSources:\n"
            for source, count in analytics['source_breakdown'].items():
                response += f"  {source}: {count}\n"
            
            if analytics.get('top_tags'):
                response += "\nTop Tags:\n"
                for tag, count in list(analytics['top_tags'].items())[:5]:
                    response += f"  {tag}: {count}\n"
            
            if analytics.get('recent_activity'):
                response += "\nRecent Activity (Last 7 days):\n"
                for activity in analytics['recent_activity'][:5]:
                    response += f"  {activity['type']} - {activity['created']}\n"
            
            return response
            
        except Exception as e:
            return f"Memory analytics failed: {str(e)}"
    
    def get_server(self) -> FastMCP:
        """Get the configured MCP server"""
        return self.mcp

# Initialize the memory server
memory_server = EnhancedMemoryMCPServer()
mcp = memory_server.get_server()

if __name__ == "__main__":
    # Example usage
    async def memory_example():
        """Example memory operations for Case 1FDV-23-0001009"""
        manager = EnhancedMemoryManager(case_number="1FDV-23-0001009")
        
        # Create case session
        session_id = await manager.create_case_memory_session()
        print(f"Created session: {session_id}")
        
        # Store some case memories
        memories_to_store = [
            {
                "content": "Case initiated in Hawaii Family Court involving custody dispute between Casey and Teresa regarding son Kekoa",
                "memory_type": MemoryType.FACTUAL,
                "source": "case_initiation",
                "priority": MemoryPriority.HIGH,
                "tags": ["case_start", "custody", "family_court"]
            },
            {
                "content": "Hawaii family court follows best interests of child standard per HRS 571-46",
                "memory_type": MemoryType.LEGAL,
                "source": "legal_research",
                "priority": MemoryPriority.HIGH,
                "tags": ["best_interests", "hawaii_law", "custody_standard"]
            },
            {
                "content": "Kekoa's birthdate is November 29th, making him a Sagittarius. Casey's birthday is November 17th.",
                "memory_type": MemoryType.PERSONAL,
                "source": "personal_information",
                "priority": MemoryPriority.NORMAL,
                "tags": ["birthday", "family", "personal_details"]
            }
        ]
        
        for memory_data in memories_to_store:
            entry = await manager.store_case_memory(**memory_data)
            print(f"Stored memory: {entry.memory_id[:8]}... ({entry.memory_type.value})")
        
        # Query memories
        results = await manager.query_case_memories(
            query="Hawaii family court custody standards",
            limit=5
        )
        
        print(f"\nFound {len(results)} relevant memories:")
        for result in results:
            print(f"- {result['content'][:100]}... (score: {result['relevance_score']:.2f})")
        
        # Get analytics
        analytics = await manager.get_memory_analytics()
        print(f"\nCase analytics: {analytics['total_memories']} total memories")
    
    # Run the MCP server
    from mcp.server.stdio import stdio_server
    
    async def main():
        logger.info("Starting Enhanced Memory MCP server")
        
        async with stdio_server() as (read_stream, write_stream):
            await mcp.run(
                read_stream,
                write_stream,
                mcp.create_initialization_options()
            )
    
    # Run example or server based on environment
    if os.getenv("RUN_EXAMPLE"):
        asyncio.run(memory_example())
    else:
        asyncio.run(main())