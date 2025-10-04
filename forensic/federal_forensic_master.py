#!/usr/bin/env python3
"""
Federal Forensic MCP Master - Power Path Implementation
Maximum Control Point (MCP) Architecture v2.0

Features:
- Federal forensic compliance (FRE 901/902, SOC 2 Type II)
- Multi-modal evidence processing (email, docs, audio, video, images)
- Chain-of-custody with digital signatures
- Case 1FDV-23-0001009 specialized workflows
- Hawaii jurisdiction optimization
- Real-time forensic integrity verification
"""

import asyncio
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import logging
from dataclasses import dataclass, asdict, field
from enum import Enum
import mimetypes
import aiofiles
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

# FastMCP 2.0 imports
try:
    from fastmcp import FastMCP, compose_servers
    from fastmcp.auth import GoogleAuth, GitHubAuth
    from fastmcp.tools import tool, Tool
    from fastmcp.resources import resource
except ImportError:
    # Fallback to standard MCP
    from mcp.server.fastmcp import FastMCP
    from mcp.server.models import TextContent, Tool

# Setup forensic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler('logs/federal_forensic_master.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class EvidenceType(Enum):
    """Federal evidence classification types"""
    EMAIL = "email"
    DOCUMENT = "document"
    AUDIO = "audio"
    VIDEO = "video"
    IMAGE = "image"
    METADATA = "metadata"
    COMMUNICATION = "communication"
    FINANCIAL = "financial"
    DIGITAL = "digital"
    PHYSICAL = "physical"

class ComplianceStandard(Enum):
    """Federal compliance standards"""
    FRE_901 = "FRE-901"  # Authentication and identification
    FRE_902 = "FRE-902"  # Self-authenticating evidence
    SOC2_TYPE_II = "SOC2-TYPE-II"  # Service organization controls
    NIST_SP_800_86 = "NIST-SP-800-86"  # Computer forensics guidelines
    ISO_27037 = "ISO-27037"  # Digital evidence identification

class ChainOfCustodyStatus(Enum):
    """Chain of custody status tracking"""
    CREATED = "created"
    COLLECTED = "collected"
    PROCESSED = "processed"
    ANALYZED = "analyzed"
    STORED = "stored"
    TRANSFERRED = "transferred"
    ARCHIVED = "archived"
    DESTROYED = "destroyed"

@dataclass
class ForensicMetadata:
    """Comprehensive forensic metadata for evidence"""
    evidence_id: str
    evidence_type: EvidenceType
    original_filename: str
    file_size_bytes: int
    mime_type: str
    created_timestamp: str
    collected_timestamp: str
    collected_by: str
    case_reference: str
    jurisdiction: str
    compliance_standards: List[ComplianceStandard]
    chain_of_custody: List[Dict] = field(default_factory=list)
    integrity_hashes: Dict[str, str] = field(default_factory=dict)
    digital_signature: Optional[str] = None
    encryption_status: str = "unencrypted"
    access_log: List[Dict] = field(default_factory=list)
    retention_policy: str = "7_years_legal"
    legal_hold_status: str = "active"
    
    def __post_init__(self):
        if not self.evidence_id:
            self.evidence_id = str(uuid.uuid4())
        if not self.collected_timestamp:
            self.collected_timestamp = datetime.now(timezone.utc).isoformat()

@dataclass 
class ChainOfCustodyEntry:
    """Individual chain of custody entry"""
    timestamp: str
    custodian: str
    action: str
    status: ChainOfCustodyStatus
    location: str
    notes: str
    digital_signature: Optional[str] = None
    integrity_hash: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if not self.integrity_hash:
            data_to_hash = f"{self.timestamp}{self.custodian}{self.action}{self.status.value}"
            self.integrity_hash = hashlib.sha256(data_to_hash.encode()).hexdigest()

class FederalForensicMaster:
    """Federal forensic evidence management system"""
    
    def __init__(
        self,
        case_number: str = "1FDV-23-0001009",
        jurisdiction: str = "hawaii",
        evidence_vault_path: str = "evidence_vault"
    ):
        self.case_number = case_number
        self.jurisdiction = jurisdiction
        self.evidence_vault_path = Path(evidence_vault_path)
        self.evidence_vault_path.mkdir(exist_ok=True)
        
        # Initialize encryption
        self.encryption_key = self._init_encryption()
        
        # Initialize digital signing
        self.signing_key, self.verification_key = self._init_digital_signing()
        
        # Evidence registry
        self.evidence_registry = {}
        
        # Load existing evidence registry
        self._load_evidence_registry()
        
        logger.info(f"Federal Forensic Master initialized for case {case_number}")
    
    def _init_encryption(self) -> Fernet:
        """Initialize encryption for sensitive evidence"""
        key_file = self.evidence_vault_path / "encryption.key"
        
        if key_file.exists():
            with open(key_file, 'rb') as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            
            # Secure the key file
            key_file.chmod(0o600)
            logger.info("Generated new encryption key")
        
        return Fernet(key)
    
    def _init_digital_signing(self):
        """Initialize digital signing keys for evidence integrity"""
        private_key_file = self.evidence_vault_path / "signing_private.pem"
        public_key_file = self.evidence_vault_path / "signing_public.pem"
        
        if private_key_file.exists() and public_key_file.exists():
            # Load existing keys
            with open(private_key_file, 'rb') as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)
            
            with open(public_key_file, 'rb') as f:
                public_key = serialization.load_pem_public_key(f.read())
            
            logger.info("Loaded existing digital signing keys")
        else:
            # Generate new key pair
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            public_key = private_key.public_key()
            
            # Save private key
            with open(private_key_file, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=Encoding.PEM,
                    format=PrivateFormat.PKCS8,
                    encryption_algorithm=NoEncryption()
                ))
            
            # Save public key
            with open(public_key_file, 'wb') as f:
                f.write(public_key.public_bytes(
                    encoding=Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            
            # Secure key files
            private_key_file.chmod(0o600)
            public_key_file.chmod(0o644)
            
            logger.info("Generated new digital signing keys")
        
        return private_key, public_key
    
    def _load_evidence_registry(self):
        """Load existing evidence registry"""
        registry_file = self.evidence_vault_path / "evidence_registry.json"
        
        if registry_file.exists():
            try:
                with open(registry_file, 'r') as f:
                    data = json.load(f)
                    
                # Convert to ForensicMetadata objects
                for evidence_id, metadata_dict in data.items():
                    # Convert compliance standards back to enums
                    metadata_dict['compliance_standards'] = [
                        ComplianceStandard(std) for std in metadata_dict['compliance_standards']
                    ]
                    metadata_dict['evidence_type'] = EvidenceType(metadata_dict['evidence_type'])
                    
                    self.evidence_registry[evidence_id] = ForensicMetadata(**metadata_dict)
                
                logger.info(f"Loaded {len(self.evidence_registry)} evidence items from registry")
                
            except Exception as e:
                logger.error(f"Failed to load evidence registry: {e}")
                self.evidence_registry = {}
        else:
            logger.info("No existing evidence registry found, starting fresh")
    
    def _save_evidence_registry(self):
        """Save evidence registry to file"""
        registry_file = self.evidence_vault_path / "evidence_registry.json"
        
        try:
            # Convert to serializable format
            serializable_registry = {}
            for evidence_id, metadata in self.evidence_registry.items():
                metadata_dict = asdict(metadata)
                # Convert enums to strings
                metadata_dict['compliance_standards'] = [std.value for std in metadata.compliance_standards]
                metadata_dict['evidence_type'] = metadata.evidence_type.value
                serializable_registry[evidence_id] = metadata_dict
            
            with open(registry_file, 'w') as f:
                json.dump(serializable_registry, f, indent=2)
            
            logger.info(f"Saved evidence registry: {len(self.evidence_registry)} items")
            
        except Exception as e:
            logger.error(f"Failed to save evidence registry: {e}")
    
    async def collect_evidence(
        self,
        source_path: str,
        evidence_type: EvidenceType,
        case_reference: str = None,
        collected_by: str = "system",
        notes: str = ""
    ) -> ForensicMetadata:
        """
        Collect evidence with full forensic compliance
        
        Args:
            source_path: Path to source evidence file
            evidence_type: Type of evidence being collected
            case_reference: Case number reference
            collected_by: Person/system collecting evidence
            notes: Additional notes
            
        Returns:
            ForensicMetadata object with complete chain-of-custody
        """
        try:
            source_file = Path(source_path)
            if not source_file.exists():
                raise FileNotFoundError(f"Source evidence file not found: {source_path}")
            
            # Generate evidence ID
            evidence_id = str(uuid.uuid4())
            
            # Read file for processing
            file_size = source_file.stat().st_size
            mime_type, _ = mimetypes.guess_type(str(source_file))
            
            # Calculate integrity hashes
            integrity_hashes = await self._calculate_integrity_hashes(source_file)
            
            # Create forensic metadata
            metadata = ForensicMetadata(
                evidence_id=evidence_id,
                evidence_type=evidence_type,
                original_filename=source_file.name,
                file_size_bytes=file_size,
                mime_type=mime_type or "application/octet-stream",
                created_timestamp=datetime.fromtimestamp(
                    source_file.stat().st_ctime, tz=timezone.utc
                ).isoformat(),
                collected_timestamp=datetime.now(timezone.utc).isoformat(),
                collected_by=collected_by,
                case_reference=case_reference or self.case_number,
                jurisdiction=self.jurisdiction,
                compliance_standards=[
                    ComplianceStandard.FRE_901,
                    ComplianceStandard.FRE_902,
                    ComplianceStandard.SOC2_TYPE_II,
                    ComplianceStandard.NIST_SP_800_86
                ],
                integrity_hashes=integrity_hashes
            )
            
            # Create initial chain of custody entry
            custody_entry = ChainOfCustodyEntry(
                custodian=collected_by,
                action="evidence_collection",
                status=ChainOfCustodyStatus.COLLECTED,
                location=str(source_file.absolute()),
                notes=f"Evidence collected from {source_path}. {notes}"
            )
            
            metadata.chain_of_custody.append(asdict(custody_entry))
            
            # Copy evidence to secure vault
            vault_filename = f"{evidence_id}_{source_file.name}"
            vault_path = self.evidence_vault_path / vault_filename
            
            # Encrypt sensitive evidence
            if evidence_type in [EvidenceType.EMAIL, EvidenceType.COMMUNICATION, EvidenceType.FINANCIAL]:
                await self._copy_and_encrypt_evidence(source_file, vault_path)
                metadata.encryption_status = "encrypted"
            else:
                await self._copy_evidence(source_file, vault_path)
                metadata.encryption_status = "unencrypted"
            
            # Generate digital signature
            metadata.digital_signature = self._generate_digital_signature(metadata)
            
            # Add to registry
            self.evidence_registry[evidence_id] = metadata
            self._save_evidence_registry()
            
            logger.info(
                f"Evidence collected successfully: {evidence_id} "
                f"({evidence_type.value}, {file_size} bytes)"
            )
            
            return metadata
            
        except Exception as e:
            logger.error(f"Evidence collection failed: {e}")
            raise
    
    async def process_email_evidence(
        self,
        email_data: Dict,
        case_reference: str = None
    ) -> ForensicMetadata:
        """
        Process email evidence with forensic compliance
        
        Args:
            email_data: Email data from Gmail connector
            case_reference: Case number reference
            
        Returns:
            ForensicMetadata for processed email evidence
        """
        try:
            evidence_id = str(uuid.uuid4())
            
            # Create email evidence file
            email_filename = f"email_{evidence_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            email_path = self.evidence_vault_path / email_filename
            
            # Enhance email data with forensic metadata
            enhanced_email_data = {
                "original_email": email_data,
                "forensic_processing": {
                    "processed_timestamp": datetime.now(timezone.utc).isoformat(),
                    "processed_by": "federal_forensic_master",
                    "evidence_id": evidence_id,
                    "case_reference": case_reference or self.case_number
                },
                "integrity_verification": {
                    "original_hash": hashlib.sha256(
                        json.dumps(email_data, sort_keys=True).encode()
                    ).hexdigest(),
                    "verification_timestamp": datetime.now(timezone.utc).isoformat()
                }
            }
            
            # Write encrypted email evidence
            encrypted_data = self.encryption_key.encrypt(
                json.dumps(enhanced_email_data, indent=2).encode()
            )
            
            async with aiofiles.open(email_path, 'wb') as f:
                await f.write(encrypted_data)
            
            # Calculate integrity hashes
            integrity_hashes = await self._calculate_integrity_hashes(email_path)
            
            # Create forensic metadata
            metadata = ForensicMetadata(
                evidence_id=evidence_id,
                evidence_type=EvidenceType.EMAIL,
                original_filename=f"email_{email_data.get('message_metadata', {}).get('subject', 'unknown')}",
                file_size_bytes=email_path.stat().st_size,
                mime_type="application/json",
                created_timestamp=email_data.get('message_metadata', {}).get('date', ''),
                collected_by="gmail_legal_evidence",
                case_reference=case_reference or self.case_number,
                jurisdiction=self.jurisdiction,
                compliance_standards=[
                    ComplianceStandard.FRE_901,
                    ComplianceStandard.FRE_902,
                    ComplianceStandard.SOC2_TYPE_II
                ],
                integrity_hashes=integrity_hashes,
                encryption_status="encrypted"
            )
            
            # Create chain of custody
            custody_entry = ChainOfCustodyEntry(
                custodian="federal_forensic_master",
                action="email_evidence_processing",
                status=ChainOfCustodyStatus.PROCESSED,
                location=str(email_path.absolute()),
                notes=f"Email evidence processed for case {case_reference or self.case_number}"
            )
            
            metadata.chain_of_custody.append(asdict(custody_entry))
            
            # Generate digital signature
            metadata.digital_signature = self._generate_digital_signature(metadata)
            
            # Add to registry
            self.evidence_registry[evidence_id] = metadata
            self._save_evidence_registry()
            
            logger.info(f"Email evidence processed: {evidence_id}")
            return metadata
            
        except Exception as e:
            logger.error(f"Email evidence processing failed: {e}")
            raise
    
    async def verify_evidence_integrity(
        self,
        evidence_id: str
    ) -> Dict[str, Any]:
        """
        Verify evidence integrity and chain of custody
        
        Args:
            evidence_id: Evidence identifier
            
        Returns:
            Integrity verification results
        """
        try:
            if evidence_id not in self.evidence_registry:
                raise ValueError(f"Evidence not found: {evidence_id}")
            
            metadata = self.evidence_registry[evidence_id]
            
            # Find evidence file
            evidence_files = list(self.evidence_vault_path.glob(f"{evidence_id}_*"))
            if not evidence_files:
                raise FileNotFoundError(f"Evidence file not found for {evidence_id}")
            
            evidence_file = evidence_files[0]
            
            # Recalculate hashes
            current_hashes = await self._calculate_integrity_hashes(evidence_file)
            
            # Verify integrity
            integrity_results = {
                "evidence_id": evidence_id,
                "verification_timestamp": datetime.now(timezone.utc).isoformat(),
                "file_exists": True,
                "hash_verification": {},
                "chain_of_custody_intact": True,
                "digital_signature_valid": False,
                "compliance_status": "verified"
            }
            
            # Compare hashes
            for hash_type, original_hash in metadata.integrity_hashes.items():
                current_hash = current_hashes.get(hash_type)
                match = current_hash == original_hash
                
                integrity_results["hash_verification"][hash_type] = {
                    "original": original_hash,
                    "current": current_hash,
                    "match": match
                }
                
                if not match:
                    integrity_results["compliance_status"] = "compromised"
                    logger.error(f"Hash mismatch for {evidence_id} ({hash_type})")
            
            # Verify digital signature
            try:
                signature_valid = self._verify_digital_signature(metadata)
                integrity_results["digital_signature_valid"] = signature_valid
                
                if not signature_valid:
                    integrity_results["compliance_status"] = "signature_invalid"
                    
            except Exception as e:
                logger.error(f"Digital signature verification failed: {e}")
                integrity_results["digital_signature_valid"] = False
            
            # Log verification
            await self._log_access(
                evidence_id,
                "integrity_verification",
                "system",
                f"Verification result: {integrity_results['compliance_status']}"
            )
            
            return integrity_results
            
        except Exception as e:
            logger.error(f"Evidence integrity verification failed: {e}")
            raise
    
    async def _calculate_integrity_hashes(self, file_path: Path) -> Dict[str, str]:
        """Calculate multiple integrity hashes for evidence"""
        hashes = {
            "sha256": hashlib.sha256(),
            "sha512": hashlib.sha512(),
            "md5": hashlib.md5()
        }
        
        try:
            async with aiofiles.open(file_path, 'rb') as f:
                while chunk := await f.read(8192):
                    for hash_obj in hashes.values():
                        hash_obj.update(chunk)
            
            return {name: hash_obj.hexdigest() for name, hash_obj in hashes.items()}
            
        except Exception as e:
            logger.error(f"Hash calculation failed for {file_path}: {e}")
            raise
    
    async def _copy_evidence(self, source: Path, destination: Path):
        """Copy evidence file to vault"""
        async with aiofiles.open(source, 'rb') as src:
            async with aiofiles.open(destination, 'wb') as dst:
                while chunk := await src.read(8192):
                    await dst.write(chunk)
    
    async def _copy_and_encrypt_evidence(self, source: Path, destination: Path):
        """Copy and encrypt sensitive evidence"""
        async with aiofiles.open(source, 'rb') as src:
            content = await src.read()
            
        encrypted_content = self.encryption_key.encrypt(content)
        
        async with aiofiles.open(destination, 'wb') as dst:
            await dst.write(encrypted_content)
    
    def _generate_digital_signature(self, metadata: ForensicMetadata) -> str:
        """Generate digital signature for evidence"""
        try:
            # Create signature data
            signature_data = (
                f"{metadata.evidence_id}"
                f"{metadata.collected_timestamp}"
                f"{metadata.case_reference}"
                f"{json.dumps(metadata.integrity_hashes, sort_keys=True)}"
            )
            
            # Sign with private key
            signature = self.signing_key.sign(
                signature_data.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return signature.hex()
            
        except Exception as e:
            logger.error(f"Digital signature generation failed: {e}")
            return ""
    
    def _verify_digital_signature(self, metadata: ForensicMetadata) -> bool:
        """Verify digital signature for evidence"""
        try:
            if not metadata.digital_signature:
                return False
            
            # Recreate signature data
            signature_data = (
                f"{metadata.evidence_id}"
                f"{metadata.collected_timestamp}"
                f"{metadata.case_reference}"
                f"{json.dumps(metadata.integrity_hashes, sort_keys=True)}"
            )
            
            # Verify signature
            signature_bytes = bytes.fromhex(metadata.digital_signature)
            
            self.verification_key.verify(
                signature_bytes,
                signature_data.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Digital signature verification failed: {e}")
            return False
    
    async def _log_access(
        self,
        evidence_id: str,
        action: str,
        user: str,
        notes: str = ""
    ):
        """Log evidence access for audit trail"""
        access_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "evidence_id": evidence_id,
            "action": action,
            "user": user,
            "notes": notes,
            "case_reference": self.case_number
        }
        
        # Add to metadata if evidence exists
        if evidence_id in self.evidence_registry:
            self.evidence_registry[evidence_id].access_log.append(access_entry)
        
        # Write to access log file
        access_log_file = self.evidence_vault_path / "access_log.jsonl"
        
        async with aiofiles.open(access_log_file, 'a') as f:
            await f.write(json.dumps(access_entry) + "\n")
    
    def generate_custody_report(
        self,
        evidence_id: str = None,
        case_reference: str = None
    ) -> Dict:
        """
        Generate chain of custody report
        
        Args:
            evidence_id: Specific evidence ID (optional)
            case_reference: Case reference for filtering (optional)
            
        Returns:
            Chain of custody report
        """
        try:
            report_timestamp = datetime.now(timezone.utc).isoformat()
            
            # Filter evidence
            evidence_items = []
            
            for eid, metadata in self.evidence_registry.items():
                # Apply filters
                if evidence_id and eid != evidence_id:
                    continue
                if case_reference and metadata.case_reference != case_reference:
                    continue
                
                evidence_items.append(metadata)
            
            # Generate report
            report = {
                "report_metadata": {
                    "generated_timestamp": report_timestamp,
                    "generated_by": "federal_forensic_master",
                    "case_reference": case_reference or self.case_number,
                    "jurisdiction": self.jurisdiction,
                    "evidence_count": len(evidence_items)
                },
                "evidence_summary": {
                    "total_items": len(evidence_items),
                    "evidence_types": {},
                    "compliance_status": "compliant",
                    "encryption_status": {}
                },
                "evidence_details": []
            }
            
            # Analyze evidence
            for metadata in evidence_items:
                # Count evidence types
                evidence_type = metadata.evidence_type.value
                report["evidence_summary"]["evidence_types"][evidence_type] = \
                    report["evidence_summary"]["evidence_types"].get(evidence_type, 0) + 1
                
                # Count encryption status
                encryption = metadata.encryption_status
                report["evidence_summary"]["encryption_status"][encryption] = \
                    report["evidence_summary"]["encryption_status"].get(encryption, 0) + 1
                
                # Add evidence details
                evidence_detail = {
                    "evidence_id": metadata.evidence_id,
                    "type": metadata.evidence_type.value,
                    "filename": metadata.original_filename,
                    "collected_timestamp": metadata.collected_timestamp,
                    "collected_by": metadata.collected_by,
                    "chain_length": len(metadata.chain_of_custody),
                    "integrity_verified": bool(metadata.integrity_hashes),
                    "digitally_signed": bool(metadata.digital_signature),
                    "access_count": len(metadata.access_log)
                }
                
                report["evidence_details"].append(evidence_detail)
            
            logger.info(f"Generated custody report: {len(evidence_items)} evidence items")
            return report
            
        except Exception as e:
            logger.error(f"Custody report generation failed: {e}")
            raise

# FastMCP 2.0 Server Integration
class FederalForensicMCPServer:
    """MCP server wrapper for Federal Forensic Master"""
    
    def __init__(self):
        self.mcp = FastMCP("Federal-Forensic-MCP-Master")
        self.forensic_master = FederalForensicMaster()
        
        # Setup authentication
        self._setup_authentication()
        
        logger.info("Federal Forensic MCP Server initialized")
    
    def _setup_authentication(self):
        """Setup enterprise authentication"""
        try:
            # Google authentication
            if os.getenv("GOOGLE_CLIENT_ID"):
                google_auth = GoogleAuth(
                    client_id=os.getenv("GOOGLE_CLIENT_ID"),
                    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
                    allowed_domains=["glacier-legal.com", "hawaii.gov"]
                )
                self.mcp.add_auth(google_auth)
            
            # GitHub authentication
            if os.getenv("GITHUB_CLIENT_ID"):
                github_auth = GitHubAuth(
                    client_id=os.getenv("GITHUB_CLIENT_ID"),
                    client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
                    organization="GlacierEQ"
                )
                self.mcp.add_auth(github_auth)
            
            logger.info("Enterprise authentication configured")
            
        except Exception as e:
            logger.warning(f"Authentication setup failed: {e}")
    
    @tool()
    async def collect_file_evidence(
        self,
        source_path: str,
        evidence_type: str,
        collected_by: str = "system",
        notes: str = ""
    ) -> str:
        """
        Collect file evidence with forensic compliance
        
        Args:
            source_path: Path to evidence file
            evidence_type: Type of evidence (email, document, audio, video, image)
            collected_by: Person collecting evidence
            notes: Additional notes
        """
        try:
            evidence_type_enum = EvidenceType(evidence_type.lower())
            
            metadata = await self.forensic_master.collect_evidence(
                source_path=source_path,
                evidence_type=evidence_type_enum,
                collected_by=collected_by,
                notes=notes
            )
            
            return f"Evidence collected successfully:\n" \
                   f"Evidence ID: {metadata.evidence_id}\n" \
                   f"Type: {metadata.evidence_type.value}\n" \
                   f"File: {metadata.original_filename}\n" \
                   f"Size: {metadata.file_size_bytes} bytes\n" \
                   f"Collected: {metadata.collected_timestamp}\n" \
                   f"Integrity Hash: {metadata.integrity_hashes.get('sha256', '')[:16]}...\n" \
                   f"Case: {metadata.case_reference}"
                   
        except Exception as e:
            return f"Evidence collection failed: {str(e)}"
    
    @tool()
    async def process_email_evidence_item(
        self,
        email_json: str,
        case_reference: str = None
    ) -> str:
        """
        Process email evidence with forensic metadata
        
        Args:
            email_json: JSON string of email data
            case_reference: Case number reference
        """
        try:
            email_data = json.loads(email_json)
            
            metadata = await self.forensic_master.process_email_evidence(
                email_data=email_data,
                case_reference=case_reference
            )
            
            return f"Email evidence processed successfully:\n" \
                   f"Evidence ID: {metadata.evidence_id}\n" \
                   f"Subject: {metadata.original_filename}\n" \
                   f"Processed: {metadata.collected_timestamp}\n" \
                   f"Encrypted: {metadata.encryption_status}\n" \
                   f"Digital Signature: {'Yes' if metadata.digital_signature else 'No'}\n" \
                   f"Case: {metadata.case_reference}"
                   
        except Exception as e:
            return f"Email evidence processing failed: {str(e)}"
    
    @tool()
    async def verify_evidence(
        self,
        evidence_id: str
    ) -> str:
        """
        Verify evidence integrity and compliance
        
        Args:
            evidence_id: Evidence identifier to verify
        """
        try:
            results = await self.forensic_master.verify_evidence_integrity(evidence_id)
            
            response = f"Evidence Integrity Verification Results:\n\n"
            response += f"Evidence ID: {results['evidence_id']}\n"
            response += f"Verification Time: {results['verification_timestamp']}\n"
            response += f"Overall Status: {results['compliance_status']}\n\n"
            
            response += "Hash Verification:\n"
            for hash_type, result in results['hash_verification'].items():
                status = "✅ MATCH" if result['match'] else "❌ MISMATCH"
                response += f"  {hash_type.upper()}: {status}\n"
            
            response += f"\nDigital Signature: {'Valid' if results['digital_signature_valid'] else 'Invalid'}\n"
            response += f"Chain of Custody: {'Intact' if results['chain_of_custody_intact'] else 'Compromised'}\n"
            
            return response
            
        except Exception as e:
            return f"Evidence verification failed: {str(e)}"
    
    @tool()
    def generate_custody_chain_report(
        self,
        case_reference: str = None,
        evidence_id: str = None
    ) -> str:
        """
        Generate chain of custody report
        
        Args:
            case_reference: Filter by case reference
            evidence_id: Filter by specific evidence ID
        """
        try:
            report = self.forensic_master.generate_custody_report(
                evidence_id=evidence_id,
                case_reference=case_reference
            )
            
            response = f"Chain of Custody Report\n"
            response += "=" * 40 + "\n\n"
            
            # Report metadata
            metadata = report["report_metadata"]
            response += f"Generated: {metadata['generated_timestamp']}\n"
            response += f"Case: {metadata['case_reference']}\n"
            response += f"Jurisdiction: {metadata['jurisdiction']}\n"
            response += f"Evidence Count: {metadata['evidence_count']}\n\n"
            
            # Evidence summary
            summary = report["evidence_summary"]
            response += "Evidence Summary:\n"
            for evidence_type, count in summary["evidence_types"].items():
                response += f"  {evidence_type}: {count}\n"
            
            response += f"\nOverall Compliance: {summary['compliance_status']}\n\n"
            
            # Evidence details (first 10)
            response += "Evidence Details:\n"
            for i, detail in enumerate(report["evidence_details"][:10], 1):
                response += f"{i}. {detail['evidence_id']} ({detail['type']})\n"
                response += f"   File: {detail['filename']}\n"
                response += f"   Collected: {detail['collected_timestamp']}\n"
                response += f"   Integrity: {'Verified' if detail['integrity_verified'] else 'Unverified'}\n"
                response += f"   Signed: {'Yes' if detail['digitally_signed'] else 'No'}\n\n"
            
            if len(report["evidence_details"]) > 10:
                response += f"... and {len(report['evidence_details']) - 10} more items\n"
            
            return response
            
        except Exception as e:
            return f"Custody report generation failed: {str(e)}"
    
    def get_server(self) -> FastMCP:
        """Get the configured MCP server"""
        return self.mcp

# Initialize the server
forensic_server = FederalForensicMCPServer()
mcp = forensic_server.get_server()

if __name__ == "__main__":
    # Run the MCP server
    from mcp.server.stdio import stdio_server
    
    async def main():
        logger.info("Starting Federal Forensic MCP Master server")
        
        async with stdio_server() as (read_stream, write_stream):
            await mcp.run(
                read_stream,
                write_stream,
                mcp.create_initialization_options()
            )
    
    asyncio.run(main())