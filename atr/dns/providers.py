"""DNS provider implementations"""
from abc import ABC, abstractmethod
from typing import Optional, List
import dns.resolver
import dns.name

from atr.core.config import settings


class DNSProvider(ABC):
    """Abstract DNS provider interface"""
    
    @abstractmethod
    def create_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
        """Create a TXT record"""
        pass
    
    @abstractmethod
    def delete_txt_record(self, name: str, value: str) -> bool:
        """Delete a TXT record"""
        pass
    
    @abstractmethod
    def get_txt_records(self, name: str) -> List[str]:
        """Get all TXT records for a name"""
        pass


class LocalDNSProvider(DNSProvider):
    """Local DNS provider (no-op for development)"""
    
    def create_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
        """No-op for local development"""
        return True
    
    def delete_txt_record(self, name: str, value: str) -> bool:
        """No-op for local development"""
        return True
    
    def get_txt_records(self, name: str) -> List[str]:
        """No-op for local development"""
        return []


class Route53Provider(DNSProvider):
    """AWS Route53 DNS provider"""
    
    def __init__(self):
        try:
            import boto3
            self.client = boto3.client(
                'route53',
                aws_access_key_id=settings.route53_aws_access_key_id,
                aws_secret_access_key=settings.route53_aws_secret_access_key,
                region_name=settings.route53_aws_region
            )
            self.hosted_zone_id = settings.route53_hosted_zone_id
        except ImportError:
            raise ImportError("boto3 is required for Route53 provider")
        except Exception as e:
            raise ValueError(f"Failed to initialize Route53 client: {e}")
    
    def create_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
        """Create TXT record in Route53"""
        try:
            # Ensure name ends with dot for Route53
            if not name.endswith('.'):
                name = name + '.'
            
            response = self.client.change_resource_record_sets(
                HostedZoneId=self.hosted_zone_id,
                ChangeBatch={
                    'Changes': [{
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': name,
                            'Type': 'TXT',
                            'TTL': ttl,
                            'ResourceRecords': [{'Value': f'"{value}"'}]
                        }
                    }]
                }
            )
            return response['ChangeInfo']['Status'] == 'PENDING'
        except Exception:
            return False
    
    def delete_txt_record(self, name: str, value: str) -> bool:
        """Delete TXT record from Route53"""
        try:
            if not name.endswith('.'):
                name = name + '.'
            
            response = self.client.change_resource_record_sets(
                HostedZoneId=self.hosted_zone_id,
                ChangeBatch={
                    'Changes': [{
                        'Action': 'DELETE',
                        'ResourceRecordSet': {
                            'Name': name,
                            'Type': 'TXT',
                            'TTL': 300,
                            'ResourceRecords': [{'Value': f'"{value}"'}]
                        }
                    }]
                }
            )
            return response['ChangeInfo']['Status'] == 'PENDING'
        except Exception:
            return False
    
    def get_txt_records(self, name: str) -> List[str]:
        """Get TXT records from Route53"""
        try:
            if not name.endswith('.'):
                name = name + '.'
            
            response = self.client.list_resource_record_sets(
                HostedZoneId=self.hosted_zone_id,
                StartRecordName=name,
                StartRecordType='TXT'
            )
            
            records = []
            for record_set in response.get('ResourceRecordSets', []):
                if record_set['Name'] == name and record_set['Type'] == 'TXT':
                    for record in record_set.get('ResourceRecords', []):
                        # Remove quotes from Route53 values
                        value = record['Value'].strip('"')
                        records.append(value)
            
            return records
        except Exception:
            return []


class CloudflareProvider(DNSProvider):
    """Cloudflare DNS provider"""
    
    def __init__(self):
        try:
            import cloudflare
            self.api = cloudflare.CloudFlare(
                token=settings.cloudflare_api_token
            )
            self.zone_id = settings.cloudflare_zone_id
        except ImportError:
            raise ImportError("cloudflare library is required for Cloudflare provider")
        except Exception as e:
            raise ValueError(f"Failed to initialize Cloudflare client: {e}")
    
    def create_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
        """Create TXT record in Cloudflare"""
        try:
            self.api.zones.dns_records.post(
                self.zone_id,
                data={
                    'type': 'TXT',
                    'name': name,
                    'content': value,
                    'ttl': ttl
                }
            )
            return True
        except Exception:
            return False
    
    def delete_txt_record(self, name: str, value: str) -> bool:
        """Delete TXT record from Cloudflare"""
        try:
            # Find the record first
            records = self.api.zones.dns_records.get(
                self.zone_id,
                params={'type': 'TXT', 'name': name}
            )
            
            for record in records:
                if record['content'] == value:
                    self.api.zones.dns_records.delete(
                        self.zone_id,
                        record['id']
                    )
                    return True
            return False
        except Exception:
            return False
    
    def get_txt_records(self, name: str) -> List[str]:
        """Get TXT records from Cloudflare"""
        try:
            records = self.api.zones.dns_records.get(
                self.zone_id,
                params={'type': 'TXT', 'name': name}
            )
            return [record['content'] for record in records]
        except Exception:
            return []


def get_dns_provider() -> DNSProvider:
    """Get DNS provider based on configuration"""
    provider_type = settings.dns_provider.lower()
    
    if provider_type == "route53":
        return Route53Provider()
    elif provider_type == "cloudflare":
        return CloudflareProvider()
    else:
        return LocalDNSProvider()
