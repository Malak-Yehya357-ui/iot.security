"""
Risk Assessment Module for IoT Security
"""


def assess_eavesdropping_risk(encryption: bool, network_type: str, 
                               data_sensitivity: str, public_exposure: bool) -> dict:
    risk_score = 0
    factors = []
    
    if not encryption:
        risk_score += 50
        factors.append("No encryption enabled")
    else:
        risk_score += 5
        factors.append("Encryption enabled")
    
    network_risks = {
        'bluetooth': 25,
        'zigbee': 20,
        'wifi': 15,
        'cellular': 5
    }
    net_risk = network_risks.get(network_type.lower(), 15)
    risk_score += net_risk
    factors.append(f"Network type: {network_type}")
    
    sensitivity_risks = {
        'low': 5,
        'medium': 15,
        'high': 25,
        'critical': 35
    }
    sens_risk = sensitivity_risks.get(data_sensitivity.lower(), 15)
    risk_score += sens_risk
    factors.append(f"Data sensitivity: {data_sensitivity}")
    
    if public_exposure:
        risk_score += 15
        factors.append("Device in public area")
    
    risk_score = min(100, risk_score)
    
    if risk_score >= 70:
        risk_level = "CRITICAL"
    elif risk_score >= 45:
        risk_level = "HIGH"
    elif risk_score >= 20:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    
    return {
        'attack_type': 'Eavesdropping / Sniffing',
        'risk_score': risk_score,
        'risk_level': risk_level,
        'factors': factors,
        'recommendations': [
            "Enable TLS/DTLS encryption for all communications",
            "Use VPN when connecting from untrusted networks",
            "Implement certificate pinning"
        ]
    }


def assess_mitm_risk(uses_https: bool, validates_certificates: bool,
                     has_cert_pinning: bool, network_location: str) -> dict:
    risk_score = 0
    factors = []
    
    if not uses_https:
        risk_score += 45
        factors.append("No HTTPS/TLS protocol")
    else:
        risk_score += 5
        factors.append("HTTPS/TLS enabled")
    
    if not validates_certificates:
        risk_score += 30
        factors.append("Certificate validation disabled")
    
    if not has_cert_pinning:
        risk_score += 15
        factors.append("No certificate pinning")
    
    location_risks = {
        'public': 30,
        'unknown': 25,
        'office': 10,
        'home': 5
    }
    loc_risk = location_risks.get(network_location.lower(), 20)
    risk_score += loc_risk
    factors.append(f"Network location: {network_location}")
    
    risk_score = min(100, risk_score)
    
    if risk_score >= 70:
        risk_level = "CRITICAL"
    elif risk_score >= 45:
        risk_level = "HIGH"
    elif risk_score >= 20:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    
    return {
        'attack_type': 'Man-in-the-Middle (MITM)',
        'risk_score': risk_score,
        'risk_level': risk_level,
        'factors': factors,
        'recommendations': [
            "Enable strict certificate validation",
            "Implement certificate pinning",
            "Use mutual TLS (mTLS)"
        ]
    }


def assess_bruteforce_risk(password_strength: str, has_rate_limiting: bool,
                           has_mfa: bool, exposed_to_internet: bool) -> dict:
    risk_score = 0
    factors = []
    
    strength_scores = {
        'weak': 40,
        'moderate': 20,
        'strong': 5
    }
    str_score = strength_scores.get(password_strength.lower(), 25)
    risk_score += str_score
    factors.append(f"Password strength: {password_strength}")
    
    if not has_rate_limiting:
        risk_score += 30
        factors.append("No rate limiting implemented")
    
    if not has_mfa:
        risk_score += 20
        factors.append("Multi-factor authentication disabled")
    
    if exposed_to_internet:
        risk_score += 15
        factors.append("Service exposed to internet")
    
    risk_score = min(100, risk_score)
    
    if risk_score >= 70:
        risk_level = "CRITICAL"
    elif risk_score >= 45:
        risk_level = "HIGH"
    elif risk_score >= 20:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    
    return {
        'attack_type': 'Brute Force Attack',
        'risk_score': risk_score,
        'risk_level': risk_level,
        'factors': factors,
        'recommendations': [
            "Implement rate limiting (max 5 attempts per minute)",
            "Enable multi-factor authentication",
            "Enforce strong password policy"
        ]
    }