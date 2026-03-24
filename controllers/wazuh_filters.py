# -*- coding: utf-8 -*-
"""
Wazuh custom filters.
Define criteria in python functions to filter incoming alerts.
"""
def apply_filters(alert_data):
    """
    Evaluate alert and return True to accept, False to drop.
    """
    rule = alert_data.get('rule', {})
    rule_id = str(rule.get('id', ''))
    rule_level = rule.get('level', 0)
    
    # Example Criterion 1: Drop useless rules below level 1 (allow most alerts for testing)
    if rule_level < 1:
        return False
        
    # Example Criterion 2: Ignore specific extremely noisy structural rules if needed
    # (Commented out to allow most alerts during testing)
    # if rule_id in ['1002']:
    #     return False
        
    return True
