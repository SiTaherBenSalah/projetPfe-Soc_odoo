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
    
    # Example Criterion 1: Drop useless rules below level 3
    if rule_level < 3:
        return False
        
    # Example Criterion 2: Ignore specific noisy rules 
    # (e.g., rule 1002 - Unknown problem somewhere in the system)
    if rule_id in ['1002', '5716', '5501', '5502']:
        return False
        
    return True
