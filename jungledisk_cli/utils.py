"""Utility functions for JungleDisk CLI."""


def normalize_name_for_comparison(name: str) -> str:
    """Normalize a name for comparison by replacing smart quotes and other variations.
    
    Args:
        name: Name to normalize
        
    Returns:
        Normalized name
    """
    # Replace various types of quotes with standard ones using Unicode codes
    replacements = {
        chr(8217): "'",  # U+2019 Right single quotation mark (')
        chr(8216): "'",  # U+2018 Left single quotation mark (')
        chr(8221): '"',  # U+201D Right double quotation mark (")
        chr(8220): '"',  # U+201C Left double quotation mark (")
        chr(8211): '-',  # U+2013 En dash (–)
        chr(8212): '-',  # U+2014 Em dash (—)
    }
    
    normalized = name
    for old, new in replacements.items():
        normalized = normalized.replace(old, new)
    
    return normalized